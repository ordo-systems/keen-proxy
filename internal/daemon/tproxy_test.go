package daemon

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

type recoveryFirewall struct {
	fail      bool
	onRestore func()
	deleteErr error
	attempts  int
	inserted  int
	jumps     map[[3]string]bool
	chains    map[[2]string]bool
}

func (r *recoveryFirewall) Run(_ context.Context, input, name string, args ...string) error {
	if name == "iptables-restore" {
		if r.onRestore != nil {
			r.onRestore()
		}
		r.attempts++
		r.inserted = 0
		var table string
		for line := range strings.SplitSeq(input, "\n") {
			if t, ok := strings.CutPrefix(line, "*"); ok {
				table = t
			} else if definition, ok := strings.CutPrefix(line, ":"); ok {
				chain, _, _ := strings.Cut(definition, " ")
				r.chains[[2]string{table, chain}] = true
			}
		}
		return nil
	}
	if name != "iptables" || len(args) < 5 {
		return errors.New("unexpected command")
	}
	key := [3]string{args[2], args[4], args[len(args)-1]}
	switch args[3] {
	case "-C":
		if !r.jumps[key] {
			return errors.New("jump absent")
		}
	case "-I":
		if r.fail && r.inserted != 0 {
			return errors.New("jump insertion failed")
		}
		r.jumps[key] = true
		r.inserted++
	case "-D":
		if r.deleteErr != nil {
			return r.deleteErr
		}
		if !r.jumps[key] {
			return &exec.ExitError{Stderr: []byte("iptables: Bad rule (does a matching rule exist in that chain?).")}
		}
		delete(r.jumps, key)
	case "-X":
		delete(r.chains, [2]string{args[2], args[4]})
	}
	return nil
}

func TestUnavailableSavedTProxyKeepsConfigAndCanRecover(t *testing.T) {
	holdMemoryLimit(t)
	ctx, cancel := context.WithCancel(context.Background())
	cfg := quietConfig(t)
	cfg.Intercept.Mode = model.InterceptTProxy
	cfg.API.NoTokenFrom = []string{"192.0.2.0/24"}
	path := writeSavedConfig(t, cfg)
	runner := &recoveryFirewall{fail: true, jumps: make(map[[3]string]bool), chains: make(map[[2]string]bool)}
	// Model stale jumps from both modes, with unrelated firewall state.
	staleDNS := [3]string{"nat", "PREROUTING", netfilter.ChainDNS}
	staleTCP := [3]string{"nat", "PREROUTING", netfilter.ChainTCP}
	staleUDP := [3]string{"mangle", "PREROUTING", netfilter.ChainUDP}
	otherJump := [3]string{"nat", "PREROUTING", "OTHER"}
	otherChain := [2]string{"nat", "OTHER"}
	staleChain := [2]string{"mangle", netfilter.ChainUDP}
	runner.jumps[staleDNS], runner.jumps[staleTCP], runner.jumps[staleUDP], runner.jumps[otherJump] = true, true, true, true
	runner.chains[staleChain], runner.chains[otherChain] = true, true
	d := newMemoryDaemon(t, path, runner)
	blocked := make(chan bool, 1)
	d.opt.OnStartupBlocked = func() {
		blocked <- !runner.jumps[staleDNS] && !runner.jumps[staleTCP] && !runner.jumps[staleUDP] &&
			runner.jumps[otherJump] && runner.chains[staleChain] && runner.chains[otherChain] &&
			d.startupBlocked != nil && d.live.Load() != nil && d.dns == nil
	}
	d.opt.OnStartupActive = func() { t.Error("active startup callback fired during blocked startup or later apply") }
	readiness := netfilter.TProxyReadiness{State: netfilter.TProxyUnavailable, Reason: "target_not_registered"}
	d.tproxyProbe = func(context.Context) netfilter.TProxyReadiness { return readiness }
	errC := make(chan error, 1)
	stop := sync.OnceFunc(func() { stopDaemon(t, cancel, errC) })
	t.Cleanup(stop)
	go func() { errC <- d.Run(ctx); close(errC) }()
	select {
	case clean := <-blocked:
		if !clean {
			t.Fatal("management-only callback ran before stale jumps were detached or disturbed unrelated state")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("management-only callback did not run")
	}
	assertInactive := func() {
		t.Helper()
		saved := d.Config()
		status := d.Status(ctx)
		if saved == nil || saved.Intercept.Mode != model.InterceptTProxy || status.DNS != "" || status.Firewall || !d.TProxyReadiness(ctx).StartupBlocked || len(d.NoTokenFrom()) != 1 {
			t.Fatalf("saved mode or management state lost: saved=%+v status=%+v", saved, status)
		}
		if _, _, running := d.eng.Outbound(model.TargetDirect); running {
			t.Error("interception engine is running in inactive state")
		}
		if len(runner.jumps) != 1 || !runner.jumps[otherJump] || len(runner.chains) != 2 || !runner.chains[staleChain] || !runner.chains[otherChain] {
			t.Fatalf("inactive firewall left unexpected jumps=%v chains=%v", runner.jumps, runner.chains)
		}
	}
	assertInactive()
	if _, err := os.Stat(path + ".previous"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("startup unexpectedly wrote a backup: %v", err)
	}
	if err := d.Apply(ctx, d.Config()); err == nil || !strings.Contains(err.Error(), readiness.Reason) || runner.attempts != 0 {
		t.Fatalf("unavailable draft executed firewall operations: apply=%v, attempts=%d", err, runner.attempts)
	}
	redirect := d.Config()
	redirect.Intercept.Mode = model.InterceptRedirect
	redirect.API.NoTokenFrom = []string{"198.51.100.0/24"}
	trustedSaved := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	runner.onRestore = func() {
		if got := d.NoTokenFrom(); !slices.Equal(got, trustedSaved) {
			t.Errorf("staged draft changed trusted networks before commit: %v", got)
		}
	}
	if err := d.Apply(ctx, redirect); err == nil || !strings.Contains(err.Error(), "jump insertion failed") {
		t.Fatalf("expected first activation to fail during jump insertion: %v", err)
	}
	assertInactive()
	if runner.attempts != 1 || runner.inserted != 1 {
		t.Fatalf("failed recovery did not exercise partial installation exactly once: attempts=%d inserts=%d", runner.attempts, runner.inserted)
	}
	if got := lastAudit(t, d, "Configuration apply failed"); !strings.Contains(got, "interception remains inactive") {
		t.Errorf("failed recovery audit: %s", got)
	}
	if saved, err := model.Load(path); err != nil || saved.Intercept.Mode != model.InterceptTProxy {
		t.Fatalf("failed recovery modified persisted config: %v (%v)", saved, err)
	}

	// Stop before starting a transparent socket or changing host policy routing.
	// Both a ready and an inconclusive retry must enter the normal apply path.
	ruleSetDir := d.opt.RuleSetDir
	backup := []byte("# distinct rollback snapshot\n")
	if err := os.WriteFile(path+".previous", backup, 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d.opt.RuleSetDir = path // An existing file cannot serve as the rule-set directory.
	unavailable := readiness
	for _, state := range []string{netfilter.TProxyReady, netfilter.TProxyUnknown} {
		readiness = netfilter.TProxyReadiness{State: state}
		err := d.RetrySavedTProxy(ctx)
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) || pathErr.Op != "mkdir" || pathErr.Path != path {
			t.Fatalf("%s retry did not enter normal Apply: %v", state, err)
		}
	}
	if current, err := os.ReadFile(path); err != nil || !bytes.Equal(current, original) {
		t.Fatalf("retry modified the saved YAML: %v", err)
	}
	if previous, err := os.ReadFile(path + ".previous"); err != nil || !bytes.Equal(previous, backup) {
		t.Fatalf("retry replaced rollback history: %q (%v)", previous, err)
	}
	d.opt.RuleSetDir = ruleSetDir
	readiness = unavailable
	assertInactive()

	runner.fail = false
	memoryBefore := debug.SetMemoryLimit(-1)
	redirect.System.MemoryLimitMiB = new(model.MemoryLimitMiB(250))
	if err := os.Rename(path+".previous", path+".held"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".previous", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, redirect); err == nil || !strings.Contains(err.Error(), "rollback snapshot could not be read") {
		t.Fatalf("failed read of existing snapshot: %v", err)
	}
	assertInactive()
	if got := debug.SetMemoryLimit(-1); got != memoryBefore {
		t.Fatalf("failed persistence committed memory limit %d, want %d", got, memoryBefore)
	}
	if got := d.NoTokenFrom(); !slices.Equal(got, trustedSaved) {
		t.Fatalf("failed persistence changed trusted networks: %v", got)
	}
	if current, err := os.ReadFile(path); err != nil || !bytes.Equal(current, original) {
		t.Fatalf("failed persistence changed saved YAML: %v", err)
	}
	if err := os.Remove(path + ".previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".held", path+".previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".tmp", []byte("# interrupted recovery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, redirect); err != nil {
		t.Fatalf("activate REDIRECT from blocked startup: %v", err)
	}
	if status := d.Status(ctx); status.Mode != string(model.InterceptRedirect) || status.DNS == "" || !status.Firewall || d.TProxyReadiness(ctx).StartupBlocked {
		t.Fatalf("REDIRECT did not activate and clear blocked state: %+v", status)
	}
	if trusted := d.NoTokenFrom(); !slices.Equal(trusted, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}) {
		t.Fatalf("committed access policy = %v", trusted)
	}
	if err := d.RetrySavedTProxy(ctx); !errors.Is(err, ErrStartupNotBlocked) {
		t.Fatalf("active daemon accepted saved retry: %v", err)
	}
	if saved, err := model.Load(path); err != nil || saved.Intercept.Mode != model.InterceptRedirect {
		t.Fatalf("recovered config not saved: %v (%v)", saved, err)
	}
	if previous, err := model.Load(path + ".previous"); err != nil || previous.Intercept.Mode != model.InterceptTProxy {
		t.Fatalf("original config was not kept as the previous configuration: %v (%v)", previous, err)
	}

	rejected := d.Config()
	rejected.Intercept.Mode = model.InterceptTProxy
	if err := d.Apply(ctx, rejected); err == nil || !strings.Contains(err.Error(), readiness.Reason) || runner.attempts != 3 {
		t.Fatalf("rejecting active REDIRECT's new draft attempted rollback: apply=%v, attempts=%d", err, runner.attempts)
	}
	if status := d.Status(ctx); status.Mode != string(model.InterceptRedirect) || !status.Firewall {
		t.Fatalf("rejecting a new draft disrupted active REDIRECT: %+v", status)
	}
	stop()
	if len(runner.jumps) != 1 || !runner.jumps[otherJump] || len(runner.chains) != 2 {
		t.Fatalf("shutdown disturbed unrelated state or left active jumps=%v chains=%v", runner.jumps, runner.chains)
	}
}

func TestActiveStartupSignalsAfterApplyUnderLock(t *testing.T) {
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.Intercept.Mode = model.InterceptRedirect
	runner := &recoveryFirewall{jumps: make(map[[3]string]bool), chains: make(map[[2]string]bool)}
	d := newMemoryDaemon(t, writeSavedConfig(t, cfg), runner)
	active := make(chan bool, 1)
	d.opt.OnStartupActive = func() {
		locked := !d.mu.TryLock()
		ready := locked && d.planOn && d.dns != nil && d.live.Load() != nil
		if !locked {
			d.mu.Unlock()
		}
		select {
		case active <- ready:
		default:
			t.Error("active startup callback fired twice")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	errC := make(chan error, 1)
	t.Cleanup(func() { stopDaemon(t, cancel, errC) })
	go func() { errC <- d.Run(ctx); close(errC) }()
	select {
	case ready := <-active:
		if !ready {
			t.Fatal("active startup callback fired before interception was working or without the daemon lock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("active startup callback did not run")
	}
	if err := d.Apply(ctx, d.Config()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-active:
		t.Fatal("active startup callback fired during Apply")
	default:
	}
}

func TestRecoverySaveRestoresPreviousAfterFinalRenameFails(t *testing.T) {
	// Renaming the staged YAML over a directory fails after the .previous
	// update succeeds. Keep both the existing and initially absent cases.
	for _, withBackup := range []bool{true, false} {
		path := t.TempDir() + "/config.yaml"
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		backup := []byte("# distinct rollback snapshot\n")
		if withBackup {
			if err := os.WriteFile(path+".previous", backup, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		err := persistRecoveryConfig(path, []byte("# original\n"), []byte("# replacement\n"))
		var renameErr *os.LinkError
		if !errors.As(err, &renameErr) || renameErr.Op != "rename" || renameErr.New != path {
			t.Fatalf("expected final rename failure, got %v", err)
		}
		got, err := os.ReadFile(path + ".previous")
		if withBackup && (err != nil || !bytes.Equal(got, backup)) {
			t.Fatalf("rollback snapshot was not restored: %q (%v)", got, err)
		}
		if !withBackup && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rollback snapshot should still be absent: %q (%v)", got, err)
		}
	}
}

func TestBlockedStartupDoesNotSignalReadinessIfJumpsRemain(t *testing.T) {
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.Intercept.Mode = model.InterceptTProxy
	runner := &recoveryFirewall{deleteErr: errors.New("iptables lock unavailable")}
	d := newMemoryDaemon(t, writeSavedConfig(t, cfg), runner)
	d.tproxyProbe = func(context.Context) netfilter.TProxyReadiness {
		return netfilter.TProxyReadiness{State: netfilter.TProxyUnavailable}
	}
	d.opt.OnStartupBlocked = func() { t.Error("signaled management-only startup despite cleanup failure") }
	if err := d.Run(t.Context()); !errors.Is(err, runner.deleteErr) {
		t.Fatalf("startup cleanup failure was not reported: %v", err)
	}
}

func TestBlockedStartupRejectsRetryAndApplyOnShutdown(t *testing.T) {
	holdMemoryLimit(t)
	runCtx, cancel := context.WithCancel(context.Background())
	cfg := quietConfig(t)
	cfg.Intercept.Mode = model.InterceptTProxy
	runner := &recoveryFirewall{}
	d := newMemoryDaemon(t, writeSavedConfig(t, cfg), runner)
	blocked := make(chan struct{})
	d.opt.OnStartupBlocked = func() { close(blocked) }
	d.tproxyProbe = func(context.Context) netfilter.TProxyReadiness {
		select {
		case <-blocked:
			// Simulate shutdown starting while an accepted retry is in preflight.
			cancel()
			return netfilter.TProxyReadiness{State: netfilter.TProxyReady}
		default:
			return netfilter.TProxyReadiness{State: netfilter.TProxyUnavailable}
		}
	}
	errC := make(chan error, 1)
	stop := sync.OnceFunc(func() { stopDaemon(t, cancel, errC) })
	t.Cleanup(stop)
	go func() { errC <- d.Run(runCtx); close(errC) }()
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not enter blocked startup")
	}
	if err := d.RetrySavedTProxy(t.Context()); err == nil || !strings.Contains(err.Error(), "daemon is stopping") {
		t.Fatalf("retry continued after cancellation: %v", err)
	}
	stop()
	draft := d.Config()
	draft.Intercept.Mode = model.InterceptRedirect
	if err := d.Apply(t.Context(), draft); err == nil || !strings.Contains(err.Error(), "daemon is stopping") || runner.attempts != 0 {
		t.Fatalf("late apply installed interception: error=%v, attempts=%d", err, runner.attempts)
	}
	if err := d.RetrySavedTProxy(t.Context()); err == nil || !strings.Contains(err.Error(), "daemon is stopping") {
		t.Fatalf("late retry was admitted: %v", err)
	}
}

func TestSuccessfulSavedRetryPreservesConfigurationFiles(t *testing.T) {
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	path := writeSavedConfig(t, cfg)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte("# preserve this YAML comment\n"), raw...)
	backup := []byte("# distinct rollback snapshot\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".previous", backup, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recoveryFirewall{jumps: make(map[[3]string]bool), chains: make(map[[2]string]bool)}
	d := newMemoryDaemon(t, path, runner)
	t.Cleanup(d.shutdown)
	// Seed the state a blocked startup hands to recovery, using REDIRECT so
	// this portable test does not need a transparent socket or host routing.
	d.cfg = cfg
	d.live.Store(cfg)
	activated := make(chan struct{})
	d.startupBlocked = activated
	if err := d.RetrySavedTProxy(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-activated:
	default:
		t.Fatal("successful retry did not release the startup wait")
	}
	if status := d.Status(t.Context()); !status.Firewall || status.DNS == "" || d.TProxyReadiness(t.Context()).StartupBlocked {
		t.Fatalf("saved retry did not activate interception: %+v", status)
	}
	for name, want := range map[string][]byte{path: original, path + ".previous": backup} {
		if got, err := os.ReadFile(name); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("saved retry changed %q: %v", name, err)
		}
	}
}
