package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/devices"
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

const memoryMiB = 1024 * 1024

// gateRunner isolates firewall effects and can fail activation.
type gateRunner struct {
	fail bool
}

func (g *gateRunner) Run(_ context.Context, _, _ string, args ...string) error {
	if g.fail {
		return errors.New("iptables failed")
	}
	// No rules are installed by this fake; deletion must report that none remain.
	for _, arg := range args {
		if arg == "-D" {
			return errors.New("rule absent")
		}
	}
	return nil
}

// These tests change the process-wide Go memory limit and must not run in parallel.
func holdMemoryLimit(t *testing.T) {
	t.Helper()
	before := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(before) })
}

func requireLimit(t *testing.T, want int64) {
	t.Helper()
	if got := debug.SetMemoryLimit(-1); got != want {
		t.Fatalf("memory limit = %d bytes, want %d", got, want)
	}
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return uint16(port)
}

func quietConfig(t *testing.T) *model.Config {
	t.Helper()
	cfg := &model.Config{}
	cfg.Defaults()
	cfg.DNS.Listen = "127.0.0.1:0"
	cfg.Intercept.TCPPort = freeTCPPort(t)
	for i := range cfg.GeoIP.Databases {
		cfg.GeoIP.Databases[i].Enabled = false
	}
	return cfg
}

func newMemoryDaemon(t *testing.T, path string, run netfilter.Runner) *Daemon {
	t.Helper()
	d := New(Options{
		ConfigPath:    path,
		RuleSetDir:    t.TempDir(),
		ARPPath:       filepath.Join(t.TempDir(), "arp"),
		Firewall:      &netfilter.Firewall{Run: run, IPTables: "iptables", Restore: "iptables-restore"},
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		WatchInterval: time.Hour,
		DeviceNames: func(context.Context, map[string]netip.Addr) map[string]devices.Name {
			return nil
		},
		SingBoxLog: os.DevNull,
	})
	return d
}

// Run owns shutdown; register cancellation and joining before starting its goroutine.
func startMemoryDaemon(t *testing.T, path string, runner netfilter.Runner, want int64) (*Daemon, func()) {
	t.Helper()
	d := newMemoryDaemon(t, path, runner)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	stop := sync.OnceFunc(func() { stopDaemon(t, cancel, errc) })
	t.Cleanup(stop)
	go func() {
		defer close(errc)
		errc <- d.Run(ctx)
	}()
	waitStarted(t, d, errc, want)
	return d, stop
}

func writeSavedConfig(t *testing.T, cfg *model.Config) string {
	t.Helper()
	raw, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func lastAudit(t *testing.T, d *Daemon, text string) string {
	t.Helper()
	page := d.Journal(journal.Audit).Find(journal.Query{Text: text}, nil)
	if len(page.Entries) == 0 {
		t.Fatalf("audit missing %q", text)
	}
	return page.Entries[0].Details
}

func waitStarted(t *testing.T, d *Daemon, errc <-chan error, want int64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var dns string
	for time.Now().Before(deadline) {
		select {
		case err := <-errc:
			t.Fatalf("daemon stopped before the memory limit was applied: %v", err)
		default:
		}
		dns = d.Status(context.Background()).DNS
		if dns != "" && debug.SetMemoryLimit(-1) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("startup limit = %d, want %d, dns %q", debug.SetMemoryLimit(-1), want, dns)
}

func stopDaemon(t *testing.T, cancel context.CancelFunc, errc <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("daemon did not stop")
	}
}

// Saved recommendations become exact byte limits at startup and Apply, clearing
// restores the pre-daemon runtime limit, and a memory-only change does not restart the core.
func TestMemoryLimitStartupApplyAndClear(t *testing.T) {
	holdMemoryLimit(t)
	baseline := int64(300) * memoryMiB
	debug.SetMemoryLimit(baseline)

	path := filepath.Join(t.TempDir(), "config.yaml")
	gate := &gateRunner{}
	d := newMemoryDaemon(t, path, gate)
	closeInitial := sync.OnceFunc(d.shutdown)
	t.Cleanup(closeInitial)
	cfg := quietConfig(t)
	cfg.System.MemoryLimitMiB = new(model.MemoryLimitMiB(400))
	if err := d.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("apply 400: %v", err)
	}
	requireLimit(t, 400*memoryMiB)
	if !d.planOn || d.planPending {
		t.Fatal("successful activation did not commit the firewall plan")
	}

	blocked := t.TempDir()
	d.opt.ConfigPath = blocked
	unsaved := d.Config()
	unsaved.System.MemoryLimitMiB = new(model.MemoryLimitMiB(250))
	err := d.Apply(context.Background(), unsaved)
	if err == nil || !strings.Contains(err.Error(), "not saved") {
		t.Fatalf("applied-but-unsaved: %v", err)
	}
	requireLimit(t, 250*memoryMiB)
	saved, err := model.Load(path)
	if err != nil || saved.System.MemoryLimitMiB == nil || *saved.System.MemoryLimitMiB != 400 {
		t.Fatalf("unsaved apply changed the file: %+v %v", saved, err)
	}

	closeInitial()
	requireLimit(t, baseline)

	d, stop := startMemoryDaemon(t, path, gate, 400*memoryMiB)

	lower := d.Config()
	lower.System.MemoryLimitMiB = new(model.MemoryLimitMiB(250))
	if err := d.Apply(context.Background(), lower); err != nil {
		t.Fatalf("apply 250: %v", err)
	}
	requireLimit(t, 250*memoryMiB)
	if d.coreRestarted {
		t.Fatal("memory-only apply restarted the core")
	}
	if details := lastAudit(t, d, "Apply configuration"); !strings.Contains(details, "400 → 250") || !strings.Contains(details, "core not restarted") {
		t.Fatalf("audit: %s", details)
	}

	for _, bad := range []int64{0, -1, 8796093022208} {
		rejected := d.Config()
		rejected.System.MemoryLimitMiB = new(model.MemoryLimitMiB(bad))
		if err := d.Apply(context.Background(), rejected); err == nil {
			t.Fatalf("invalid limit %d accepted", bad)
		}
		requireLimit(t, 250*memoryMiB)
		if got := d.Config().System.MemoryLimitMiB; got == nil || *got != 250 {
			t.Fatalf("invalid apply replaced the saved limit with %v", got)
		}
	}

	gate.fail = true
	failed := d.Config()
	failed.System.MemoryLimitMiB = new(model.MemoryLimitMiB(400))
	if err := d.Apply(context.Background(), failed); err == nil {
		t.Fatal("activation failure was accepted")
	}
	requireLimit(t, 250*memoryMiB)
	d.mu.Lock()
	pending, installed := d.planPending, d.planOn
	d.mu.Unlock()
	if !pending || installed {
		t.Fatal("failed activation and rollback did not leave the firewall plan pending")
	}
	if details := lastAudit(t, d, "Configuration apply failed"); !strings.Contains(details, "rollback also failed") {
		t.Fatalf("activation rollback audit: %s", details)
	}
	gate.fail = false

	cleared := d.Config()
	cleared.System.MemoryLimitMiB = nil
	if err := d.Apply(context.Background(), cleared); err != nil {
		t.Fatalf("clear: %v", err)
	}
	requireLimit(t, baseline)
	d.mu.Lock()
	pending, installed = d.planPending, d.planOn
	d.mu.Unlock()
	if pending || !installed {
		t.Fatal("successful apply did not commit the pending firewall plan")
	}
	if d.coreRestarted {
		t.Fatal("clearing the memory limit restarted the core")
	}
	if details := lastAudit(t, d, "memory limit cleared"); !strings.Contains(details, "core not restarted") {
		t.Fatalf("clear audit: %s", details)
	}
	reloaded, err := model.Load(path)
	if err != nil || reloaded.System.MemoryLimitMiB != nil {
		t.Fatalf("clear was not saved: %+v %v", reloaded, err)
	}
	stop()
	requireLimit(t, baseline)
}

// A failed start must not leave the saved recommendation installed in the process.
func TestMemoryLimitStartFailureRestoresBaseline(t *testing.T) {
	holdMemoryLimit(t)
	baseline := int64(300) * memoryMiB
	debug.SetMemoryLimit(baseline)
	cfg := quietConfig(t)
	cfg.System.MemoryLimitMiB = new(model.MemoryLimitMiB(400))
	d := newMemoryDaemon(t, writeSavedConfig(t, cfg), &gateRunner{fail: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := d.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "interception rules") {
		t.Fatalf("start failure: %v", err)
	}
	requireLimit(t, baseline)
}

// GOMEMLIMIT is captured at daemon initialization and restored when the override is cleared.
func TestMemoryLimitInheritsExternalGOMEMLIMIT(t *testing.T) {
	if os.Getenv("KEENPROXY_MEMORY_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestMemoryLimitInheritsExternalGOMEMLIMIT$")
		cmd.Env = append(os.Environ(), "KEENPROXY_MEMORY_CHILD=1", "GOMEMLIMIT=293601280")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		return
	}
	if got := debug.SetMemoryLimit(-1); got != 293601280 {
		t.Fatalf("GOMEMLIMIT not visible to the runtime: %d", got)
	}
	cfg := quietConfig(t)
	path := writeSavedConfig(t, cfg)
	d, stop := startMemoryDaemon(t, path, &gateRunner{}, 293601280)

	next := d.Config()
	next.System.MemoryLimitMiB = new(model.MemoryLimitMiB(400))
	if err := d.Apply(context.Background(), next); err != nil {
		t.Fatalf("apply: %v", err)
	}
	requireLimit(t, 400*memoryMiB)
	cleared := d.Config()
	cleared.System.MemoryLimitMiB = nil
	if err := d.Apply(context.Background(), cleared); err != nil {
		t.Fatalf("clear: %v", err)
	}
	requireLimit(t, 293601280)
	stop()
}

// The built-in budget applies only when no startup limit was provided; clearing
// restores that choice while shutdown still restores the original process state.
func TestMemoryLimitDefaultAndExplicitOff(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		want int64
	}{
		{"default", "", 805306368},
		{"explicit_off", "off", math.MaxInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			holdMemoryLimit(t)
			t.Setenv("GOMEMLIMIT", tc.env)
			debug.SetMemoryLimit(math.MaxInt64)
			cfg := quietConfig(t)
			d, stop := startMemoryDaemon(t, writeSavedConfig(t, cfg), &gateRunner{}, tc.want)
			requireLimit(t, tc.want)

			explicit := d.Config()
			explicit.System.MemoryLimitMiB = new(model.MemoryLimitMiB(400))
			if err := d.Apply(context.Background(), explicit); err != nil {
				t.Fatal(err)
			}
			requireLimit(t, 419430400)
			cleared := d.Config()
			cleared.System.MemoryLimitMiB = nil
			if err := d.Apply(context.Background(), cleared); err != nil {
				t.Fatal(err)
			}
			requireLimit(t, tc.want)
			if d.coreRestarted {
				t.Fatal("clearing the override restarted the core")
			}
			stop()
			requireLimit(t, math.MaxInt64)
		})
	}
}
