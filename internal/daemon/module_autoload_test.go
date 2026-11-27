package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

func TestKernelModuleAutoloadEnrollmentLeavesConfigUntouched(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeAutoloadFixture(t, path, "saved configuration")
	writeAutoloadFixture(t, path+".previous", "previous configuration")
	d := newMemoryDaemon(t, path, nil)
	status := netfilter.KernelModules{Guard: netfilter.GuardModuleStatus{KernelModuleStatus: netfilter.KernelModuleStatus{State: "registered", CanAutoload: true}}}
	d.moduleDiagnostics = func(context.Context) netfilter.KernelModules { return status }
	d.moduleAutoload = func(context.Context, string) (bool, error) {
		t.Fatal("changing the opt-in attempted to load a module")
		return false, nil
	}
	for _, feature := range []string{"tproxy", "../guard"} {
		if err := d.SetKernelModuleAutoload(ctx, feature, true); !errors.Is(err, netfilter.ErrModuleNotLoadable) {
			t.Fatalf("enable %q: %v", feature, err)
		}
	}
	for range 2 {
		if err := d.SetKernelModuleAutoload(ctx, "guard", true); err != nil {
			t.Fatal(err)
		}
	}
	if marker, err := os.Lstat(path + ".autoload-guard"); err != nil || !marker.Mode().IsRegular() || marker.Size() != 0 {
		t.Fatalf("expected an independent empty guard marker: %v, %v", marker, err)
	}
	got := d.KernelModuleDiagnostics(ctx)
	if !got.Guard.Autoload || !got.Guard.CanAutoload || got.TProxy.Autoload || got.TProxy.CanAutoload {
		t.Fatalf("unexpected enabled diagnostics: %+v", got)
	}
	status.Guard.KernelModuleStatus = netfilter.KernelModuleStatus{State: "not_found"}
	got = d.KernelModuleDiagnostics(ctx)
	if !got.Guard.Autoload || got.Guard.CanAutoload || got.Guard.State != "not_found" {
		t.Fatalf("missing firmware lost saved state or permitted enable: %+v", got)
	}
	d.moduleDiagnostics = func(context.Context) netfilter.KernelModules {
		t.Fatal("disabling must not probe firmware")
		return netfilter.KernelModules{}
	}
	for range 2 {
		if err := d.SetKernelModuleAutoload(ctx, "guard", false); err != nil {
			t.Fatal(err)
		}
	}
	for _, feature := range []string{"guard", "tproxy"} {
		if _, err := os.Lstat(path + ".autoload-" + feature); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected marker for %q: %v", feature, err)
		}
	}
	for filename, want := range map[string]string{path: "saved configuration", path + ".previous": "previous configuration"} {
		if raw, err := os.ReadFile(filename); string(raw) != want || err != nil {
			t.Fatalf("state modified %s: %q, %v", filename, raw, err)
		}
	}
}

func TestKernelModuleAutoloadRejectsUntrustedMarkers(t *testing.T) {
	for _, kind := range []string{"symlink", "directory", "hardlink", "writable marker", "writable directory", "nonempty marker"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			marker := path + ".autoload-guard"
			target := filepath.Join(dir, "target")
			writeAutoloadFixture(t, target, "")
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(target, marker)
			case "directory":
				err = os.Mkdir(marker, 0o700)
			case "hardlink":
				err = os.Link(target, marker)
			case "writable marker":
				writeAutoloadFixture(t, marker, "")
				err = os.Chmod(marker, 0o622)
			case "writable directory":
				writeAutoloadFixture(t, marker, "")
				err = os.Chmod(dir, 0o722)
			case "nonempty marker":
				writeAutoloadFixture(t, marker, "unexpected")
			}
			if err != nil {
				t.Fatal(err)
			}
			if enrolled, verified, err := loadSavedKernelModule(t.Context(), path, "guard", nil); enrolled || verified || err == nil {
				t.Fatalf("unsafe marker: enrolled=%t verified=%t error=%v", enrolled, verified, err)
			}
			status := netfilter.KernelModuleStatus{State: "registered", CanAutoload: true}
			decorateAutoload(path, "guard", &status)
			if status.Autoload || status.CanAutoload {
				t.Fatalf("reported unsafe marker: %+v", status)
			}
		})
	}
}

func TestAutoloadUpdateGuardIgnoresAbsentOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeAutoloadFixture(t, path+".autoload-tproxy", "")
	if err := AutoloadUpdateGuard(t.Context(), path, nil); err != nil {
		t.Fatal(err)
	}
	if enrolled, verified, err := loadSavedKernelModule(t.Context(), path, "guard", nil); enrolled || verified || err != nil {
		t.Fatalf("absent marker: enrolled=%t verified=%t error=%v", enrolled, verified, err)
	}
}

func TestKernelModuleAutoloadRunsBeforeStartupPreflight(t *testing.T) {
	for _, tc := range []struct {
		mode model.InterceptMode
		want []string
	}{
		{model.InterceptRedirect, []string{"guard"}},
		{model.InterceptTProxy, []string{"guard", "tproxy", "preflight"}},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			cfg := quietConfig(t)
			cfg.Intercept.Mode = tc.mode
			path := writeSavedConfig(t, cfg)
			writeAutoloadFixture(t, path+".autoload-guard", "")
			writeAutoloadFixture(t, path+".autoload-tproxy", "")
			d := newMemoryDaemon(t, path, &recoveryFirewall{})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var calls []string
			d.moduleAutoload = func(_ context.Context, feature string) (bool, error) {
				calls = append(calls, feature)
				if tc.mode == model.InterceptRedirect {
					cancel() // Stop before reaching normal network activation.
					return false, nil
				}
				if feature == "guard" {
					return true, nil
				}
				return false, errors.New("firmware descriptor not found")
			}
			readiness := netfilter.TProxyReadiness{State: netfilter.TProxyUnknown}
			d.tproxyProbe = func(context.Context) netfilter.TProxyReadiness {
				calls = append(calls, "preflight")
				return readiness
			}
			d.mu.Lock()
			blocked, err := d.startLocked(ctx, d.applyLocked)
			d.mu.Unlock()
			wantBlocked := tc.mode == model.InterceptTProxy
			if err != nil || !slices.Equal(calls, tc.want) || (blocked != nil) != wantBlocked {
				t.Fatalf("startup got calls=%v, management-only=%t, err=%v", calls, blocked != nil, err)
			}
			entries := d.Journal(journal.Audit).Find(journal.Query{Text: FirmwareModuleLoadAction}, nil).Entries
			if !wantBlocked {
				if len(entries) != 0 {
					t.Fatalf("no-op boot emitted load audit: %+v", entries)
				}
				return
			}
			if !slices.ContainsFunc(entries, func(e journal.Entry) bool {
				return e.Target == "guard" && e.Result == "ok" && strings.Contains(e.Details, "registration verified")
			}) || !slices.ContainsFunc(entries, func(e journal.Entry) bool {
				return e.Target == "tproxy" && e.Result == "error" && strings.Contains(e.Details, "descriptor not found")
			}) {
				t.Fatalf("missing boot evidence: %+v", entries)
			}
			readiness.State = netfilter.TProxyReady
			if err := d.tproxyPreflight(ctx, cfg, errors.New("autoload failed")); err != nil {
				t.Fatalf("verified readiness failed to supersede autoload error: %v", err)
			}
		})
	}
}

func TestStartupRecoversIfEnrolledTProxyRulesAreRejected(t *testing.T) {
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.Intercept.Mode = model.InterceptTProxy
	path := writeSavedConfig(t, cfg)
	writeAutoloadFixture(t, path+".autoload-tproxy", "")
	runner := &recoveryFirewall{fail: true, jumps: make(map[[3]string]bool), chains: make(map[[2]string]bool)}
	d := newMemoryDaemon(t, path, runner)
	t.Cleanup(d.shutdown)
	d.moduleAutoload = func(context.Context, string) (bool, error) { return true, nil }
	d.tproxyProbe = func(context.Context) netfilter.TProxyReadiness {
		return netfilter.TProxyReadiness{State: netfilter.TProxyUnknown}
	}
	reported := false
	d.opt.OnStartupBlocked = func() { reported = true }
	ctx := t.Context()
	d.mu.Lock()
	blocked, err := d.startLocked(ctx, func(ctx context.Context, cfg *model.Config, preserveRoutes bool) error {
		if !preserveRoutes {
			t.Error("enrolled startup may replace unrelated policy routing")
		}
		// Exercise the real firewall installation without a platform-specific
		// transparent socket or a privileged policy route.
		d.plan = netfilter.Plan{Mode: cfg.Intercept.Mode}
		return d.installFirewall(ctx)
	})
	d.mu.Unlock()
	if err != nil || blocked == nil || !reported {
		t.Fatalf("rejected rules did not reach management-only: blocked=%t reported=%t err=%v", blocked != nil, reported, err)
	}
	if runner.attempts != 1 || len(runner.jumps) != 0 || d.Config().Intercept.Mode != model.InterceptTProxy {
		t.Fatalf("startup did not remove partially applied interception: attempts=%d jumps=%v", runner.attempts, runner.jumps)
	}
}

func TestStartupKeepsManagementOnEnrolledTProxyRouteConflict(t *testing.T) {
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.Intercept.Mode = model.InterceptTProxy
	path := writeSavedConfig(t, cfg)
	writeAutoloadFixture(t, path+".autoload-tproxy", "")
	runner := &recoveryFirewall{jumps: make(map[[3]string]bool)}
	d := newMemoryDaemon(t, path, runner)
	t.Cleanup(d.shutdown)
	d.moduleAutoload = func(context.Context, string) (bool, error) { return true, nil }
	d.tproxyProbe = func(context.Context) netfilter.TProxyReadiness {
		return netfilter.TProxyReadiness{State: netfilter.TProxyReady}
	}
	d.mu.Lock()
	blocked, err := d.startLocked(t.Context(), func(context.Context, *model.Config, bool) error {
		return errors.Join(errPolicyRouteAcquisition, errors.New("conflicting policy rule already exists"))
	})
	d.mu.Unlock()
	if err != nil || blocked == nil || !d.TProxyReadiness(t.Context()).StartupBlocked || runner.attempts != 0 {
		t.Fatalf("route conflict did not preserve management: blocked=%t restores=%d err=%v", blocked != nil, runner.attempts, err)
	}
}

func writeAutoloadFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
