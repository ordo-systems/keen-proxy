package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

// ErrStartupNotBlocked means there is no saved startup activation to retry.
var ErrStartupNotBlocked = errors.New("interception startup is not blocked")

// TProxyDiagnostic combines a fresh readiness probe with the startup state.
type TProxyDiagnostic struct {
	netfilter.TProxyReadiness
	StartupBlocked bool `json:"startup_blocked,omitempty"`
}

// TProxyReadiness is a preliminary check; an inconclusive probe is not a veto.
func (d *Daemon) TProxyReadiness(ctx context.Context) TProxyDiagnostic {
	readiness := d.tproxyProbe(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	return TProxyDiagnostic{TProxyReadiness: readiness, StartupBlocked: d.startupBlocked != nil}
}

// FirmwareModuleLoadAction identifies module load attempts in local and exported audits.
const FirmwareModuleLoadAction = "Firmware module load"

// LoadKernelModule serializes an explicit recovery action with Apply and shutdown.
// The kernel's synchronous module initialization cannot be canceled.
func (d *Daemon) LoadKernelModule(ctx context.Context, feature string) error {
	if netfilter.FirmwareModuleName(feature) == "" {
		return netfilter.ErrModuleNotLoadable
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.applyAdmissionLocked(ctx); err != nil {
		return err
	}
	err := d.opt.Firewall.LoadKernelModule(ctx, feature)
	by, from := applyActor(ctx)
	if err != nil {
		d.audit(by, FirmwareModuleLoadAction, feature, "error", err.Error()+from)
	} else {
		d.audit(by, FirmwareModuleLoadAction, feature, "ok", from)
	}
	return err
}

// RetrySavedTProxy activates the configuration retained at blocked startup,
// without saving the configuration or rotating its backup.
func (d *Daemon) RetrySavedTProxy(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.applyAdmissionLocked(ctx); err != nil {
		return err
	}
	if d.startupBlocked == nil {
		return ErrStartupNotBlocked
	}
	return d.applyConfigLocked(ctx, d.cfg, false)
}

func (d *Daemon) tproxyPreflight(ctx context.Context, cfg *model.Config, autoloadErr error) error {
	if cfg.Intercept.Mode != model.InterceptTProxy {
		return nil
	}
	readiness := d.tproxyProbe(ctx)
	if readiness.State == netfilter.TProxyUnavailable {
		return fmt.Errorf("TPROXY interception is unavailable (%s)", readiness.Reason)
	}
	if autoloadErr != nil && readiness.State != netfilter.TProxyReady {
		return fmt.Errorf("TPROXY module autoload failed: %w", autoloadErr)
	}
	return nil
}
