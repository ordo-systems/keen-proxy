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

func (d *Daemon) tproxyPreflight(ctx context.Context, cfg *model.Config) error {
	if cfg.Intercept.Mode != model.InterceptTProxy {
		return nil
	}
	if readiness := d.tproxyProbe(ctx); readiness.State == netfilter.TProxyUnavailable {
		return fmt.Errorf("TPROXY interception is unavailable (%s)", readiness.Reason)
	}
	return nil
}
