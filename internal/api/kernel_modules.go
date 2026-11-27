package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
	"github.com/ordo-systems/keen-proxy/internal/update"
)

type kernelModuleDaemon interface {
	KernelModuleDiagnostics(context.Context) netfilter.KernelModules
	LoadKernelModule(context.Context, string) error
	SetKernelModuleAutoload(context.Context, string, bool) error
}

type kernelModuleResponse struct {
	netfilter.KernelModules
	// TokenRequired indicates that the browser has no authenticated session cookie.
	TokenRequired bool `json:"token_required"`
}

func (s *Server) kernelModules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	unknown := netfilter.KernelModuleStatus{State: netfilter.ModuleUnknown}
	status := netfilter.KernelModules{Guard: netfilter.GuardModuleStatus{KernelModuleStatus: unknown}, TProxy: unknown}
	if d, ok := s.D.(kernelModuleDaemon); ok {
		status = d.KernelModuleDiagnostics(r.Context())
	}
	writeJSON(w, http.StatusOK, kernelModuleResponse{status, !s.tokenCookieOK(r)})
}

// mutateKernelModule applies the same authorization and update lock to both operations.
func (s *Server) mutateKernelModule(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.tokenOK(r) {
		writeError(w, http.StatusForbidden, "panel token required to change firmware module settings")
		return
	}
	if err := browserOrigin.Check(r); err != nil {
		writeError(w, http.StatusForbidden, "cross-origin firmware module action denied")
		return
	}
	feature := r.PathValue("feature")
	if netfilter.FirmwareModuleName(feature) == "" {
		writeError(w, http.StatusNotFound, "unknown kernel feature")
		return
	}
	d, ok := s.D.(kernelModuleDaemon)
	if !ok {
		writeError(w, http.StatusConflict, netfilter.ErrModuleNotLoadable.Error())
		return
	}
	var change struct {
		Enabled *bool `json:"enabled"`
	}
	if r.Method == http.MethodPut {
		if err := decodeJSONRequest(w, r, 256, &change); err != nil || change.Enabled == nil {
			writeError(w, http.StatusBadRequest, "expected a JSON boolean in the enabled field")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	ctx = daemon.WithActor(ctx, daemon.Actor{Who: "user", From: clientIP(r)})
	err := s.Updates.WithoutInstall(func() error {
		if change.Enabled != nil {
			return d.SetKernelModuleAutoload(ctx, feature, *change.Enabled)
		}
		return d.LoadKernelModule(ctx, feature)
	})
	if err != nil {
		switch {
		case errors.Is(err, update.ErrBusy):
			writeError(w, http.StatusConflict, "wait for the managed update to finish before changing firmware module settings")
		case errors.Is(err, netfilter.ErrModuleNotLoadable):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusUnprocessableEntity, err.Error())
		}
		return
	}
	s.kernelModules(w, r)
}
