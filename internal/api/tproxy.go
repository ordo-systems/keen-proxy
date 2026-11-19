package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

type tproxyDiagnosticDaemon interface {
	TProxyReadiness(context.Context) daemon.TProxyDiagnostic
}

type tproxyRecoveryDaemon interface {
	RetrySavedTProxy(context.Context) error
}

func (s *Server) tproxyReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if d, ok := s.D.(tproxyDiagnosticDaemon); ok {
		writeJSON(w, http.StatusOK, d.TProxyReadiness(r.Context()))
		return
	}
	writeJSON(w, http.StatusOK, netfilter.TProxyReadiness{State: netfilter.TProxyUnknown, Reason: netfilter.TProxyProbeFailed})
}

func (s *Server) retryTProxy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := browserOrigin.Check(r); err != nil {
		writeError(w, http.StatusForbidden, "cross-origin TPROXY retry denied")
		return
	}
	d, ok := s.D.(tproxyRecoveryDaemon)
	if !ok {
		writeError(w, http.StatusConflict, daemon.ErrStartupNotBlocked.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	ctx = daemon.WithActor(ctx, daemon.Actor{Who: "user", From: clientIP(r)})
	if err := d.RetrySavedTProxy(ctx); err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, daemon.ErrStartupNotBlocked) {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	s.tproxyReadiness(w, r)
}
