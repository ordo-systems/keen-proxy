package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

const tproxyPath = "/api/diagnostics/tproxy"

type tproxyDiagnosticStub struct {
	*fakeDaemon
	result   daemon.TProxyDiagnostic
	calls    int
	retries  int
	retryErr error
}

func (s *tproxyDiagnosticStub) TProxyReadiness(context.Context) daemon.TProxyDiagnostic {
	s.calls++
	return s.result
}

func (s *tproxyDiagnosticStub) RetrySavedTProxy(context.Context) error {
	s.retries++
	if s.retryErr != nil {
		return s.retryErr
	}
	s.result.StartupBlocked = false
	return nil
}

func TestTProxyDiagnosticAuthenticatedAndFresh(t *testing.T) {
	s, fake := newServer()
	probe := &tproxyDiagnosticStub{fakeDaemon: fake, result: daemon.TProxyDiagnostic{
		TProxyReadiness: netfilter.TProxyReadiness{State: netfilter.TProxyUnavailable, Reason: "module_not_loaded"},
		StartupBlocked:  true,
	}}
	s.D = probe
	h := s.Handler()
	if w := do(t, h, "GET", tproxyPath, "", "", lan); w.Code != http.StatusUnauthorized || probe.calls != 0 {
		t.Fatalf("unauthenticated diagnostic status=%d, probe calls=%d", w.Code, probe.calls)
	}
	w := do(t, h, "GET", tproxyPath, "", "secret", lan)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || strings.TrimSpace(w.Body.String()) != `{"state":"unavailable","reason":"module_not_loaded","startup_blocked":true}` {
		t.Fatalf("unavailable diagnostic status=%d, headers=%v, body=%s", w.Code, w.Header(), w.Body)
	}
	probe.result.TProxyReadiness = netfilter.TProxyReadiness{State: netfilter.TProxyReady}
	w = do(t, h, "GET", tproxyPath, "", "secret", lan)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"state":"ready","startup_blocked":true}` || probe.calls != 2 {
		t.Fatalf("retried diagnostic status=%d, calls=%d, body=%s", w.Code, probe.calls, w.Body)
	}
	probe.result.StartupBlocked = false
	w = do(t, h, "GET", tproxyPath, "", "secret", lan)
	if strings.TrimSpace(w.Body.String()) != `{"state":"ready"}` {
		t.Fatalf("active diagnostic body=%s", w.Body)
	}
}

func TestTProxyDiagnosticWithoutProbeIsInconclusive(t *testing.T) {
	s, _ := newServer()
	w := do(t, s.Handler(), "GET", tproxyPath, "", "secret", lan)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"state":"unknown","reason":"probe_failed"}` {
		t.Fatalf("diagnostic status=%d, body=%s", w.Code, w.Body)
	}
}

func TestTProxyRetryUsesAuthenticatedSavedActivation(t *testing.T) {
	const path = tproxyPath + "/retry"
	s, fake := newServer()
	recovery := &tproxyDiagnosticStub{fakeDaemon: fake, result: daemon.TProxyDiagnostic{
		TProxyReadiness: netfilter.TProxyReadiness{State: netfilter.TProxyReady},
		StartupBlocked:  true,
	}}
	s.D = recovery
	h := s.Handler()
	if w := do(t, h, "POST", path, "", "", lan); w.Code != http.StatusUnauthorized || recovery.retries != 0 {
		t.Fatalf("unauthenticated retry status=%d, attempts=%d", w.Code, recovery.retries)
	}
	recovery.retryErr = errors.New("activation failed")
	w := do(t, h, "POST", path, "", "secret", lan)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), recovery.retryErr.Error()) || recovery.calls != 0 {
		t.Fatalf("failed retry status=%d, probes=%d, body=%s", w.Code, recovery.calls, w.Body)
	}
	recovery.retryErr = nil
	w = do(t, h, "POST", path, `{"intercept":{"mode":"redirect"}}`, "secret", lan)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || strings.TrimSpace(w.Body.String()) != `{"state":"ready"}` {
		t.Fatalf("successful retry status=%d, headers=%v, body=%s", w.Code, w.Header(), w.Body)
	}
	if recovery.retries != 2 || fake.applied != nil {
		t.Fatalf("request bypassed the saved activation path: retries=%d, applied=%+v", recovery.retries, fake.applied)
	}
	recovery.retryErr = daemon.ErrStartupNotBlocked
	if w := do(t, h, "POST", path, "", "secret", lan); w.Code != http.StatusConflict {
		t.Fatalf("retry after activation status=%d, body=%s", w.Code, w.Body)
	}
}

func TestTProxyRetryRejectsCrossOriginFromTrustedNetwork(t *testing.T) {
	s, fake := newServer()
	fake.cfg.API.NoTokenFrom = []string{"192.168.7.0/24"}
	recovery := &tproxyDiagnosticStub{fakeDaemon: fake, result: daemon.TProxyDiagnostic{StartupBlocked: true}}
	s.D = recovery
	h := s.Handler()
	for i, origin := range []string{"https://other.example", "http://keenproxy.example"} {
		r := httptest.NewRequest("POST", "http://keenproxy.example"+tproxyPath+"/retry", nil)
		r.RemoteAddr = lan
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := []int{http.StatusForbidden, http.StatusOK}[i]
		if w.Code != want || recovery.retries != i {
			t.Fatalf("origin %q: status=%d (want %d), retry attempts=%d (want %d)", origin, w.Code, want, recovery.retries, i)
		}
	}
}
