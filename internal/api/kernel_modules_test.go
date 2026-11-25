package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

type moduleDiagnosticStub struct {
	*fakeDaemon
	loaded string
}

func (s *moduleDiagnosticStub) KernelModuleDiagnostics(context.Context) netfilter.KernelModules {
	guard := netfilter.KernelModuleStatus{State: "unloaded", CanLoad: true}
	families := netfilter.GuardFamilies{IPv4: "unregistered", IPv6: "not_required"}
	if s.loaded == "guard" {
		guard = netfilter.KernelModuleStatus{State: "registered"}
		families.IPv4 = "registered"
	}
	return netfilter.KernelModules{
		Guard:  netfilter.GuardModuleStatus{KernelModuleStatus: guard, GuardFamilies: families},
		TProxy: netfilter.KernelModuleStatus{State: "unknown"},
	}
}

func (s *moduleDiagnosticStub) LoadKernelModule(_ context.Context, feature string) error {
	s.loaded = feature
	return nil
}

func TestFirmwareModuleActionRequiresTokenAndSameOrigin(t *testing.T) {
	const base = "/api/diagnostics/kernel-modules"
	s, fake := newServer()
	fake.cfg.API.NoTokenFrom = []string{"192.168.7.0/24"}
	stub := &moduleDiagnosticStub{fakeDaemon: fake}
	s.D = stub
	h := s.Handler()
	w := do(t, h, "GET", base, "", "", lan)
	var got kernelModuleResponse
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &got) != nil ||
		!got.Guard.CanLoad || !got.TokenRequired || got.Guard.IPv4 != "unregistered" || got.Guard.IPv6 != "not_required" {
		t.Fatalf("read-only diagnostics: %d %s", w.Code, w.Body)
	}
	for _, tc := range []struct {
		path, token, origin string
		want                int
	}{
		{"guard", "", "http://keenproxy.example", http.StatusForbidden},
		{"guard", "secret", "https://other.example", http.StatusForbidden},
		{"xt_socket", "secret", "http://keenproxy.example", http.StatusNotFound},
	} {
		r := httptest.NewRequest("POST", "http://keenproxy.example"+base+"/"+tc.path+"/load", nil)
		r.RemoteAddr = lan
		r.Header.Set("Origin", tc.origin)
		if tc.token != "" {
			r.AddCookie(&http.Cookie{Name: cookieName, Value: tc.token})
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want || stub.loaded != "" {
			t.Fatalf("%+v: status %d, loaded %q", tc, w.Code, stub.loaded)
		}
	}
	w = do(t, h, "POST", base+"/guard/load", "", "secret", lan)
	got = kernelModuleResponse{}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Guard.State != "registered" || got.Guard.CanLoad || got.TokenRequired || stub.loaded != "guard" || fake.applied != nil {
		t.Fatalf("verified load: %d %s, loaded=%q", w.Code, w.Body, stub.loaded)
	}
}

func TestSupportBundleKeepsOnlyKnownFirmwareLoadMetadata(t *testing.T) {
	for _, target := range []string{"guard", "tproxy", "private-config"} {
		entry := journal.Entry{Action: daemon.FirmwareModuleLoadAction, Target: target, Result: "error", Details: "permission denied at private path"}
		safe := supportEntry(journal.Audit, entry, func(_, _ string) string { return "connection-1" })
		want := target
		if target == "private-config" {
			want = ""
		}
		if safe.Action != "Firmware module load" || safe.Target != want || safe.Result != "error" || safe.Details != "permission denied" {
			t.Fatalf("incorrect sanitized event: %+v", safe)
		}
	}
}
