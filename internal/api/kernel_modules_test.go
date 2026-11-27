package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

type moduleDiagnosticStub struct {
	*fakeDaemon
	loaded        string
	autoload      bool
	autoloadCalls int
}

func (s *moduleDiagnosticStub) KernelModuleDiagnostics(context.Context) netfilter.KernelModules {
	guard := netfilter.KernelModuleStatus{State: "unloaded", CanLoad: true}
	families := netfilter.GuardFamilies{IPv4: "unregistered", IPv6: "not_required"}
	if s.loaded == "guard" {
		guard = netfilter.KernelModuleStatus{State: "registered", Autoload: s.autoload, CanAutoload: !s.autoload}
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

func (s *moduleDiagnosticStub) SetKernelModuleAutoload(_ context.Context, feature string, enabled bool) error {
	s.autoloadCalls++
	if enabled && s.loaded != feature {
		return netfilter.ErrModuleNotLoadable
	}
	s.autoload = enabled
	return nil
}

func TestFirmwareModuleAutoloadAction(t *testing.T) {
	const base = "http://keenproxy.example/api/diagnostics/kernel-modules/"
	s, fake := newServer()
	fake.cfg.API.NoTokenFrom = []string{"192.168.7.0/24"}
	stub := &moduleDiagnosticStub{fakeDaemon: fake}
	s.D = stub
	h := s.Handler()
	request := func(feature, origin, token, body string, want int) kernelModuleResponse {
		t.Helper()
		r := httptest.NewRequest("PUT", base+feature+"/autoload", strings.NewReader(body))
		r.RemoteAddr = lan
		r.Header.Set("Origin", origin)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" {
			t.Fatalf("%s %s: got %d %s, want %d", feature, body, w.Code, w.Body, want)
		}
		var got kernelModuleResponse
		if want == http.StatusOK && json.Unmarshal(w.Body.Bytes(), &got) != nil {
			t.Fatalf("invalid diagnostics: %s", w.Body)
		}
		return got
	}
	const origin = "http://keenproxy.example"
	request("guard", origin, "", `{"enabled":true}`, http.StatusForbidden)
	request("guard", "http://other.example", "secret", `{"enabled":true}`, http.StatusForbidden)
	request("xt_socket", origin, "secret", `{"enabled":true}`, http.StatusNotFound)
	for _, body := range []string{`{}`, `{"enabled":null}`, `{"enabled":"true"}`, `{"enabled":true} false`} {
		request("guard", origin, "secret", body, http.StatusBadRequest)
	}
	if stub.autoloadCalls != 0 {
		t.Fatal("unauthorized or malformed request reached daemon")
	}
	request("guard", origin, "secret", `{"enabled":true}`, http.StatusConflict)
	stub.loaded = "guard"
	got := request("guard", origin, "secret", `{"enabled":true}`, http.StatusOK)
	if !got.Guard.Autoload || !got.TokenRequired || fake.applied != nil {
		t.Fatalf("enable changed panel session or routing: %+v", got)
	}
	got = request("guard", origin, "secret", `{"enabled":false}`, http.StatusOK)
	if got.Guard.Autoload || got.Guard.State != "registered" || !got.Guard.CanAutoload {
		t.Fatalf("disable changed module registration: %+v", got)
	}
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
	r := httptest.NewRequest("POST", base+"/guard/load", nil)
	r.RemoteAddr = lan
	r.AddCookie(&http.Cookie{Name: cookieName, Value: "secret"})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	got = kernelModuleResponse{}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Guard.State != "registered" || got.Guard.CanLoad || got.TokenRequired || stub.loaded != "guard" || fake.applied != nil {
		t.Fatalf("verified load: %d %s, loaded=%q", w.Code, w.Body, stub.loaded)
	}
}

func TestFirmwareModuleBearerDoesNotCreatePanelSession(t *testing.T) {
	const base = "/api/diagnostics/kernel-modules"
	s, fake := newServer()
	fake.cfg.API.NoTokenFrom = []string{"192.168.7.0/24"}
	stub := &moduleDiagnosticStub{fakeDaemon: fake}
	s.D = stub
	h := s.Handler()
	for _, token := range []string{"wrong", "secret"} {
		r := httptest.NewRequest("POST", "http://keenproxy.example"+base+"/guard/load", nil)
		r.RemoteAddr = lan
		r.Header.Set("Origin", "http://keenproxy.example")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if token == "wrong" {
			if w.Code != http.StatusForbidden || stub.loaded != "" {
				t.Fatalf("invalid token authorized load: %d %s", w.Code, w.Body)
			}
			continue
		}
		var got kernelModuleResponse
		if w.Code != http.StatusOK || w.Header().Get("Set-Cookie") != "" ||
			json.Unmarshal(w.Body.Bytes(), &got) != nil || !got.TokenRequired || got.Guard.State != "registered" {
			t.Fatalf("one-shot authorization leaked into the session: %d %s", w.Code, w.Body)
		}
	}
	if w := do(t, h, "POST", "/api/updates/install", "", "", lan); w.Code != http.StatusForbidden {
		t.Fatalf("trusted network alone authorized update install: %d %s", w.Code, w.Body)
	}
}

func TestSupportBundleKeepsOnlyKnownFirmwareModuleMetadata(t *testing.T) {
	alias := func(_, _ string) string { return "connection-1" }
	for _, action := range []string{daemon.FirmwareModuleLoadAction, daemon.FirmwareModuleAutoloadAction} {
		for _, target := range []string{"guard", "tproxy", "private-config"} {
			entry := journal.Entry{Action: action, Target: target, Result: "error", Details: "permission denied at private path"}
			safe := supportEntry(journal.Audit, entry, alias)
			want := target
			if target == "private-config" {
				want = ""
			}
			if safe.Action != action || safe.Target != want || safe.Result != "error" || safe.Details != "permission denied" {
				t.Fatalf("incorrect sanitized event: %+v", safe)
			}
		}
	}
	entry := journal.Entry{Action: daemon.FirmwareModuleAutoloadAction, Target: "tproxy", Result: "ok", Details: "enabled=false (from 192.0.2.2)"}
	if got := supportEntry(journal.Audit, entry, alias).Details; got != "enabled=false" {
		t.Fatalf("incorrect sanitized setting: %q", got)
	}
	entry = journal.Entry{Message: "firmware module autoload failed feature=tproxy err=permission denied at private path"}
	if got := supportEntry(journal.System, entry, alias).Message; got != "firmware module autoload failed: permission denied" {
		t.Fatalf("incorrect sanitized system event: %q", got)
	}
}
