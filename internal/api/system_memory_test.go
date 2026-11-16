package api

import (
	"context"
	"net/http"
	"runtime/debug"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// These tests observe process-wide state and must not run in parallel.
func holdMemoryLimit(t *testing.T) {
	t.Helper()
	before := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(before) })
}

// The demo API accepts and returns the recommendation without changing the host process.
func TestDemoMemoryLimitPreservedWithoutRuntimeChange(t *testing.T) {
	holdMemoryLimit(t)
	before := debug.SetMemoryLimit(-1)
	cfg := &model.Config{}
	cfg.Defaults()
	d := NewDemo(cfg)
	next := d.Config()
	next.System.MemoryLimitMiB = new(model.MemoryLimitMiB(400))
	if err := d.Apply(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if got := d.Config().System.MemoryLimitMiB; got == nil || *got != 400 {
		t.Fatalf("demo dropped the memory limit: %v", got)
	}
	if debug.SetMemoryLimit(-1) != before {
		t.Fatal("demo changed the process memory limit")
	}
	cleared := d.Config()
	cleared.System.MemoryLimitMiB = nil
	if err := d.Apply(context.Background(), cleared); err != nil {
		t.Fatal(err)
	}
	if d.Config().System.MemoryLimitMiB != nil {
		t.Fatal("demo kept a cleared memory limit")
	}
	if debug.SetMemoryLimit(-1) != before {
		t.Fatal("demo changed the process memory limit")
	}
}

// PUT /api/config is the only memory-limit route and still requires authentication.
func TestConfigRoutePreservesMemoryLimit(t *testing.T) {
	holdMemoryLimit(t)
	before := debug.SetMemoryLimit(-1)
	cfg := &model.Config{}
	cfg.Defaults()
	ui := fstest.MapFS{"index.html": {Data: []byte("<div id=app>")}}
	s := &Server{D: NewDemo(cfg), Token: "secret", UI: ui}
	h := s.Handler()

	body := `{"system":{"memory_limit_mib":400}}`
	if w := do(t, h, "PUT", "/api/config", body, "", lan); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated put: %d", w.Code)
	}
	w := do(t, h, "PUT", "/api/config", body, "secret", lan)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"memory_limit_mib":400`) {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	w = do(t, h, "GET", "/api/config", "", "secret", lan)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"memory_limit_mib":400`) {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	w = do(t, h, "PUT", "/api/config", `{"system":{"memory_limit_mib":0}}`, "secret", lan)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("zero accepted: %d %s", w.Code, w.Body)
	}
	w = do(t, h, "GET", "/api/config", "", "secret", lan)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"memory_limit_mib":400`) {
		t.Fatalf("rejected put changed the stored limit: %d %s", w.Code, w.Body)
	}
	w = do(t, h, "PUT", "/api/config", `{"system":{"memory_limit_mib":null}}`, "secret", lan)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "memory_limit_mib") {
		t.Fatalf("clear: %d %s", w.Code, w.Body)
	}
	if debug.SetMemoryLimit(-1) != before {
		t.Fatal("config route changed the process memory limit")
	}
}
