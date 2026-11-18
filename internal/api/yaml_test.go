package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestYAMLPreviewAndExport(t *testing.T) {
	s, d := newServer()
	h := s.Handler()
	if w := do(t, h, "GET", "/api/config/yaml", "", "", lan); w.Code != http.StatusUnauthorized {
		t.Fatal(w.Code)
	}
	w := do(t, h, "POST", "/api/config/import", `{"yaml":"{}"}`, "secret", lan)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if d.applied != nil {
		t.Fatal("preview applied")
	}
	var c map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if c["schema_version"] != float64(1) {
		t.Fatal(c)
	}
	w = do(t, h, "POST", "/api/config/import", `{"yaml":"{}\n---\n{}"}`, "secret", lan)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	w = do(t, h, "GET", "/api/config/yaml", "", "secret", lan)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w.Header().Get("Content-Disposition") == "" {
		t.Fatal("missing download header")
	}
}

func TestDNSBypassSourcesApplyAndExport(t *testing.T) {
	s, d := newServer()
	h := s.Handler()
	const resolver = "192.168.37.53"
	preview := do(t, h, "POST", "/api/config/import", `{"yaml":"dns: {bypass_sources: [`+resolver+`]}"}`, "secret", lan)
	if preview.Code != http.StatusOK || d.applied != nil || !strings.Contains(preview.Body.String(), `"bypass_sources":["`+resolver+`"]`) {
		t.Fatalf("preview: %d %s, applied=%v", preview.Code, preview.Body, d.applied != nil)
	}
	applied := do(t, h, "PUT", "/api/config", preview.Body.String(), "secret", lan)
	if applied.Code != http.StatusOK || !strings.Contains(applied.Body.String(), `"bypass_sources":["`+resolver+`"]`) {
		t.Fatalf("apply: %d %s", applied.Code, applied.Body)
	}
	bad := do(t, h, "PUT", "/api/config", `{"dns":{"bypass_sources":["192.168.37.0/24"]}}`, "secret", lan)
	if bad.Code != http.StatusUnprocessableEntity || !strings.Contains(bad.Body.String(), "dns.bypass_sources[0]") {
		t.Fatalf("invalid apply: %d %s", bad.Code, bad.Body)
	}
	redacted := do(t, h, "GET", "/api/config/yaml?redacted=1", "", "secret", lan)
	if redacted.Code != http.StatusOK || strings.Contains(redacted.Body.String(), resolver) {
		t.Fatalf("redacted export: %d %s", redacted.Code, redacted.Body)
	}
	full := do(t, h, "GET", "/api/config/yaml", "", "secret", lan)
	if full.Code != http.StatusOK {
		t.Fatalf("backup: %d %s", full.Code, full.Body)
	}
	cfg, err := model.Parse(full.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.DNS.BypassSources; len(got) != 1 || got[0] != resolver {
		t.Fatalf("bypass sources in backup = %v", got)
	}
	cleared := do(t, h, "PUT", "/api/config", `{"dns":{"bypass_sources":[]}}`, "secret", lan)
	if cleared.Code != http.StatusOK || strings.Contains(cleared.Body.String(), "bypass_sources") {
		t.Fatalf("clear: %d %s", cleared.Code, cleared.Body)
	}
}

func TestSupportExportRemovesURLSecrets(t *testing.T) {
	s, d := newServer()
	d.cfg.DNS.Upstreams = []string{"https://dns.example/private-token"}
	d.cfg.GeoIP.Databases = []model.GeoIPDatabase{{ID: "custom-1", URL: "https://geo.example/geo-token", Enabled: true}}
	d.cfg.Failover.URL = "https://health.example/health-token"
	w := do(t, s.Handler(), "GET", "/api/config/yaml?redacted=1", "", "secret", lan)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, v := range []string{"private-token", "geo-token", "health-token"} {
		if strings.Contains(w.Body.String(), v) {
			t.Fatal("secret leaked", v)
		}
	}
}

func TestRedactedYAMLOmitsAmneziaWGSecrets(t *testing.T) {
	s, d := newServer()
	const (
		privateKey = "AWG-PRIVATE-7f3a9c1e-not-a-wireguard-key"
		psk        = "AWG-PSK-91ab44d0-not-a-wireguard-key"
		hpk        = "AWG-HPK-c0ffee12-not-a-wireguard-key"
		endpoint   = "awg-endpoint-203-0-113-44.example:51820"
	)
	profile := "[Interface]\nPrivateKey = " + privateKey + "\nHeaderProtectionKey = " + hpk + "\n[Peer]\nPresharedKey = " + psk + "\nEndpoint = " + endpoint + "\n"
	d.cfg.Connections = []model.Connection{{ID: "awg", Type: model.ConnAmneziaWG, AmneziaWG: profile}}
	h := s.Handler()
	plain := do(t, h, "GET", "/api/config/yaml", "", "secret", lan)
	if plain.Code != 200 {
		t.Fatal(plain.Code, plain.Body.String())
	}
	for _, secret := range []string{privateKey, psk, hpk, endpoint} {
		if !strings.Contains(plain.Body.String(), secret) {
			t.Fatalf("fixture did not retain %s", secret)
		}
	}
	w := do(t, h, "GET", "/api/config/yaml?redacted=1", "", "secret", lan)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, secret := range []string{privateKey, psk, hpk, endpoint} {
		if strings.Contains(body, secret) {
			t.Fatalf("redacted YAML leaked %s", secret)
		}
	}
	if !strings.Contains(body, "redacted: true") || !strings.Contains(body, "type: amneziawg") {
		t.Fatalf("redacted export lost connection identity: %s", body)
	}
	if d.cfg.Connections[0].AmneziaWG != profile {
		t.Fatal("export mutated the live profile")
	}
}
