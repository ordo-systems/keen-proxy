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
