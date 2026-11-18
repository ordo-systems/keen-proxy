package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
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

func TestLocalPresetYAMLBackupAndRedaction(t *testing.T) {
	s, d := newServer()
	d.cfg.LocalPresets = []model.LocalPreset{{
		ID: "local-resources", Name: "Private resource list",
		Entries: []string{"internal-only.example"}, DisabledEntries: []string{"internal-only.example"},
	}}
	h := s.Handler()
	backup := do(t, h, "GET", "/api/config/yaml", "", "secret", lan)
	if backup.Code != http.StatusOK {
		t.Fatal(backup.Code, backup.Body.String())
	}
	restored, err := model.Parse(backup.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.LocalPresets) != 1 || len(restored.LocalPresets[0].DisabledEntries) != 1 || restored.LocalPresets[0].DisabledEntries[0] != "internal-only.example" {
		t.Fatalf("backup lost local preset: %+v", restored.LocalPresets)
	}
	redacted := do(t, h, "GET", "/api/config/yaml?redacted=1", "", "secret", lan)
	if redacted.Code != http.StatusOK || strings.Contains(redacted.Body.String(), "local_presets") || strings.Contains(redacted.Body.String(), "internal-only.example") {
		t.Fatalf("unexpected redacted export: %d %s", redacted.Code, redacted.Body.String())
	}
	if len(d.cfg.LocalPresets) != 1 {
		t.Fatal("redacted export changed applied configuration")
	}
}

func TestLargeLocalPresetConfigEndpoints(t *testing.T) {
	s, d := newServer()
	h := s.Handler()
	entries := make([]string, model.MaxLocalPresetEntries)
	label := strings.Repeat("x", 36)
	for i := range entries {
		entries[i] = fmt.Sprintf("%05d.%s.example", i, label)
	}
	preset := model.LocalPreset{
		ID:              "local-large",
		Name:            "Large local preset",
		Entries:         entries,
		DisabledEntries: entries[:500],
	}
	draft := *d.cfg
	draft.LocalPresets = []model.LocalPreset{preset}
	// Match the panel's copy-to-group action: retain both the values and their switches.
	draft.Groups = []model.Group{{
		Name:            preset.Name,
		Target:          model.TargetDirect,
		Entries:         slices.Clone(preset.Entries),
		DisabledEntries: slices.Clone(preset.DisabledEntries),
	}}
	encode := func(v any) string {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	checkCopies := func(c *model.Config) {
		t.Helper()
		if c == nil || len(c.LocalPresets) != 1 || len(c.Groups) == 0 {
			t.Fatal("missing local preset or copied group")
		}
		p, g := c.LocalPresets[0], c.Groups[0]
		if p.ID != preset.ID || p.Name != preset.Name || g.Name != preset.Name || g.Target != model.TargetDirect ||
			!slices.Equal(p.Entries, entries) || !slices.Equal(g.Entries, entries) ||
			!slices.Equal(p.DisabledEntries, preset.DisabledEntries) || !slices.Equal(g.DisabledEntries, preset.DisabledEntries) {
			t.Fatal("local preset or group copy changed")
		}
	}

	body := encode(draft)
	if len(body) <= 2<<20 || len(body) > maxConfigJSONBytes {
		t.Fatalf("fixture outside large Apply range: %d bytes", len(body))
	}
	w := do(t, h, http.MethodPut, "/api/config", body, s.Token, lan)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	checkCopies(d.applied)
	applied := d.applied

	w = do(t, h, http.MethodPost, "/api/presets/preview", encode(map[string]any{
		"config": draft, "id": "steam", "target": model.TargetDirect,
	}), s.Token, lan)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var preview struct {
		Config *model.Config `json:"config"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	checkCopies(preview.Config)
	if groups := preview.Config.Groups; len(groups) != 2 || groups[1].Preset == nil || groups[1].Preset.ID != "steam" {
		t.Fatal("bundled preset wasn't previewed")
	}

	w = do(t, h, http.MethodPost, "/api/dns/check", body, s.Token, lan)
	var dns daemon.DNSCheck
	if err := json.Unmarshal(w.Body.Bytes(), &dns); w.Code != http.StatusOK || err != nil || !dns.Demo {
		t.Fatalf("DNS check: status %d, response %+v, error %v", w.Code, dns, err)
	}

	backup := do(t, h, http.MethodGet, "/api/config/yaml", "", s.Token, lan)
	if backup.Code != http.StatusOK {
		t.Fatal(backup.Code, backup.Body.String())
	}
	if backup.Body.Len() <= 2<<20 {
		t.Fatalf("backup did not exceed the legacy JSON envelope: %d bytes", backup.Body.Len())
	}
	if backup.Body.Len() > 3<<20 {
		t.Fatalf("large supported backup exceeds the panel budget: %d bytes", backup.Body.Len())
	}
	restore, untouched := newServer()
	w = httptest.NewRecorder()
	restore.Handler().ServeHTTP(w, yamlImportRequest(bytes.NewReader(backup.Body.Bytes()), restore.Token))
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var restored model.Config
	if err := json.Unmarshal(w.Body.Bytes(), &restored); err != nil {
		t.Fatal(err)
	}
	checkCopies(&restored)
	if untouched.applied != nil || len(untouched.cfg.LocalPresets) != 0 || len(untouched.cfg.Groups) != 0 {
		t.Fatal("backup preview changed live config")
	}
	if d.applied != applied || len(d.cfg.Groups) != 1 {
		t.Fatal("feature preview changed live config")
	}
}

func TestYAMLRawImportBodyLimit(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	r := yamlImportRequest(strings.NewReader(strings.Repeat(" ", (3<<20)+1)), s.Token)
	r.ContentLength = -1 // enforce the reader limit even without a declared length
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized raw YAML: %d %s", w.Code, w.Body)
	}
	unread := &resourceUnreadBody{}
	r = yamlImportRequest(unread, s.Token)
	r.ContentLength = (3 << 20) + 1
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || unread.read {
		t.Fatalf("oversized declared YAML: %d read=%t", w.Code, unread.read)
	}
}

func TestYAMLImportSerializesWithResourceExchangeBeforeReading(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	started, resume := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(unblock)
	body := &resourcePausedReader{Reader: strings.NewReader("{}"), started: started, resume: resume}
	done := startResourceRequest(h, yamlImportRequest(body, s.Token))
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("YAML import did not start reading")
	}
	for _, tc := range []struct{ path, media string }{
		{"/api/config/import", "application/yaml"},
		{"/api/config/import", "application/json"},
		{resourcePreviewPath + "?format=txt", "application/octet-stream"},
	} {
		unread := &resourceUnreadBody{}
		r := resourceRequest(tc.path, tc.media, unread, s.Token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable || unread.read || w.Header().Get("Connection") != "close" {
			t.Fatalf("competing %s (%s): %d read=%t %v %s", tc.path, tc.media, w.Code, unread.read, w.Header(), w.Body)
		}
	}
	unblock()
	select {
	case w := <-done:
		if w.Code != http.StatusOK {
			t.Fatalf("active YAML import: %d %s", w.Code, w.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("active YAML import did not finish")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, yamlImportRequest(strings.NewReader("{}"), s.Token))
	if w.Code != http.StatusOK {
		t.Fatalf("YAML import did not release gate: %d %s", w.Code, w.Body)
	}
}

func yamlImportRequest(body io.Reader, token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/config/import", body)
	r.RemoteAddr = lan
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/yaml; charset=utf-8")
	return r
}
