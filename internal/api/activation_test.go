package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestDemoDisabledConnectionIsUnavailable(t *testing.T) {
	cfg := &model.Config{Connections: []model.Connection{{ID: "off", Type: model.ConnTrustTunnel, Disabled: true, Fallback: "reserve"}, {ID: "reserve", Type: model.ConnLink, Link: "socks5://203.0.113.2:1080"}}}
	d := &Demo{cfg: cfg, started: time.Now()}
	st := d.Status(context.Background())
	if st.Health["off"].OK || st.Health["off"].Error != "connection is disabled" || st.Failover["off"].Active != "reserve" || len(st.TrustTunnel) != 0 {
		t.Fatalf("dishonest demo status: %+v", st)
	}
	if report, err := d.DiagnosticChecks(context.Background(), "off"); !errors.Is(err, daemon.ErrDiagnosticConnection) || len(report.Results) != 0 {
		t.Fatalf("disabled diagnostic: %+v %v", report, err)
	}
	for _, o := range d.Stats(false).Outbounds {
		if o.Tag == "off" {
			t.Fatal("disabled profile has traffic")
		}
	}
	cfg.Connections[1].Disabled = true
	if st = d.Status(context.Background()); st.Failover["off"].Active != model.TargetBlock {
		t.Fatalf("all-off demo = %+v", st.Failover)
	}
}

func TestDemoDNSDisabledPolicy(t *testing.T) {
	cfg := &model.Config{Connections: []model.Connection{{ID: "off", Type: model.ConnLink, Link: "socks5://203.0.113.1:1080", Disabled: true}}}
	cfg.Defaults()
	cfg.DNS.Route, cfg.DNS.Connection, cfg.DNS.Failure = "connection", "off", "strict"
	cfg.DNS.Upstreams = []string{"https://1.1.1.1/dns-query"}
	d := &Demo{cfg: cfg}
	check, err := d.CheckDNS(context.Background(), cfg)
	if err != nil || !check.Demo || check.Route != "unavailable" || check.RCode != dns.RcodeServerFailure {
		t.Fatalf("strict demo DNS: %+v %v", check, err)
	}
	cfg.DNS.Failure = "direct"
	check, err = d.CheckDNS(context.Background(), cfg)
	if err != nil || check.Route != "direct-fallback" || check.Error == "" {
		t.Fatalf("direct demo DNS: %+v %v", check, err)
	}
}

func TestSupportExportsKeepActivationMetadataPrivate(t *testing.T) {
	const private = "private-disabled-activation.example"
	const historical = "historical-disabled-activation.example"
	s, fake := newServer()
	fake.cfg.Groups = []model.Group{{
		Name: "rules", Target: model.TargetDirect,
		Entries: []string{private}, DisabledEntries: []string{private, historical},
		Preset: &model.Preset{ID: "saved", Base: []string{private}},
	}}
	raw, err := json.Marshal(supportConfig(fake.cfg, func(kind, value string) string { return kind + "-alias" }))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), private) || strings.Contains(string(raw), historical) {
		t.Fatal("anonymous support projection leaked inactive metadata")
	}
	w := do(t, s.Handler(), "GET", "/api/config/yaml?redacted=1", "", "secret", lan)
	if w.Code != 200 || strings.Contains(w.Body.String(), historical) || strings.Contains(w.Body.String(), "disabled_entries") {
		t.Fatalf("redacted YAML leaked historical activation metadata: %s", w.Body)
	}
	if !strings.Contains(w.Body.String(), private) {
		t.Fatal("credential redaction unexpectedly removed existing policy data")
	}
	w = do(t, s.Handler(), "GET", "/api/config/yaml", "", "secret", lan)
	if w.Code != 200 || !strings.Contains(w.Body.String(), private) || !strings.Contains(w.Body.String(), historical) {
		t.Fatal("restorable backup lost inactive metadata")
	}
}

func TestEmptyHostsResponseIsArray(t *testing.T) {
	s, _ := newServer()
	s.D = &Demo{cfg: &model.Config{
		Connections: []model.Connection{{ID: "off", Disabled: true}, {ID: "on"}},
		Groups:      []model.Group{{Target: "on", Entries: []string{"example.com"}}},
	}}
	for _, path := range []string{"/api/stats/hosts?tag=off", "/api/stats/hosts?tag=on&q=missing.invalid"} {
		t.Run(path, func(t *testing.T) {
			w := do(t, s.Handler(), "GET", path, "", "secret", lan)
			var response struct {
				Hosts json.RawMessage `json:"hosts"`
				Total int             `json:"total"`
			}
			if w.Code != 200 {
				t.Fatalf("hosts status = %d: %s", w.Code, w.Body)
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if string(response.Hosts) != "[]" || response.Total != 0 {
				t.Fatalf("empty host list must render as an array: %s", w.Body)
			}
		})
	}
}
