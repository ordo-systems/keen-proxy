package compile

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestActivationFallbackRouting(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		primaryOff, reserveOff bool
		last                   string
		want                   []string
	}{
		{"disabled primary", true, false, "", []string{"reserve"}},
		{"disabled intermediate", false, true, "direct", []string{"primary", "direct"}},
		{"all disabled", true, true, "", []string{"block"}},
		{"explicit direct", true, true, "direct", []string{"direct"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &model.Config{
				Connections: []model.Connection{
					{ID: "primary", Type: model.ConnLink, Link: "socks5://203.0.113.1:1080", Disabled: tc.primaryOff, Fallback: "reserve"},
					{ID: "reserve", Type: model.ConnLink, Link: "socks5://203.0.113.2:1080", Disabled: tc.reserveOff, Fallback: tc.last},
				},
				Groups:   []model.Group{{Target: "primary", Entries: []string{"example.com"}}},
				Networks: []model.Network{{CIDR: "192.0.2.0/24", Mode: model.ModeFull, Target: "primary"}},
				Clients:  []model.Client{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.2", Mode: model.ModeFull, Target: "primary"}},
			}
			cfg.Defaults()
			out, err := Compile(Input{Config: cfg})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(out.Failover[0].Chain, tc.want) {
				t.Fatalf("chain = %v", out.Failover[0].Chain)
			}
			var parsed struct {
				Outbounds []struct {
					Tag, Default string
				}
				Route struct{ Rules []map[string]any }
			}
			if err := json.Unmarshal(out.SingBox, &parsed); err != nil {
				t.Fatal(err)
			}
			for _, o := range parsed.Outbounds {
				if o.Tag == "failover-primary" && o.Default != tc.want[0] {
					t.Fatalf("default = %s", o.Default)
				}
			}
			if !strings.Contains(string(out.SingBox), `"outbound": "failover-primary"`) {
				t.Fatal("reference disappeared")
			}
		})
	}
}

func TestActivationEntriesAndEmptyGeo(t *testing.T) {
	cfg := &model.Config{Groups: []model.Group{
		{Target: "direct", Entries: []string{"EXAMPLE.COM", "192.0.2.0/24", "active.example"}, DisabledEntries: []string{"*.example.com", "192.0.2.1/24"}},
		{Target: "block", Countries: []string{" ru "}, Categories: []string{" telegram "}, DisabledCountries: []string{"Ru"}, DisabledCategories: []string{"TELEGRAM"}, Except: true},
	}}
	cfg.Defaults()
	out, err := Compile(Input{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Countries) != 0 || len(out.Categories) != 0 {
		t.Fatalf("inactive geo compiled: %v %v", out.Countries, out.Categories)
	}
	if got := DomainNames(cfg); !slices.Equal(got, []string{"active.example"}) {
		t.Fatalf("domains = %v", got)
	}
	if strings.Contains(string(out.SingBox), `"outbound": "block"`) {
		t.Fatal("empty inverted geo rule still blocks traffic")
	}
	if strings.Contains(string(out.SingBox), `"192.0.2.0/24"`) {
		t.Fatal("disabled network prefix remains in routing")
	}
	sets := DNSRuleSets(cfg, map[string][]string{"example.com": {"198.51.100.1"}, "active.example": {"198.51.100.2"}})
	for _, raw := range sets {
		if strings.Contains(string(raw), "198.51.100.1") {
			t.Fatal("disabled domain leaked into DNS routing")
		}
	}
}

func TestDisabledProtocolPayloadIsNotCompiled(t *testing.T) {
	cfg := &model.Config{Connections: []model.Connection{
		{ID: "tt", Type: model.ConnTrustTunnel, Disabled: true},
		{ID: "wg", Type: model.ConnWireGuard, Disabled: true},
		{ID: "link", Type: model.ConnLink, Link: "invalid", Disabled: true},
	}}
	cfg.Defaults()
	out, err := Compile(Input{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.ServerHosts) != 0 {
		t.Fatal("disabled runtime dependency created")
	}
	var emitted struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal(out.SingBox, &emitted); err != nil {
		t.Fatal(err)
	}
	if len(emitted.Endpoints) != 0 {
		t.Fatalf("disabled endpoint was compiled: %+v", emitted.Endpoints)
	}
	for _, outbound := range emitted.Outbounds {
		if outbound["type"] == "trusttunnel" {
			t.Fatalf("disabled TrustTunnel outbound was compiled: %+v", outbound)
		}
	}
}
