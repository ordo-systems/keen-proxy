package resourceexchange

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
)

func TestSingBoxExportPreservesUnion(t *testing.T) {
	// The exact apex and leading-dot suffix can be in different rules. The
	// nested exact/suffix are already covered and must not widen the union.
	const source = `{"version":5,"rules":[{"domain":["example.com","ru"]},{"domain_suffix":[".example.com",".nested.example.com",".ru"],"ip_cidr":["192.0.2.0/25","192.0.2.128/25","2001:db8::/32"]},{"type":"default","domain":["child.example.com"]}]}`
	preview := Decode(SingBox, []byte(source))
	if !preview.Valid {
		t.Fatalf("source rejected: %+v", preview.Issues)
	}
	var original option.PlainRuleSetCompat
	if err := json.Unmarshal([]byte(source), &original); err != nil {
		t.Fatal(err)
	}
	wantRules := compileSingBoxTestRules(t, original.Options.Rules)
	for _, format := range []Format{SingBox, SRS} {
		t.Run(string(format), func(t *testing.T) {
			encoded, _, err := Encode(format, preview.List)
			if err != nil {
				t.Fatal(err)
			}
			decoded := Decode(format, encoded)
			if !decoded.Valid {
				t.Fatalf("export cannot be imported: %+v", decoded.Issues)
			}
			var exported option.PlainRuleSetCompat
			if format == SRS {
				exported, err = srs.Read(bytes.NewReader(encoded), false)
			} else {
				err = json.Unmarshal(encoded, &exported)
			}
			if err != nil || exported.Version != 2 {
				t.Fatalf("expected portable v2 output: version %d, error %v", exported.Version, err)
			}
			gotRules := compileSingBoxTestRules(t, exported.Options.Rules)
			for _, probe := range []struct {
				domain, ip string
				want       bool
			}{
				{"example.com", "", true},
				{"nested.example.com", "", true},
				{"a.b.example.com", "198.51.100.10", true},
				{"notexample.com", "", false},
				{"example.com.invalid", "", false},
				{"ru", "", true},
				{"example.ru", "", true},
				{"a.example.ru", "", true},
				{"example.ru.com", "", false},
				{"guru", "", false},
				{"unrelated.test", "192.0.2.200", true},
				{"", "192.0.2.10", true},
				{"", "2001:db8::42", true},
				{"unrelated.test", "2001:db9::", false},
			} {
				if original := matchSingBoxTestRules(wantRules, probe.domain, probe.ip); original != probe.want {
					t.Fatalf("fixture predicate mismatch for %s/%s: got %t, want %t", probe.domain, probe.ip, original, probe.want)
				}
				if got := matchSingBoxTestRules(gotRules, probe.domain, probe.ip); got != probe.want {
					t.Errorf("export mismatch for %s/%s: got %t, want %t", probe.domain, probe.ip, got, probe.want)
				}
			}
		})
	}
}

func compileSingBoxTestRules(t *testing.T, options []option.HeadlessRule) []adapter.HeadlessRule {
	t.Helper()
	rules := make([]adapter.HeadlessRule, 0, len(options))
	for _, opt := range options {
		r, err := rule.NewHeadlessRule(context.Background(), opt)
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, r)
	}
	return rules
}

func matchSingBoxTestRules(rules []adapter.HeadlessRule, domain, ip string) bool {
	var addr netip.Addr
	if ip != "" {
		addr = netip.MustParseAddr(ip)
	}
	for _, r := range rules {
		if r.Match(&adapter.InboundContext{Domain: domain, Destination: M.Socksaddr{Addr: addr}}) {
			return true
		}
	}
	return false
}

func TestSingBoxRejectsUnrepresentableOrMalformedSource(t *testing.T) {
	for _, tc := range []struct {
		name, input, location string
	}{
		{"exact only", `{"version":1,"rules":[{"domain":"example.com"}]}`, "rules[0].domain[0]"},
		{"leading dot only", `{"version":1,"rules":[{"domain_suffix":".example.com"}]}`, "rules[0].domain_suffix[0]"},
		{"leading dot TLD only", `{"version":2,"rules":[{"domain_suffix":".ru"}]}`, "rules[0].domain_suffix[0]"},
		{"exact TLD only", `{"version":2,"rules":[{"domain":"ru"}]}`, "rules[0].domain[0]"},
		{"leading dot with unrelated apex", `{"version":2,"rules":[{"domain_suffix":".example.com"},{"domain_suffix":"notexample.com"}]}`, "rules[0].domain_suffix[0]"},
		{"normalization changes meaning", `{"version":2,"rules":[{"domain_suffix":"EXAMPLE.COM"}]}`, "rules[0].domain_suffix[0]"},
		{"trailing dot normalization", `{"version":2,"rules":[{"domain_suffix":"example.com."}]}`, "rules[0].domain_suffix[0]"},
		{"prefix rather than suffix", `{"version":2,"rules":[{"domain_suffix":"*.example.com"}]}`, "rules[0].domain_suffix[0]"},
		{"IP as domain suffix", `{"version":2,"rules":[{"domain_suffix":"192.0.2.1"}]}`, "rules[0].domain_suffix[0]"},
		{"IP as leading-dot suffix", `{"version":2,"rules":[{"domain_suffix":".192.0.2.1"},{"domain":"192.0.2.1"}]}`, "rules[0].domain_suffix[0]"},
		{"not a raw IP", `{"version":2,"rules":[{"ip_cidr":"192.0.2.1 # comment"}]}`, "rules[0].ip_cidr[0]"},
		{"logical", `{"version":2,"rules":[{"type":"logical","mode":"or","rules":[]}]}`, "rules[0].type"},
		{"invert", `{"version":2,"rules":[{"invert":true,"domain_suffix":"example.com"}]}`, "rules[0].invert"},
		{"other predicate", `{"version":2,"rules":[{"domain_suffix":"example.com","network":"tcp"}]}`, "rules[0].network"},
		{"unknown wrapper field", `{"version":2,"rules":[],"name":"x"}`, "name"},
		{"duplicate rule predicate", `{"version":2,"rules":[{"domain":"example.com","domain":"other.test"}]}`, "rules[0].domain"},
		{"duplicate version", `{"version":2,"rules":[],"version":2}`, "version"},
		{"null rule", `{"version":2,"rules":[null]}`, "rules[0]"},
		{"null predicate item", `{"version":2,"rules":[{"domain_suffix":[null]}]}`, "rules[0].domain_suffix[0]"},
		{"empty rule", `{"version":2,"rules":[{"domain_suffix":[]}]}`, "rules[0]"},
		{"version bounds", `{"version":6,"rules":[]}`, "version"},
		{"missing version", `{"rules":[]}`, "version"},
		{"trailing document", `{"version":2,"rules":[]} {}`, "file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Decode(SingBox, []byte(tc.input))
			if got.Valid || len(got.Issues) == 0 || got.Issues[0].Location != tc.location {
				t.Fatalf("expected rejection at %s, got %+v", tc.location, got)
			}
		})
	}
}

func TestSingBoxPredicateValueLimit(t *testing.T) {
	// Repeating the same raw predicate must not bypass the parser's limit.
	input := `{"version":2,"rules":[{"domain_suffix":[` +
		strings.Repeat(`"example.com",`, MaxEntries) + `"example.com"]}]}`
	got := Decode(SingBox, []byte(input))
	if got.Valid || len(got.Issues) != 1 || got.Issues[0].Location != "rules[0].domain_suffix[20000]" {
		t.Fatalf("expected predicate limit issue, got %+v", got)
	}
}
