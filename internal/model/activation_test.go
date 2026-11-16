package model

import (
	"slices"
	"testing"
)

func TestActivationSurvivesRestoreAndParentToggle(t *testing.T) {
	cfg := &Config{Groups: []Group{{Name: "rules", Target: TargetDirect, Disabled: true, Entries: []string{"Example.COM", "192.0.2.0/24"}, DisabledEntries: []string{"*.example.com"}}}}
	cfg.Defaults()
	raw, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	g := &restored.Groups[0]
	if got := slices.Collect(g.ActiveEntries()); len(got) != 0 {
		t.Fatalf("parent off entries = %v", got)
	}
	g.Disabled = false
	if got := slices.Collect(g.ActiveEntries()); !slices.Equal(got, []string{"192.0.2.0/24"}) {
		t.Fatalf("restored child state = %v", got)
	}
	if !slices.Equal(g.Entries, cfg.Groups[0].Entries) || !slices.Equal(g.DisabledEntries, cfg.Groups[0].DisabledEntries) {
		t.Fatal("activation rewrote source values")
	}
}

func TestDisabledDNSReferenceRemainsValidAndStrict(t *testing.T) {
	cfg := &Config{Connections: []Connection{{ID: "vpn", Type: ConnLink, Link: "socks5://203.0.113.1:1080", Disabled: true}}}
	cfg.Defaults()
	cfg.DNS = DNS{Route: "connection", Connection: "vpn", Failure: "strict", Listen: "127.0.0.1:5354", Upstreams: []string{"https://1.1.1.1/dns-query"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.ActiveChain("vpn"); !slices.Equal(got, []string{TargetBlock}) {
		t.Fatalf("chain = %v", got)
	}
	cfg.Connections[0].Fallback = TargetDirect
	if err := cfg.Validate(); err == nil {
		t.Fatal("strict DNS acquired a direct fallback")
	}
}
