package model

import (
	"strings"
	"testing"
)

func TestSchemaAndDNSPolicy(t *testing.T) {
	for _, raw := range []string{"schema_version: 9", "{}\n---\n{}", "redacted: true"} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	c, err := Parse([]byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if c.SchemaVersion != 1 {
		t.Fatal(c.SchemaVersion)
	}
	c.DNS.Route = "connection"
	c.DNS.Connection = "missing"
	c.DNS.Failure = "strict"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "dns") {
		t.Fatal(err)
	}
	c.DNS.Route = "direct"
	c.DNS.Connection = ""
	c.DNS.Upstreams = []string{"https://dns.google/dns-query"}
	if err := c.Validate(); err == nil {
		t.Fatal("bootstrap missing accepted")
	}
	c.DNS.Bootstrap = map[string]string{"dns.google": "8.8.8.8"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRejectsHiddenDirect(t *testing.T) {
	c := &Config{Connections: []Connection{{ID: "hidden", Type: ConnSingBox, Outbound: map[string]any{"type": "direct"}}}}
	c.Defaults()
	c.DNS.Route = "connection"
	c.DNS.Connection = "hidden"
	c.DNS.Failure = "strict"
	c.DNS.Upstreams = []string{"https://1.1.1.1/dns-query"}
	if err := c.Validate(); err == nil {
		t.Fatal("direct under arbitrary id accepted")
	}
	c.Connections[0].Outbound = map[string]any{"type": "selector", "outbounds": []string{"direct"}}
	if err := c.Validate(); err == nil {
		t.Fatal("selector with hidden direct accepted")
	}
}

func TestDNSBypassSourcesValidation(t *testing.T) {
	c, err := Parse([]byte("dns: {bypass_sources: [192.168.31.53, 169.254.7.12, 203.0.113.31]}"))
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		"", " 192.168.31.53 ", "192.168.031.53", "192.168.31.0/24", "192.168.31.53/32",
		"192.168.31.53:53", "resolver.example", "2001:db8::53", "::ffff:192.168.31.53",
		"0.0.0.0", "127.0.0.1", "224.0.0.53", "255.255.255.255",
	} {
		t.Run(invalid, func(t *testing.T) {
			c.DNS.BypassSources = []string{"192.168.31.53", invalid}
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "dns.bypass_sources[1]: expected a unicast IPv4 address") {
				t.Fatalf("Validate() = %v", err)
			}
		})
	}
}
