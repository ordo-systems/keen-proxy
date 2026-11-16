package model

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLegacyTrustTunnelBecomesLink(t *testing.T) {
	raw := []byte(`
connections:
  - id: tt
    name: Finland
    type: trusttunnel
    trusttunnel:
      link: "  tt://?exported  "
      binary: /opt/bin/trusttunnel_client
      socks_port: 17100
`)
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Defaults()
	cn := cfg.Connections[0]
	if cn.Type != ConnLink || cn.Link != "tt://?exported" || cn.TrustTunnel != nil {
		t.Fatalf("normalized = %+v", cn)
	}
	saved, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	text := string(saved)
	for _, gone := range []string{"trusttunnel:", "binary:", "socks_port:", "trusttunnel_client"} {
		if strings.Contains(text, gone) {
			t.Fatalf("saved configuration kept %s:\n%s", gone, text)
		}
	}
	if !strings.Contains(text, "type: link") || !strings.Contains(text, "tt://?exported") {
		t.Fatalf("saved configuration lost the link:\n%s", text)
	}
}

func TestLegacyTrustTunnelJSONLoadDropsProcessFields(t *testing.T) {
	var cfg Config
	body := []byte(`{"connections":[{"id":"tt","type":"trusttunnel","trusttunnel":{"link":"tt://?from-api","binary":"/opt/bin/trusttunnel_client","socks_port":17101}}]}`)
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Defaults()
	cn := cfg.Connections[0]
	if cn.Type != ConnLink || cn.Link != "tt://?from-api" || cn.TrustTunnel != nil {
		t.Fatalf("JSON load = %+v", cn)
	}
}

func TestMixedTrustTunnelPayloadIsNotDropped(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "conflicting links",
			yaml: "connections:\n  - {id: tt, type: trusttunnel, link: 'tt://?one', trusttunnel: {link: 'tt://?two', binary: /opt/bin/trusttunnel_client}}\n",
			want: "conflicts",
		},
		{
			name: "legacy plus wireguard",
			yaml: "connections:\n  - {id: tt, type: trusttunnel, wireguard: {private_key: k, address: [10.0.0.2/32], peer: {endpoint: '192.0.2.1:51820', public_key: p}}, trusttunnel: {link: 'tt://?one'}}\n",
			want: "refusing to drop",
		},
		{
			name: "link type with a different trusttunnel link",
			yaml: "connections:\n  - {id: tt, type: link, link: 'tt://?one', trusttunnel: {link: 'tt://?two'}}\n",
			want: "conflicts",
		},
		{
			name: "empty link beside trusttunnel link",
			yaml: "connections:\n  - {id: tt, type: link, trusttunnel: {link: 'tt://?one'}}\n",
			want: "refusing to choose",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
