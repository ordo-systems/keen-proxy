package model

import (
	"encoding/json"
	"strings"
	"testing"
)

const awgProfile = "# retain this comment\n[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\nJc = 4\nI1 = <b 0xAbCd><r 12>\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = vpn.example:51820\nPersistentKeepalive = 25-35\n"

func TestAmneziaWGRoundtrip(t *testing.T) {
	c, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	c.Connections[0] = Connection{ID: "fi", Type: ConnAmneziaWG, AmneziaWG: awgProfile}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Connections[0].AmneziaWG != awgProfile || restored.Clone().Connections[0].AmneziaWG != awgProfile {
		t.Fatal("YAML or clone changed the profile")
	}
	body, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Config
	if err := json.Unmarshal(body, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if fromJSON.Connections[0].AmneziaWG != awgProfile {
		t.Fatal("JSON changed the profile")
	}
	if err := fromJSON.Validate(); err != nil {
		t.Fatal(err)
	}
	if restored.DNS.Upstreams[0] != "https://1.1.1.1/dns-query" {
		t.Fatal("profile DNS replaced policy")
	}
}

func TestAmneziaWGValidation(t *testing.T) {
	for name, connection := range map[string]Connection{
		"missing":                       {ID: "fi", Type: ConnAmneziaWG},
		"invalid":                       {ID: "fi", Type: ConnAmneziaWG, AmneziaWG: strings.Replace(awgProfile, "Jc = 4", "Jc = -1", 1)},
		"mixed link":                    {ID: "fi", Type: ConnAmneziaWG, AmneziaWG: awgProfile, Link: "socks5://example.com:1080"},
		"mixed wireguard":               {ID: "fi", Type: ConnAmneziaWG, AmneziaWG: awgProfile, WireGuard: &WireGuard{}},
		"mixed other type":              {ID: "fi", Type: ConnLink, AmneziaWG: awgProfile, Link: "socks5://example.com:1080"},
		"wireguard with profile only":   {ID: "fi", Type: ConnWireGuard, AmneziaWG: awgProfile},
		"amneziawg with wireguard only": {ID: "fi", Type: ConnAmneziaWG, WireGuard: &WireGuard{}},
		"singbox with profile only":     {ID: "fi", Type: ConnSingBox, AmneziaWG: awgProfile},
		"link with profile only":        {ID: "fi", Type: ConnLink, AmneziaWG: awgProfile},
		"trusttunnel with profile only": {ID: "fi", Type: ConnTrustTunnel, AmneziaWG: awgProfile},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := Parse([]byte(validYAML))
			if err != nil {
				t.Fatal(err)
			}
			c.Connections[0] = connection
			if err := c.Validate(); err == nil {
				t.Fatal("invalid connection accepted")
			}
			raw, err := c.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(raw); err == nil {
				t.Fatal("persisted invalid connection accepted")
			}
		})
	}
}
