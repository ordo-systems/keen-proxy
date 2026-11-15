package compile

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

const compileAWGProfile = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32, 2001:db8::2/128\nDNS = 9.9.9.9\nMTU = 1280\nJc = 3\nJmin = 50\nJmax = 100\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 100-110\nH2 = 200\nH3 = 300\nH4 = 400\nI1 = <b 0xAbCd><r 12>\nHeaderProtectionKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nContentPaddingAddition = 0-10\nRandomTrailers = true\nDisableCookies = true\nRekeyAfterTime = 100-120\nRekeyTimeout = 3-7\nRejectAfterTime = 150-180\nKeepaliveTimeout = 5-15\nMaxHandshakeAttempts = 15-20\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nPresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25-35\n"

func TestAmneziaWGCompilerPreservesConsumerValues(t *testing.T) {
	c := &model.Config{Connections: []model.Connection{{ID: "awg-stable", Type: model.ConnAmneziaWG, AmneziaWG: compileAWGProfile}}}
	out, err := connections(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.outbounds) != 0 || len(out.endpoints) != 1 {
		t.Fatalf("incorrect endpoint placement: %#v", out)
	}
	if out.hosts["awg-stable"] != "2001:db8::1" || len(out.servers) != 1 || out.servers[0] != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("missing bypass peer: %#v", out)
	}
	raw, err := json.Marshal(map[string]any{"endpoints": out.endpoints})
	if err != nil {
		t.Fatal(err)
	}
	options, err := sjson.UnmarshalExtendedContext[option.Options](engine.Context(context.Background()), raw)
	if err != nil {
		t.Fatalf("consumer rejected endpoint: %v", err)
	}
	if len(options.Endpoints) != 1 || options.Endpoints[0].Tag != "awg-stable" {
		t.Fatal("stable tag lost")
	}
	wg := options.Endpoints[0].Options.(*option.WireGuardEndpointOptions)
	if wg.Jc != 3 || wg.S4 != 12 || string(wg.H1) != "100-110" || wg.I1 != "<b 0xAbCd><r 12>" || string(wg.ContentPaddingAddition) != "0-10" || !wg.RandomTrailers || !wg.DisableCookies || wg.HeaderProtectionKey == "" || string(wg.RekeyAfterTime) != "100-120" || string(wg.RekeyTimeout) != "3-7" || string(wg.RejectAfterTime) != "150-180" || string(wg.KeepaliveTimeout) != "5-15" || string(wg.MaxHandshakeAttempts) != "15-20" {
		t.Fatalf("consumer lost AWG values: %#v", wg)
	}
	if wg.MTU != 1280 || len(wg.Address) != 2 || len(wg.Peers) != 1 || wg.Peers[0].PreSharedKey == "" || len(wg.Peers[0].AllowedIPs) != 2 || string(wg.Peers[0].PersistentKeepaliveInterval) != "25-35" {
		t.Fatalf("consumer lost WG values: %#v", wg)
	}
	if strings.Contains(string(raw), "9.9.9.9") || strings.Contains(string(raw), "[Interface]") {
		t.Fatal("profile metadata/text leaked into endpoint")
	}
	if c.Connections[0].AmneziaWG != compileAWGProfile {
		t.Fatal("compiler mutated profile")
	}
}

func TestAmneziaWGCompilerRejectsInvalidProfile(t *testing.T) {
	for _, profile := range []string{"", strings.Replace(compileAWGProfile, "Jc = 3", "Jc = -1", 1), compileAWGProfile + "[Peer]\n", strings.Replace(compileAWGProfile, "MTU = 1280", "PostUp = PRIVATE-hook", 1)} {
		_, err := connections(&model.Config{Connections: []model.Connection{{ID: "bad-awg", Type: model.ConnAmneziaWG, AmneziaWG: profile}}})
		if err == nil || !strings.Contains(err.Error(), `connection "bad-awg"`) {
			t.Fatalf("invalid connection error: %v", err)
		}
		if strings.Contains(err.Error(), "PRIVATE-hook") {
			t.Fatal("error leaked profile")
		}
	}
}

func TestAmneziaWGCompilerCollectsHostnameAndIPv4(t *testing.T) {
	for _, host := range []string{"vpn.example", "203.0.113.9"} {
		profile := strings.Replace(compileAWGProfile, "[2001:db8::1]", host, 1)
		out, err := connections(&model.Config{Connections: []model.Connection{{ID: "awg", Type: model.ConnAmneziaWG, AmneziaWG: profile}}})
		if err != nil {
			t.Fatal(err)
		}
		if out.hosts["awg"] != host {
			t.Fatal("hostname not collected")
		}
		if host == "203.0.113.9" && (len(out.servers) != 1 || out.servers[0].String() != host) {
			t.Fatal("IPv4 bypass not collected")
		}
	}
}
