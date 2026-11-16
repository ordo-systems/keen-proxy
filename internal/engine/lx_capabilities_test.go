package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/links"
)

func TestValidateParsedXHTTPAndEncryption(t *testing.T) {
	o, err := links.Parse("vless://11111111-2222-3333-4444-555555555555@203.0.113.1:443?type=xhttp&security=tls&sni=www.example.com&fp=chrome&encryption=" +
		"mlkem768x25519plus.native.0rtt.aMVnCpOnew7ZP35GkyCEsK90FCNRjSyacboJFaSlMBM" +
		"&mode=packet-up&path=/xhttp%3Fed%3D2048&host=www.example.com&xPaddingBytes=100-1000")
	if err != nil {
		t.Fatal(err)
	}
	if o["encryption"] != "mlkem768x25519plus.native.0rtt.aMVnCpOnew7ZP35GkyCEsK90FCNRjSyacboJFaSlMBM" {
		t.Fatalf("parsed encryption = %#v", o["encryption"])
	}
	if err := Validate(context.Background(), outboundConfig(t, o)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsUnsupportedVLESSEncryption(t *testing.T) {
	raw := []byte(`{"log":{"disabled":true},"outbounds":[{"type":"vless","tag":"v","server":"203.0.113.1","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","encryption":"mlkem768x25519plus.nope.0rtt.aMVnCpOnew7ZP35GkyCEsK90FCNRjSyacboJFaSlMBM"}]}`)
	err := Validate(context.Background(), raw)
	if err == nil || !strings.Contains(err.Error(), "encryption") {
		t.Fatalf("unsupported VLESS encryption: %v", err)
	}
}

func TestValidateRejectsUnknownXHTTPMode(t *testing.T) {
	raw := []byte(`{"log":{"disabled":true},"outbounds":[{"type":"vless","tag":"v","server":"203.0.113.1","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","transport":{"type":"xhttp","mode":"nope"}}]}`)
	err := Validate(context.Background(), raw)
	if err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("unknown xhttp mode: %v", err)
	}
}

func TestValidateREALITYKeyShare(t *testing.T) {
	valid := []byte(`{"log":{"disabled":true},"outbounds":[{"type":"vless","tag":"v","server":"203.0.113.1","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"aMVnCpOnew7ZP35GkyCEsK90FCNRjSyacboJFaSlMBM","short_id":"ab","key_share":"hybrid"},"fragment":true,"record_fragment":false}}]}`)
	if err := Validate(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	invalid := []byte(`{"log":{"disabled":true},"outbounds":[{"type":"vless","tag":"v","server":"203.0.113.1","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"aMVnCpOnew7ZP35GkyCEsK90FCNRjSyacboJFaSlMBM","short_id":"ab","key_share":"classic"}}}]}`)
	err := Validate(context.Background(), invalid)
	if err == nil || !strings.Contains(err.Error(), "key_share") {
		t.Fatalf("classic key_share: %v", err)
	}
}

func TestValidateTrustTunnelHTTP3FailsClosedWithoutQUIC(t *testing.T) {
	h2 := []byte(`{"log":{"disabled":true},"outbounds":[{"type":"trusttunnel","tag":"tt","server":"203.0.113.1","server_port":443,"username":"user","password":"secret","tls":{"enabled":true,"server_name":"vpn.example.com"}}]}`)
	if err := Validate(context.Background(), h2); err != nil {
		t.Fatal(err)
	}
	h3 := []byte(`{"log":{"disabled":true},"outbounds":[{"type":"trusttunnel","tag":"tt","server":"203.0.113.1","server_port":443,"username":"user","password":"secret","quic":true,"tls":{"enabled":true,"server_name":"vpn.example.com"}}]}`)
	err := Validate(context.Background(), h3)
	if quicIncluded {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "with_quic") || !strings.Contains(err.Error(), "HTTP/3") {
		t.Fatalf("lite accepted or hid QUIC trusttunnel: %v", err)
	}
}

func TestValidateXHTTPOverHTTP3FailsClosedWithoutQUIC(t *testing.T) {
	raw := []byte(`{"log":{"disabled":true},"outbounds":[{"type":"vless","tag":"v","server":"203.0.113.1","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","tls":{"enabled":true,"server_name":"www.example.com","alpn":["h3"]},"transport":{"type":"xhttp","mode":"packet-up"}}]}`)
	err := Validate(context.Background(), raw)
	if quicIncluded {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "with_quic") {
		t.Fatalf("lite accepted or hid XHTTP HTTP/3: %v", err)
	}
}

func outboundConfig(t *testing.T, outbound map[string]any) []byte {
	t.Helper()
	outbound["tag"] = "node"
	raw, err := json.Marshal(map[string]any{
		"log":       map[string]any{"disabled": true},
		"outbounds": []any{outbound},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
