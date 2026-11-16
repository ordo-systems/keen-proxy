package trusttunnel

import (
	"encoding/pem"
	"strings"
	"testing"
)

func endpointLink(fields map[byte][]byte, repeated map[byte][][]byte) string {
	var e encoder
	for tag, val := range fields {
		e.field(uint64(tag), val)
	}
	for tag, values := range repeated {
		for _, val := range values {
			e.field(uint64(tag), val)
		}
	}
	return e.link()
}

func mustOutbound(t *testing.T, link string) map[string]any {
	t.Helper()
	out, err := ParseOutbound(link)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func tlsOf(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	tlsOpts, ok := out["tls"].(map[string]any)
	if !ok {
		t.Fatalf("tls = %#v", out["tls"])
	}
	return tlsOpts
}

func TestParseOutboundPreservesVerificationSNIAndEndpointIP(t *testing.T) {
	cert := selfSigned(t)
	link := endpointLink(map[byte][]byte{
		0x01: []byte("vpn.example.com"),
		0x03: []byte("vpn.example.com"),
		0x05: []byte("premium"),
		0x06: []byte("s3cret"),
		0x08: cert,
	}, map[byte][][]byte{0x02: {[]byte("203.0.113.50:443"), []byte("[2001:db8::1]:443")}})

	out := mustOutbound(t, link)
	if out["type"] != "trusttunnel" || out["server"] != "203.0.113.50" || out["server_port"] != 443 {
		t.Fatalf("dial target = %#v", out)
	}
	if _, ok := out["quic"]; ok {
		t.Fatalf("HTTP/2 link set quic: %#v", out["quic"])
	}
	tlsOpts := tlsOf(t, out)
	if tlsOpts["enabled"] != true || tlsOpts["server_name"] != "vpn.example.com" {
		t.Fatalf("SNI = %#v", tlsOpts)
	}
	if _, skipped := tlsOpts["insecure"]; skipped {
		t.Fatal("verification was disabled without skip_verification")
	}
	pemText, _ := tlsOpts["certificate"].(string)
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || len(block.Bytes) != len(cert) {
		t.Fatalf("supplied certificate was not preserved: %q", pemText)
	}
	utls, _ := tlsOpts["utls"].(map[string]any)
	if utls["enabled"] != true || utls["fingerprint"] != "chrome" {
		t.Fatalf("HTTP/2 fingerprint = %#v", utls)
	}
}

func TestParseOutboundMapsAntiDPIAndExplicitSkip(t *testing.T) {
	link := endpointLink(map[byte][]byte{
		0x01: []byte("vpn.example.com"),
		0x02: []byte("vpn.example.com:8443"),
		0x03: []byte("front.example"),
		0x05: []byte("user"),
		0x06: []byte("pass"),
		0x07: []byte{1},
		0x0A: []byte{1},
	}, nil)
	out := mustOutbound(t, link)
	if out["server"] != "vpn.example.com" || out["server_port"] != 8443 {
		t.Fatalf("hostname address = %#v", out)
	}
	tlsOpts := tlsOf(t, out)
	if tlsOpts["insecure"] != true {
		t.Fatal("skip_verification was not preserved")
	}
	if tlsOpts["fragment"] != true {
		t.Fatal("anti_dpi was not mapped to tls.fragment")
	}
	if tlsOpts["server_name"] != "front.example" {
		t.Fatalf("server name = %#v", tlsOpts["server_name"])
	}
}

func TestParseOutboundHTTP3(t *testing.T) {
	link := endpointLink(map[byte][]byte{
		0x01: []byte("vpn.example.com"),
		0x02: []byte("203.0.113.8:443"),
		0x05: []byte("user"),
		0x06: []byte("pass"),
		0x09: []byte{2},
	}, nil)
	out, err := ParseOutbound(link)
	if quicAllowed() {
		if err != nil {
			t.Fatal(err)
		}
		if out["quic"] != true {
			t.Fatalf("quic = %#v", out["quic"])
		}
		if _, ok := tlsOf(t, out)["utls"]; ok {
			t.Fatal("HTTP/3 outbound enabled uTLS")
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "HTTP/3") {
		t.Fatalf("lite error = %v", err)
	}
}

func TestParseOutboundRejectsUnrepresentableOptions(t *testing.T) {
	base := map[byte][]byte{
		0x01: []byte("vpn.example.com"),
		0x02: []byte("203.0.113.8:443"),
		0x05: []byte("user"),
		0x06: []byte("pass"),
	}
	cases := []struct {
		name string
		add  map[byte][]byte
		want string
	}{
		{name: "client random", add: map[byte][]byte{0x0B: []byte("aa")}, want: "client_random_prefix"},
		{name: "auth key", add: map[byte][]byte{0x0F: []byte("bb")}, want: "client_random_auth_key"},
		{name: "subscription", add: map[byte][]byte{0x0E: []byte("https://sub.example/cfg")}, want: "subscription"},
		{name: "unknown protocol", add: map[byte][]byte{0x09: []byte{3}}, want: "protocol 3"},
		{name: "anti-dpi http3", add: map[byte][]byte{0x09: []byte{2}, 0x0A: []byte{1}}, want: "anti_dpi"},
		{name: "custom SNI identity", add: map[byte][]byte{0x03: []byte("front.example")}, want: "verification"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[byte][]byte{}
			for tag, val := range base {
				fields[tag] = val
			}
			for tag, val := range tc.add {
				fields[tag] = val
			}
			if tc.name == "anti-dpi http3" && !quicAllowed() {
				tc.want = "HTTP/3"
			}
			_, err := ParseOutbound(endpointLink(fields, nil))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseOutboundRejectsAmbiguousAddresses(t *testing.T) {
	fields := map[byte][]byte{0x01: []byte("vpn.example.com"), 0x05: []byte("user"), 0x06: []byte("pass")}
	_, err := ParseOutbound(endpointLink(fields, map[byte][][]byte{0x02: {[]byte("203.0.113.1:443"), []byte("203.0.113.2:8443")}}))
	if err == nil || !strings.Contains(err.Error(), "ports") {
		t.Fatalf("ports: %v", err)
	}
	_, err = ParseOutbound(endpointLink(fields, map[byte][][]byte{0x02: {[]byte("a.example:443"), []byte("b.example:443")}}))
	if err == nil || !strings.Contains(err.Error(), "hostnames") {
		t.Fatalf("hostnames: %v", err)
	}
}

func TestParseOutboundRejectsUnparseableCertificate(t *testing.T) {
	link := endpointLink(map[byte][]byte{
		0x01: []byte("vpn.example.com"),
		0x02: []byte("203.0.113.8:443"),
		0x05: []byte("user"),
		0x06: []byte("pass"),
		0x08: []byte{0x30, 0x03, 0x01, 0x01, 0xff},
	}, nil)
	_, err := ParseOutbound(link)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseOutboundKeepsVerificationWhenIPv6IsDisabled(t *testing.T) {
	link := endpointLink(map[byte][]byte{
		0x01: []byte("vpn.example.com"),
		0x02: []byte("203.0.113.9:443"),
		0x04: []byte{0},
		0x05: []byte("user"),
		0x06: []byte("pass"),
		0x0C: []byte("name"),
		0x0D: []byte{0x01, 'a'},
	}, nil)
	out := mustOutbound(t, link)
	tlsOpts := tlsOf(t, out)
	if _, skipped := tlsOpts["insecure"]; skipped {
		t.Fatal("has_ipv6 false disabled certificate verification")
	}
	if _, ok := out["domain_resolver"]; ok {
		t.Fatal("has_ipv6 false invented a domain_resolver the core config does not have")
	}
	if out["server"] != "203.0.113.9" {
		t.Fatalf("server = %#v", out["server"])
	}
}
