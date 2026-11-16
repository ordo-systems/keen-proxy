package links

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// get looks up a dotted path such as "tls.reality.public_key".
func get(o map[string]any, path string) any {
	var cur any = o
	for _, k := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

func TestParse(t *testing.T) {
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"vm","add":"vm.example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"ws","host":"cdn.example.com","path":"/ws","tls":"tls"}`))
	cases := []struct {
		link string
		want map[string]any
	}{
		{
			"vless://11111111-2222-3333-4444-555555555555@203.0.113.1:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=ab12&type=tcp#FI%20Reality",
			map[string]any{"type": "vless", "server": "203.0.113.1", "server_port": 443, "flow": "xtls-rprx-vision",
				"tls.server_name": "www.microsoft.com", "tls.reality.public_key": "PUBKEY", "tls.reality.short_id": "ab12", "tls.utls.fingerprint": "chrome"},
		},
		{
			"vless://uuid@host.example:8443?security=tls&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example",
			map[string]any{"transport.type": "ws", "transport.path": "/ws", "transport.max_early_data": 2048, "transport.headers.Host": "cdn.example", "tls.server_name": "host.example"},
		},
		{
			"vless://uuid@h.example:443?security=tls&type=grpc&serviceName=svc",
			map[string]any{"transport.type": "grpc", "transport.service_name": "svc"},
		},
		{vmess, map[string]any{"type": "vmess", "server": "vm.example.com", "transport.type": "ws", "transport.path": "/ws", "tls.server_name": "cdn.example.com", "security": "auto"}},
		{"trojan://secret@tr.example:443?type=tcp#t", map[string]any{"type": "trojan", "password": "secret", "tls.enabled": true, "tls.server_name": "tr.example"}},
		{"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@ss.example:8388#x", map[string]any{"type": "shadowsocks", "method": "aes-256-gcm", "password": "pw", "server_port": 8388}},
		{"ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@1.2.3.4:443")), map[string]any{"method": "chacha20-ietf-poly1305", "server": "1.2.3.4"}},
		{"ss://2022-blake3-aes-128-gcm:a2V5%3D@ss.example:443", map[string]any{"method": "2022-blake3-aes-128-gcm", "password": "a2V5="}},
		{"hysteria2://auth@hy.example:443?sni=hy.example&obfs=salamander&obfs-password=xyz&insecure=1",
			map[string]any{"type": "hysteria2", "password": "auth", "obfs.type": "salamander", "obfs.password": "xyz", "tls.insecure": true, "server_port": 443}},
		{"hy2://pw@hy.example:20000-30000/", map[string]any{"server_ports": []string{"20000:30000"}}},
		{"tuic://uuid:pw@tu.example:443?congestion_control=bbr&alpn=h3&sni=tu.example", map[string]any{"type": "tuic", "uuid": "uuid", "password": "pw", "congestion_control": "bbr"}},
		{"anytls://pw@any.example:443?sni=any.example", map[string]any{"type": "anytls", "password": "pw", "tls.server_name": "any.example"}},
		{"socks5://u:p@10.0.0.1:1080", map[string]any{"type": "socks", "username": "u", "password": "p", "version": "5"}},
	}
	for _, c := range cases {
		o, err := Parse(c.link)
		if err != nil {
			t.Errorf("%s: %v", c.link, err)
			continue
		}
		for path, want := range c.want {
			got := get(o, path)
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(want)
			if string(gj) != string(wj) {
				t.Errorf("%s\n  %s = %s, expected %s", c.link, path, gj, wj)
			}
		}
	}
}

func TestParseErrors(t *testing.T) {
	for link, want := range map[string]string{
		"vless://u@h:443?type=kcp":         "not supported",
		"vless://u@h:443?security=reality": "pbk",
		"wireguard://x":                    "not supported",
		"ss://YWVzOnB3@h:1?plugin=obfs":    "plugins",
		"vless://@h:443":                   "UUID",
		"nonsense":                         "scheme",
	} {
		_, err := Parse(link)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, expected to contain %q", link, err, want)
		}
	}
}

func TestName(t *testing.T) {
	if n := Name("vless://u@h:1#%D0%A4%D0%B8%D0%BD%D0%BB%D1%8F%D0%BD%D0%B4%D0%B8%D1%8F"); n != "\u0424\u0438\u043d\u043b\u044f\u043d\u0434\u0438\u044f" {
		t.Errorf("Name = %q", n)
	}
}

const supportedVLESSEncryption = "mlkem768x25519plus.native.0rtt.aMVnCpOnew7ZP35GkyCEsK90FCNRjSyacboJFaSlMBM"

func TestVLESSEncryptionNoneIsNotALayer(t *testing.T) {
	o, err := Parse("vless://11111111-2222-3333-4444-555555555555@203.0.113.1:443?encryption=NONE&security=tls")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := o["encryption"]; ok {
		t.Fatalf("encryption=none stored a layer: %#v", o["encryption"])
	}
}

func TestVLESSEncryptionPreserved(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@203.0.113.1:443?encryption=" + supportedVLESSEncryption
	o, err := Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if o["encryption"] != supportedVLESSEncryption {
		t.Fatalf("encryption = %#v", o["encryption"])
	}
}

func TestVLESSVisionTransportCompatibility(t *testing.T) {
	for _, transport := range []string{"xhttp", "splithttp", "XHTTP", "tcp"} {
		for _, encryption := range []string{"", "none", "NONE", " none ", " \t", supportedVLESSEncryption} {
			for _, flow := range []string{"", "xtls-rprx-vision"} {
				t.Run(transport+"/"+url.QueryEscape(encryption)+"/"+flow, func(t *testing.T) {
					q := url.Values{"type": {transport}, "security": {"tls"}, "flow": {flow}, "encryption": {encryption}}
					o, err := Parse("vless://11111111-2222-3333-4444-555555555555@203.0.113.1:443?" + q.Encode())
					encrypted := encryption == supportedVLESSEncryption
					if transport != "tcp" && flow != "" && !encrypted {
						if err == nil || !strings.Contains(err.Error(), "requires VLESS encryption") {
							t.Fatalf("incompatible XHTTP/Vision profile: error = %v", err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if flow != "" && o["flow"] != flow {
						t.Fatalf("Vision flow was lost: %#v", o["flow"])
					}
					if encrypted && o["encryption"] != supportedVLESSEncryption {
						t.Fatalf("VLESS encryption was lost: %#v", o["encryption"])
					}
					if !encrypted && o["encryption"] != nil {
						t.Fatalf("disabled encryption became a layer: %#v", o["encryption"])
					}
					if transport != "tcp" && get(o, "transport.type") != "xhttp" {
						t.Fatalf("XHTTP transport was lost: %#v", o["transport"])
					}
				})
			}
		}
	}
}

func TestXHTTPPreservesModePathHostAndExtra(t *testing.T) {
	q := url.Values{}
	q.Set("type", "splithttp")
	q.Set("security", "tls")
	q.Set("encryption", "none")
	q.Set("host", "cdn.example")
	q.Set("path", "/game?ed=2048")
	q.Set("mode", "auto")
	q.Set("xPaddingBytes", "100-1000")
	q.Set("noGRPCHeader", "true")
	q.Set("sessionPlacement", "header")
	q.Set("uplinkDataPlacement", "header")
	q.Set("xPaddingObfsMode", "1")
	q.Set("xPaddingMethod", "tokenish")
	q.Set("extra", `{"mode":"packet-up","scMaxEachPostBytes":1000000,"scMinPostsIntervalMs":30.0,"scMaxConcurrentPosts":100,"xmux":{"maxConcurrency":"16-32","hMaxRequestTimes":[600,900],"hKeepAlivePeriod":-1},"headers":{"User-Agent":"Mozilla/5.0"}}`)
	o, err := Parse("vless://11111111-2222-3333-4444-555555555555@203.0.113.1:443?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := o["encryption"]; ok {
		t.Fatal("encryption=none was stored")
	}
	want := map[string]any{
		"transport.type":                     "xhttp",
		"transport.host":                     "cdn.example",
		"transport.path":                     "/game?ed=2048",
		"transport.mode":                     "packet-up",
		"transport.x_padding_bytes":          "100-1000",
		"transport.no_grpc_header":           true,
		"transport.session_placement":        "header",
		"transport.uplink_data_placement":    "header",
		"transport.x_padding_obfs_mode":      true,
		"transport.x_padding_method":         "tokenish",
		"transport.sc_max_each_post_bytes":   "1000000",
		"transport.sc_min_posts_interval_ms": "30",
		"transport.xmux.max_concurrency":     "16-32",
		"transport.xmux.h_max_request_times": "600-900",
		"transport.xmux.h_keep_alive_period": float64(-1),
		"transport.headers.User-Agent":       "Mozilla/5.0",
	}
	for path, value := range want {
		got := get(o, path)
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(value)
		if string(gj) != string(wj) {
			t.Errorf("%s = %s, expected %s", path, gj, wj)
		}
	}
	if _, ok := get(o, "transport").(map[string]any)["sc_max_concurrent_posts"]; ok {
		t.Fatal("legacy scMaxConcurrentPosts was copied into the client transport")
	}
}

func TestXHTTPRejectsUnknownAndMalformedOptions(t *testing.T) {
	for link, want := range map[string]string{
		"vless://u@h:443?type=xhttp&mode=nope":                                                            "mode",
		"vless://u@h:443?type=xhttp&noGRPCHeader=maybe":                                                   "boolean",
		"vless://u@h:443?type=xhttp&extra=%7B%22downloadSettings%22%3A%7B%7D%7D":                          "downloadSettings",
		"vless://u@h:443?type=xhttp&extra=%7B%22xmux%22%3A%7B%22foo%22%3A1%7D%7D":                         "foo",
		"vless://u@h:443?type=xhttp&extra=not-json":                                                       "JSON",
		"vless://u@h:443?type=xhttp&extra=%7B%22sessionKey%22%3A%22a%22%2C%22session_key%22%3A%22b%22%7D": "conflicting",
		"vless://u@h:443?type=ws&extra=%7B%22mode%22%3A%22auto%22%7D":                                     "extra",
	} {
		_, err := Parse(link)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, expected %q", link, err, want)
		}
	}
}

func TestREALITYKeyShareAndFragmentBooleans(t *testing.T) {
	o, err := Parse("vless://u@h:443?security=reality&pbk=PUBKEY&sid=ab&fp=chrome&spx=%2F&key_share=Hybrid&fragment=1&record_fragment=false&fragment_fallback_delay=300ms")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"tls.reality.key_share":       "hybrid",
		"tls.fragment":                true,
		"tls.record_fragment":         false,
		"tls.fragment_fallback_delay": "300ms",
	}
	for path, value := range want {
		got := get(o, path)
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(value)
		if string(gj) != string(wj) {
			t.Errorf("%s = %s, expected %s", path, gj, wj)
		}
	}
}

func TestREALITYRejectsUnrepresentableOptions(t *testing.T) {
	for link, want := range map[string]string{
		"vless://u@h:443?security=reality&pbk=PUBKEY&key_share=classic":                    "key_share",
		"vless://u@h:443?security=tls&key_share=hybrid":                                    "security=reality",
		"vless://u@h:443?security=reality&pbk=PUBKEY&fragment=10-20,tlshello":              "boolean",
		"vless://u@h:443?security=tls&record_fragment=maybe":                               "boolean",
		"vless://u@h:443?security=reality&pbk=PUBKEY&pqv=abc":                              "pqv",
		"vless://u@h:443?security=reality&pbk=PUBKEY&spx=/crawl":                           "spiderX",
		"vless://u@h:443?fm=1-3":                                                           "fm",
		"vless://u@h:443?fragment=true":                                                    "security",
		"vless://u@h:443?security=tls&allowInsecure=1&insecure=0":                          "conflicting",
		"vless://u@h:443?security=tls&insecure=maybe":                                      "boolean",
		"vless://u@h:443?security=tls&fragment=false&fragment=true":                        "conflicting",
		"vless://u@h:443?security=reality&pbk=PUBKEY&key_share=hybrid&key_share=classical": "conflicting",
		"vless://u@h:443?security=reality&pbk=PUBKEY&pqv=&pqv=signature":                   "conflicting",
	} {
		_, err := Parse(link)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, expected %q", link, err, want)
		}
	}
}

func TestTrustTunnelLinkDispatches(t *testing.T) {
	_, err := Parse("tt://?AQ")
	if err == nil || strings.Contains(err.Error(), "not supported in links") {
		t.Fatalf("tt:// was not dispatched to trusttunnel: %v", err)
	}
}
