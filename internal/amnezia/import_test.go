package amnezia

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const testKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
const nativeConfig = "[Interface]\nPrivateKey = " + testKey + "\nAddress = 10.8.0.2/32\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 0\nS2 = 0\nH1 = 100-200\nH2 = 300\nH3 = 400\nH4 = 500\nI1 = <b 0x1234>\n[Peer]\nPublicKey = " + testKey + "\nPresharedKey = " + testKey + "\nEndpoint = vpn.example:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"

func exportObject(last any, container string) map[string]any {
	return map[string]any{"format_version": 1, "hostName": "vpn.example", "containers": []any{map[string]any{"container": container, "awg": map[string]any{"last_config": last}}}}
}

func uriFor(t *testing.T, value any, compressed, padded bool) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encodeBytes(t, raw, compressed, padded)
}

func encodeBytes(t *testing.T, raw []byte, compressed, padded bool) string {
	t.Helper()
	if compressed {
		var b bytes.Buffer
		if err := binary.Write(&b, binary.BigEndian, uint32(len(raw))); err != nil {
			t.Fatal(err)
		}
		w := zlib.NewWriter(&b)
		if _, err := w.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		raw = b.Bytes()
	}
	enc := base64.RawURLEncoding
	if padded {
		enc = base64.URLEncoding
	}
	return "vpn://" + enc.EncodeToString(raw)
}

func TestImportNativeExports(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		for _, padded := range []bool{false, true} {
			for _, container := range []string{"amnezia-awg", "amnezia-awg2"} {
				last, _ := json.Marshal(map[string]any{"config": nativeConfig})
				obj := exportObject(string(last), container)
				obj["userName"], obj["password"], obj["description"] = "root-secret", "ssh-secret", "ssh-secret"
				profiles, err := Import(uriFor(t, obj, compressed, padded))
				if err != nil || len(profiles) != 1 {
					t.Fatalf("profiles=%v err=%v", len(profiles), err)
				}
				p := profiles[0]
				if p.ID != "" || p.Type != "amneziawg" || p.Name == "" || p.AmneziaWG != nativeConfig {
					t.Fatalf("incorrect candidate: %s %s", p.ID, p.Type)
				}
				raw, _ := json.Marshal(p)
				if bytes.Contains(raw, []byte("ssh-secret")) || bytes.Contains(raw, []byte("root-secret")) || bytes.Contains(raw, []byte("vpn://")) {
					t.Fatal("envelope credential leak")
				}
			}
		}
	}
}

func TestImportStructuredAndMultiple(t *testing.T) {
	client := map[string]any{"client_ip": "10.8.0.2", "client_priv_key": testKey, "server_pub_key": testKey, "psk_key": testKey, "hostName": "vpn.example", "port": 51820, "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "persistent_keep_alive": "25", "H1": "100-200", "I1": "<b 0x1234>", "ContentPaddingAddition": "0-10", "RandomTrailers": "true"}
	obj := exportObject(client, "amnezia-awg2")
	obj["dns1"], obj["dns2"] = "1.1.1.1", "9.9.9.9"
	containers := obj["containers"].([]any)
	containers[0].(map[string]any)["awg"].(map[string]any)["S1"] = "0"
	obj["containers"] = append(containers, map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": map[string]any{"config": nativeConfig}}}, map[string]any{"container": "amnezia-openvpn", "openvpn": map[string]any{"last_config": "ignored"}})
	profiles, err := Import(uriFor(t, obj, true, false))
	if err != nil || len(profiles) != 2 {
		t.Fatalf("profiles=%d err=%v", len(profiles), err)
	}
	for _, want := range []string{"H1 = 100-200", "I1 = <b 0x1234>", "PresharedKey = " + testKey, "ContentPaddingAddition = 0-10", "RandomTrailers = true", "Address = 10.8.0.2/32", "S1 = 0", "DNS = 1.1.1.1, 9.9.9.9"} {
		if !strings.Contains(profiles[0].AmneziaWG, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if profiles[0].Name == profiles[1].Name {
		t.Fatal("candidate names must distinguish containers")
	}
}

func TestImportClassifications(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  error
	}{
		{"array", []any{}, ErrInvalidProfile},
		{"null", nil, ErrInvalidProfile},
		{"empty", map[string]any{}, ErrUnsupportedProfile},
		{"future", map[string]any{"format_version": 2}, ErrFormatVersion},
		{"version type", map[string]any{"format_version": "1"}, ErrFormatVersion},
		{"negative version", map[string]any{"format_version": -1}, ErrFormatVersion},
		{"admin", map[string]any{"hostName": "host", "userName": "root", "password": "ssh-secret"}, ErrAdminProfile},
		{"no client", exportObject(nil, "amnezia-awg"), ErrInvalidProfile},
		{"unsupported native", exportObject(map[string]any{"config": nativeConfig + "PostUp = secret\n"}, "amnezia-awg"), ErrUnsupportedProfile},
		{"null version", map[string]any{"format_version": nil}, ErrFormatVersion},
		{"missing key", exportObject(map[string]any{"client_ip": "10.8.0.2"}, "amnezia-awg"), ErrInvalidProfile},
		{"unknown client option", exportObject(map[string]any{"config": nativeConfig, "FutureSecurity": "secret"}, "amnezia-awg"), ErrUnsupportedProfile},
	}
	for _, marker := range []string{"api_config", "api_key", "auth_data", "api_endpoint", "service_type", "vpn_key"} {
		obj := exportObject(map[string]any{"config": nativeConfig}, "amnezia-awg")
		obj[marker] = "service-secret"
		cases = append(cases, struct {
			name  string
			value any
			want  error
		}{marker, obj, ErrServiceProfile})
	}
	for _, version := range []int{1, 2, 3} {
		obj := exportObject(map[string]any{"config": nativeConfig}, "amnezia-awg")
		obj["config_version"] = version
		cases = append(cases, struct {
			name  string
			value any
			want  error
		}{"service version", obj, ErrServiceProfile})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profiles, err := Import(uriFor(t, tc.value, true, false))
			if !errors.Is(err, tc.want) || len(profiles) != 0 {
				t.Fatalf("got %v profiles=%d want %v", err, len(profiles), tc.want)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("secret leaked")
			}
		})
	}
}

func TestImportMalformedAndBounds(t *testing.T) {
	mismatch := []byte{0, 0, 0, 1}
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, _ = w.Write([]byte(`{}`))
	_ = w.Close()
	mismatch = append(mismatch, b.Bytes()...)
	bomb := []byte(strings.Repeat("x", MaxDecodedSize+1))
	for _, input := range []string{"", "https://secret", "vpn://!!!", "vpn://AA", encodeBytes(t, []byte(`{} {}`), false, false), encodeBytes(t, mismatch, false, false), encodeBytes(t, bomb, true, false), "vpn://" + strings.Repeat("A", MaxURISize)} {
		profiles, err := Import(input)
		if !errors.Is(err, ErrInvalidProfile) || len(profiles) != 0 {
			t.Fatalf("got %v profiles=%d", err, len(profiles))
		}
	}
}

func TestImportLegacyVersions(t *testing.T) {
	for _, version := range []int{-1, 0, 1} {
		obj := exportObject(map[string]any{"config": nativeConfig}, "amnezia-awg")
		if version < 0 {
			delete(obj, "format_version")
		} else {
			obj["format_version"] = version
		}
		profiles, err := Import(uriFor(t, obj, true, false))
		if err != nil || len(profiles) != 1 {
			t.Fatalf("legacy version %d: %v", version, err)
		}
	}
}
