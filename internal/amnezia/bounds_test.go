package amnezia

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCompressedActualSizeIsBounded(t *testing.T) {
	// The header deliberately lies: the actual decompressor must still stop.
	uri := encodeBytes(t, []byte(strings.Repeat("x", MaxDecodedSize+1)), true, false)
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, "vpn://"))
	binary.BigEndian.PutUint32(raw[:4], 1)
	_, err := Import("vpn://" + base64.RawURLEncoding.EncodeToString(raw))
	if !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("got %v", err)
	}
}

func TestCompressedIntegrity(t *testing.T) {
	uri := uriFor(t, exportObject(map[string]any{"config": nativeConfig}, "amnezia-awg2"), true, false)
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, "vpn://"))
	badChecksum := append([]byte(nil), raw...)
	badChecksum[len(badChecksum)-1] ^= 0xff
	for _, data := range [][]byte{raw[:len(raw)-1], badChecksum, append(append([]byte(nil), raw...), 1)} {
		profiles, err := Import("vpn://" + base64.RawURLEncoding.EncodeToString(data))
		if !errors.Is(err, ErrInvalidProfile) || len(profiles) != 0 {
			t.Fatalf("got %v profiles=%d", err, len(profiles))
		}
	}
}

func TestSecurityOptionsNeverDisappear(t *testing.T) {
	for _, client := range []map[string]any{
		{"config": nativeConfig, "HeaderProtectionKey": testKey},
		{"config": nativeConfig, "DisableCookies": "true"},
		{"config": nativeConfig, "H1": "201-202"},
		{"config": nativeConfig, "isObfuscationEnabled": false},
		{"config": strings.ReplaceAll(nativeConfig, "PresharedKey = "+testKey+"\n", ""), "psk_key": testKey},
		{"config": nativeConfig, "persistent_keep_alive": "10-20"},
		{"config": 7},
	} {
		profiles, err := Import(uriFor(t, exportObject(client, "amnezia-awg"), true, false))
		if !errors.Is(err, ErrUnsupportedProfile) || len(profiles) != 0 {
			t.Fatalf("got %v profiles=%d", err, len(profiles))
		}
	}
}

func TestStructuredRejectsInjectionAndInvalidOptions(t *testing.T) {
	for _, patch := range []map[string]any{
		{"client_ip": "10.8.0.2\nPostUp = bad"},
		{"hostName": "vpn.example\nPostUp = bad"},
		{"psk_key": "not-a-key"},
		{"H1": "9-1"},
		{"I1": "<unknown secret>"},
		{"allowed_ips": []string{"not-a-prefix"}},
		{"RandomTrailers": "maybe"},
	} {
		client := map[string]any{"client_ip": "10.8.0.2", "client_priv_key": testKey, "server_pub_key": testKey, "hostName": "vpn.example", "port": 51820}
		for key, value := range patch {
			client[key] = value
		}
		profiles, err := Import(uriFor(t, exportObject(client, "amnezia-awg2"), true, false))
		if err == nil || len(profiles) != 0 {
			t.Fatal("invalid structured client accepted")
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "bad") {
			t.Fatal("credential leak")
		}
	}
}

func TestAdminContainersNeedClientMaterial(t *testing.T) {
	obj := exportObject(nil, "amnezia-awg2")
	obj["userName"], obj["password"] = "root", "ssh-secret"
	_, err := Import(uriFor(t, obj, true, false))
	if !errors.Is(err, ErrAdminProfile) {
		t.Fatalf("got %v", err)
	}
}

func TestPremiumServiceHeaderIsClassifiedWithoutImportingIt(t *testing.T) {
	uri := uriFor(t, map[string]any{"config_version": 2, "auth_data": map[string]any{"api_key": "synthetic-service-secret"}}, true, false)
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, "vpn://"))
	binary.BigEndian.PutUint32(raw[:4], 255)
	profiles, err := Import("vpn://" + base64.RawURLEncoding.EncodeToString(raw))
	if !errors.Is(err, ErrServiceProfile) || len(profiles) != 0 {
		t.Fatalf("service key must be identified, not imported: %v", err)
	}
}

func TestServiceSignatureCannotRelaxStandaloneLengthChecks(t *testing.T) {
	uri := uriFor(t, exportObject(map[string]any{"config": nativeConfig}, "amnezia-awg2"), true, false)
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, "vpn://"))
	binary.BigEndian.PutUint32(raw[:4], 255)
	_, err := Import("vpn://" + base64.RawURLEncoding.EncodeToString(raw))
	if !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("standalone size mismatch accepted: %v", err)
	}
}

func TestCompressedExportAtDecodedLimit(t *testing.T) {
	obj := exportObject(map[string]any{"config": nativeConfig}, "amnezia-awg2")
	obj["description"] = ""
	small, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	obj["description"] = strings.Repeat("x", MaxDecodedSize-len(small))
	profiles, err := Import(uriFor(t, obj, true, false))
	if err != nil || len(profiles) != 1 || profiles[0].AmneziaWG != nativeConfig {
		t.Fatalf("export at the decoded limit must preserve the client profile: %v", err)
	}
}

func TestStructuredExportRequiresBothClientKeys(t *testing.T) {
	for _, missing := range []string{"client_priv_key", "server_pub_key"} {
		t.Run(missing, func(t *testing.T) {
			client := map[string]any{"client_ip": "10.8.0.2", "client_priv_key": testKey, "server_pub_key": testKey, "hostName": "vpn.example", "port": 51820}
			delete(client, missing)
			profiles, err := Import(uriFor(t, exportObject(client, "amnezia-awg2"), true, false))
			if !errors.Is(err, ErrInvalidProfile) || len(profiles) != 0 {
				t.Fatalf("incomplete client material must be classified as invalid: %v", err)
			}
		})
	}
}
