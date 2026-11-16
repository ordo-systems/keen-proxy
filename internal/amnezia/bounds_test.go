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

func TestImportAcceptsURIAtRawCapWithOuterPadding(t *testing.T) {
	uri := uriFor(t, exportObject(map[string]any{"config": nativeConfig}, "amnezia-awg2"), false, false)
	pad := MaxURISize - len(uri)
	if pad < 2 {
		t.Fatalf("fixture leaves no room for outer padding: %d", len(uri))
	}
	padded := strings.Repeat("\n", pad/2) + uri + strings.Repeat(" ", pad-pad/2)
	if len(padded) != MaxURISize {
		t.Fatalf("raw length %d, want %d", len(padded), MaxURISize)
	}
	profiles, err := Import(padded)
	if err != nil || len(profiles) != 1 || profiles[0].AmneziaWG != nativeConfig {
		t.Fatalf("URI at the raw cap must import after trim: %v", err)
	}
}

func TestStructuredRejectsUnknownServerSecurityOption(t *testing.T) {
	obj := exportObject(map[string]any{"client_ip": "10.8.0.2", "client_priv_key": testKey, "server_pub_key": testKey, "hostName": "vpn.example", "port": 51820}, "amnezia-awg2")
	awg := obj["containers"].([]any)[0].(map[string]any)["awg"].(map[string]any)
	awg["subnet_address"] = "10.8.1.0"
	awg["FutureSecurity"] = "secret-server-option"
	profiles, err := Import(uriFor(t, obj, true, false))
	if !errors.Is(err, ErrUnsupportedProfile) || len(profiles) != 0 {
		t.Fatalf("unknown server option accepted: %v", err)
	}
	if strings.Contains(err.Error(), "secret-server-option") {
		t.Fatal("server secret leaked")
	}
}

func TestStructuredAcceptsPinnedServerMetadata(t *testing.T) {
	obj := exportObject(map[string]any{"client_ip": "10.8.0.2", "client_priv_key": testKey, "server_pub_key": testKey, "hostName": "vpn.example", "port": 51820}, "amnezia-awg2")
	awg := obj["containers"].([]any)[0].(map[string]any)["awg"].(map[string]any)
	awg["subnet_address"] = "10.8.1.0"
	awg["subnet_cidr"] = "24"
	awg["protocol_version"] = "2"
	awg["transport_proto"] = "udp"
	awg["isThirdPartyConfig"] = true
	awg["cascade_endpoint"] = "cascade.example"
	awg["cascade_port"] = "1"
	awg["S1"] = "0"
	profiles, err := Import(uriFor(t, obj, true, false))
	if err != nil || len(profiles) != 1 || !strings.Contains(profiles[0].AmneziaWG, "S1 = 0") {
		t.Fatalf("pinned server metadata rejected: %v", err)
	}
	if strings.Contains(profiles[0].AmneziaWG, "10.8.1.0") || strings.Contains(profiles[0].AmneziaWG, "cascade.example") {
		t.Fatal("admin metadata copied into the client profile")
	}
}

func TestStructuredRejectsNonUDPTransport(t *testing.T) {
	for _, transport := range []any{"tcp", nil, []string{"udp"}} {
		obj := exportObject(map[string]any{"client_ip": "10.8.0.2", "client_priv_key": testKey, "server_pub_key": testKey, "port": 51820}, "amnezia-awg2")
		obj["containers"].([]any)[0].(map[string]any)["awg"].(map[string]any)["transport_proto"] = transport
		if profiles, err := Import(uriFor(t, obj, true, false)); !errors.Is(err, ErrUnsupportedProfile) || len(profiles) != 0 {
			t.Fatalf("unsupported outer transport accepted: %v", err)
		}
	}
}

func TestNativeConfigIgnoresUnknownServerBookkeeping(t *testing.T) {
	obj := exportObject(map[string]any{"config": nativeConfig}, "amnezia-awg")
	obj["containers"].([]any)[0].(map[string]any)["awg"].(map[string]any)["FutureSecurity"] = "secret-server-option"
	profiles, err := Import(uriFor(t, obj, true, false))
	if err != nil || len(profiles) != 1 || profiles[0].AmneziaWG != nativeConfig {
		t.Fatalf("native config must stay authoritative: %v", err)
	}
}

func nativeAWGContainers(n int) []any {
	containers := make([]any, n)
	for i := range containers {
		containers[i] = map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": map[string]any{"config": nativeConfig}}}
	}
	return containers
}

func structuredExport(n int, dns string, stretchLast bool) map[string]any {
	containers := make([]any, n)
	for i := range containers {
		last := map[string]any{"client_ip": "10.8.0.2", "client_priv_key": testKey, "server_pub_key": testKey, "port": 51820}
		if stretchLast && i == n-1 {
			// One extra hostname byte lengthens only this profile's Endpoint line.
			last["hostName"] = "vvpn.example"
		}
		containers[i] = map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": last}}
	}
	return map[string]any{"format_version": 1, "hostName": "vpn.example", "dns1": dns, "containers": containers}
}

func TestImportAcceptsMaxAWGCandidates(t *testing.T) {
	containers := make([]any, 0, MaxAWGCandidates+2)
	ignored := map[string]any{"container": "amnezia-openvpn", "openvpn": map[string]any{"last_config": "ignored"}}
	containers = append(containers, ignored)
	containers = append(containers, nativeAWGContainers(MaxAWGCandidates)...)
	containers = append(containers, ignored)
	obj := map[string]any{"format_version": 1, "hostName": "vpn.example", "dns1": "1.1.1.1", "containers": containers}
	profiles, err := Import(uriFor(t, obj, false, false))
	if err != nil || len(profiles) != MaxAWGCandidates {
		t.Fatalf("profiles=%d err=%v", len(profiles), err)
	}
	for _, profile := range profiles {
		if profile.Type != "amneziawg" || profile.AmneziaWG != nativeConfig {
			t.Fatal("native profile text must stay authoritative")
		}
	}
}

func TestImportRejectsSurplusAWGCandidate(t *testing.T) {
	obj := map[string]any{"format_version": 1, "hostName": "vpn.example", "containers": nativeAWGContainers(MaxAWGCandidates + 1)}
	profiles, err := Import(uriFor(t, obj, false, false))
	if !errors.Is(err, ErrInvalidProfile) || len(profiles) != 0 {
		t.Fatalf("33 candidates: %v profiles=%d", err, len(profiles))
	}

	// The surplus container would be unsupported if it were built. Count must
	// reject it first so construction never reclassifies the export.
	containers := nativeAWGContainers(MaxAWGCandidates)
	containers = append(containers, map[string]any{"container": "amnezia-awg2", "awg": map[string]any{"last_config": map[string]any{"config": nativeConfig + "PostUp = secret\n"}}})
	obj["containers"] = containers
	profiles, err = Import(uriFor(t, obj, false, false))
	if !errors.Is(err, ErrInvalidProfile) || errors.Is(err, ErrUnsupportedProfile) || len(profiles) != 0 {
		t.Fatalf("surplus candidate was constructed: %v profiles=%d", err, len(profiles))
	}
}

func TestImportRejectsSharedDNSAmplification(t *testing.T) {
	const candidates = 8
	if candidates >= MaxAWGCandidates || MaxAggregateProfileBytes%candidates != 0 {
		t.Fatal("amplification fixture must stay inside the candidate cap")
	}
	probe := "1.1.1.1"
	probed, err := Import(uriFor(t, structuredExport(1, probe, false), false, false))
	if err != nil || len(probed) != 1 || !strings.Contains(probed[0].AmneziaWG, "DNS = "+probe) {
		t.Fatalf("structured DNS metadata changed: %v", err)
	}
	grow := MaxAggregateProfileBytes/candidates - len(probed[0].AmneziaWG) + 1
	if grow < 1 {
		t.Fatalf("probe profile %d exceeds an even share", len(probed[0].AmneziaWG))
	}
	dns := probe + strings.Repeat(" ", grow)
	one, err := Import(uriFor(t, structuredExport(1, dns, false), false, false))
	if err != nil || len(one) != 1 || !strings.Contains(one[0].AmneziaWG, "DNS = "+dns) {
		t.Fatalf("single profile must retain shared DNS: %v", err)
	}
	if len(one[0].AmneziaWG) > MaxAggregateProfileBytes {
		t.Fatalf("fixture exceeded one profile budget: %d", len(one[0].AmneziaWG))
	}
	profiles, err := Import(uriFor(t, structuredExport(candidates, dns, false), false, false))
	if !errors.Is(err, ErrInvalidProfile) || len(profiles) != 0 {
		t.Fatalf("amplified export accepted: %v profiles=%d", err, len(profiles))
	}
}

func TestImportAggregateProfileBytesBoundary(t *testing.T) {
	const candidates = 16
	if candidates > MaxAWGCandidates || MaxAggregateProfileBytes%candidates != 0 {
		t.Fatal("boundary fixture does not divide the budget")
	}
	target := MaxAggregateProfileBytes / candidates
	probe := "1.1.1.1"
	probed, err := Import(uriFor(t, structuredExport(1, probe, false), false, false))
	if err != nil || len(probed) != 1 || !strings.Contains(probed[0].AmneziaWG, "DNS = "+probe) {
		t.Fatalf("probe: %v", err)
	}
	grow := target - len(probed[0].AmneziaWG)
	if grow < 0 {
		t.Fatalf("probe %d exceeds target %d", len(probed[0].AmneziaWG), target)
	}
	dns := probe + strings.Repeat(" ", grow)
	profiles, err := Import(uriFor(t, structuredExport(candidates, dns, false), false, false))
	if err != nil || len(profiles) != candidates {
		t.Fatalf("exact budget: profiles=%d err=%v", len(profiles), err)
	}
	total := 0
	for _, profile := range profiles {
		if !strings.Contains(profile.AmneziaWG, "DNS = "+dns) {
			t.Fatal("shared DNS was dropped from a structured profile")
		}
		total += len(profile.AmneziaWG)
	}
	if total != MaxAggregateProfileBytes {
		t.Fatalf("retained %d, want %d", total, MaxAggregateProfileBytes)
	}

	stretched, err := Import(uriFor(t, structuredExport(1, dns, true), false, false))
	if err != nil || len(stretched) != 1 || len(stretched[0].AmneziaWG) != target+1 {
		got := 0
		if len(stretched) == 1 {
			got = len(stretched[0].AmneziaWG)
		}
		t.Fatalf("endpoint stretch must add one retained byte: got %d want %d err=%v", got, target+1, err)
	}
	over, err := Import(uriFor(t, structuredExport(candidates, dns, true), false, false))
	if !errors.Is(err, ErrInvalidProfile) || len(over) != 0 {
		t.Fatalf("one byte over budget: %v profiles=%d", err, len(over))
	}
}
