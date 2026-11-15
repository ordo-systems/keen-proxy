package awg

import (
	"encoding/json"
	"strings"
	"testing"
)

const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
const profile = "[Interface]\nPrivateKey = " + key + "\nAddress = 10.0.0.2/32, 2001:db8::2/128\nDNS = 1.1.1.1, resolver.example\nMTU = 1280\nJc = 0\nJmin = 10\nJmax = 20\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 100-110\nH2 = 200\nH3 = 300\nH4 = 400\nI1 = <b 0xAbCd><r 12><d><ds><dz 2><t><rc 2><rd 3>\nHeaderProtectionKey = " + key + "\nContentPaddingAddition = 0-10\nRandomTrailers = true\nDisableCookies = false\nRekeyAfterTime = 100-120\nRekeyTimeout = 3-7\nRejectAfterTime = 150-180\nKeepaliveTimeout = 5-15\nMaxHandshakeAttempts = 15-20\n[Peer]\nPublicKey = " + key + "\nPresharedKey = " + key + "\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25-35\nAdvancedSecurity = true\n"

func TestParsePreservesProfileValues(t *testing.T) {
	ep, err := Parse(profile)
	if err != nil {
		t.Fatal(err)
	}
	if ep["type"] != "wireguard" || ep["tag"] != nil || ep["dns"] != nil {
		t.Fatalf("endpoint boundary: %#v", ep)
	}
	for name, want := range map[string]any{"jc": uint64(0), "mtu": uint64(1280), "h1": "100-110", "h2": uint64(200), "content_padding_addition": "0-10", "random_trailers": true, "disable_cookies": false, "header_protection_key": key, "i1": "<b 0xAbCd><r 12><d><ds><dz 2><t><rc 2><rd 3>"} {
		if ep[name] != want {
			t.Errorf("%s = %#v, want %#v", name, ep[name], want)
		}
	}
	peer := ep["peers"].([]map[string]any)[0]
	if peer["address"] != "2001:db8::1" || peer["port"] != uint64(51820) || peer["pre_shared_key"] != key || peer["persistent_keepalive_interval"] != "25-35" {
		t.Fatalf("peer lost values: %#v", peer)
	}
	raw, err := json.Marshal(ep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "DNS") || strings.Contains(string(raw), "resolver.example") {
		t.Fatalf("DNS imported: %s", raw)
	}
}

func TestParseRejectsInvalidProfiles(t *testing.T) {
	cases := map[string]string{
		"missing interface":       strings.Replace(profile, "[Interface]", "", 1),
		"duplicate interface":     profile + "[Interface]\n",
		"multiple peers":          profile + "[Peer]\n",
		"unknown section":         profile + "[Other]\n",
		"duplicate key":           profile + "PublicKey = " + key + "\n",
		"case duplicate":          profile + "publickey = " + key + "\n",
		"unknown field":           profile + "Unsupported = 1\n",
		"hook":                    strings.Replace(profile, "MTU = 1280", "PostUp = echo secret", 1),
		"wrong section":           profile + "Jc = 2\n",
		"private key":             strings.Replace(profile, "PrivateKey = "+key, "PrivateKey = SECRET", 1),
		"public key":              strings.Replace(profile, "PublicKey = "+key, "PublicKey = bad", 1),
		"psk":                     strings.Replace(profile, "PresharedKey = "+key, "PresharedKey = bad", 1),
		"address":                 strings.Replace(profile, "10.0.0.2/32", "10.0.0.2/33", 1),
		"allowed IP":              strings.Replace(profile, "AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = nope", 1),
		"empty list":              strings.Replace(profile, "Address = 10.0.0.2/32, 2001:db8::2/128", "Address = 10.0.0.2/32,", 1),
		"port zero":               strings.Replace(profile, "]:51820", "]:0", 1),
		"port overflow":           strings.Replace(profile, "]:51820", "]:65536", 1),
		"hostname":                strings.Replace(profile, "[2001:db8::1]", "bad host", 1),
		"mtu":                     strings.Replace(profile, "MTU = 1280", "MTU = 65536", 1),
		"negative":                strings.Replace(profile, "Jc = 0", "Jc = -1", 1),
		"junk overflow":           strings.Replace(profile, "Jc = 0", "Jc = 65536", 1),
		"junk order":              strings.Replace(profile, "Jmin = 10", "Jmin = 21", 1),
		"range order":             strings.Replace(profile, "H1 = 100-110", "H1 = 110-100", 1),
		"header overflow":         strings.Replace(profile, "H1 = 100-110", "H1 = 4294967296", 1),
		"header overlap":          strings.Replace(profile, "H2 = 200", "H2 = 110-200", 1),
		"keepalive overflow":      strings.Replace(profile, "25-35", "25-65536", 1),
		"timer overflow":          strings.Replace(profile, "3-7", "3-65536", 1),
		"boolean":                 strings.Replace(profile, "RandomTrailers = true", "RandomTrailers = maybe", 1),
		"header padding":          strings.Replace(profile, "S3 = 12", "S3 = 11", 1),
		"invalid CPS":             strings.Replace(profile, "<r 12>", "<r -1>", 1),
		"unknown CPS":             strings.Replace(profile, "<r 12>", "<unknown 12>", 1),
		"CPS timestamp arguments": strings.Replace(profile, "<t>", "<t 1>", 1),
		"CPS missing length":      strings.Replace(profile, "<r 12>", "<r>", 1),
		"CPS empty tag":           strings.Replace(profile, "<r 12>", "<>", 1),
		"CPS empty hex":           strings.Replace(profile, "0xAbCd", "0x", 1),
		"CPS odd hex":             strings.Replace(profile, "0xAbCd", "0xA", 1),
		"CPS invalid hex":         strings.Replace(profile, "0xAbCd", "0xGG", 1),
		"CPS oversized packet":    strings.Replace(profile, "<r 12>", "<r 65507>", 1),
		"reverse header overlap":  strings.Replace(strings.Replace(profile, "H1 = 100-110", "H1 = 200-300", 1), "H2 = 200", "H2 = 100-200", 1),
		"dns":                     strings.Replace(profile, "DNS = 1.1.1.1, resolver.example", "DNS = https://resolver.example", 1),
		"disabled security":       strings.Replace(profile, "AdvancedSecurity = true", "AdvancedSecurity = false", 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(input); err == nil {
				t.Fatal("invalid profile accepted")
			} else if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("error exposed secret")
			}
		})
	}
}

func TestParseDefaultAllowedIPsAndZeroKeepalive(t *testing.T) {
	input := strings.Replace(profile, "AllowedIPs = 0.0.0.0/0, ::/0\n", "", 1)
	input = strings.Replace(input, "PersistentKeepalive = 25-35", "PersistentKeepalive = 0", 1)
	ep, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	peer := ep["peers"].([]map[string]any)[0]
	if got := peer["allowed_ips"].([]string); len(got) != 2 || got[0] != "0.0.0.0/0" || got[1] != "::/0" {
		t.Fatalf("defaults: %#v", got)
	}
	if peer["persistent_keepalive_interval"] != uint64(0) {
		t.Fatal("zero keepalive lost")
	}
}

func TestParseUTF8BOMAndCRLF(t *testing.T) {
	input := "\uFEFF# exported client profile\r\n" + strings.ReplaceAll(profile, "\n", "\r\n")
	ep, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	if ep["private_key"] != key || ep["h1"] != "100-110" {
		t.Fatal("profile values changed while decoding UTF-8 BOM/CRLF")
	}
}

func TestParseOfficialSpellingsAndOptionalFields(t *testing.T) {
	input := strings.Replace(profile, "PrivateKey =", "privatekey =", 1)
	input = strings.Replace(input, "[Peer]", "ListenPort = 0\nI2 = <r 4>\nI3 = <rc 5>\nI4 = <rd 6>\nI5 = <b 0xABcd>\n[Peer]", 1)
	input = strings.Replace(input, "PersistentKeepalive = 25-35", "PersistentKeepalive = off", 1)
	ep, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]any{"listen_port": uint64(0), "i2": "<r 4>", "i3": "<rc 5>", "i4": "<rd 6>", "i5": "<b 0xABcd>"} {
		if ep[field] != want {
			t.Errorf("%s = %#v, want %#v", field, ep[field], want)
		}
	}
	if ep["peers"].([]map[string]any)[0]["persistent_keepalive_interval"] != uint64(0) {
		t.Fatal("off keepalive not preserved")
	}
}

func TestParseRejectsBoundaryAndMissingValues(t *testing.T) {
	for _, input := range []string{
		strings.Repeat(" ", (1<<20)+1),
		profile + "\x00",
		strings.Replace(profile, "PrivateKey = "+key+"\n", "", 1),
		strings.Replace(profile, "Address = 10.0.0.2/32, 2001:db8::2/128\n", "", 1),
		strings.Replace(profile, "Endpoint = [2001:db8::1]:51820\n", "", 1),
		strings.Replace(profile, "PublicKey = "+key+"\n", "", 1),
		strings.Replace(profile, "DNS = 1.1.1.1, resolver.example", "DNS = 999.1.1.1", 1),
		strings.Replace(profile, "DNS = 1.1.1.1, resolver.example", "DNS = fe80::1%eth0", 1),
		strings.Replace(profile, "[2001:db8::1]", "999.1.1.1", 1),
		strings.Replace(profile, "<r 12>", "<c>", 1),
		strings.Replace(profile, "<r 12>", "<r 65507><r 1>", 1),
	} {
		if _, err := Parse(input); err == nil {
			t.Fatal("boundary or missing-value error accepted")
		}
	}
}

func TestParseInclusiveRangeBoundaries(t *testing.T) {
	input := strings.Replace(profile, "Jmin = 10", "Jmin = 20", 1)
	input = strings.Replace(input, "H1 = 100-110", "H1 = 100-100", 1)
	ep, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	if ep["jmin"] != uint64(20) || ep["jmax"] != uint64(20) || ep["h1"] != "100-100" {
		t.Fatal("inclusive range boundaries changed")
	}
}

func TestParseMaximumCPSPayload(t *testing.T) {
	input := strings.Replace(profile, "<b 0xAbCd><r 12><d><ds><dz 2><t><rc 2><rd 3>", "<r 65507>", 1)
	ep, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	if ep["i1"] != "<r 65507>" {
		t.Fatal("maximum UDP payload changed")
	}
}

func TestParseRejectsAssignmentsOutsideSectionsAndMissingEquals(t *testing.T) {
	for _, input := range []string{
		"PublicKey = " + key + "\n" + profile,
		strings.Replace(profile, "S1 = 12", "I2\nS1 = 12", 1),
	} {
		if _, err := Parse(input); err == nil {
			t.Fatal("accepted a field outside its section or without an equals sign")
		}
	}
}

func TestParseRejectsTouchingHeaderRangesInEitherOrder(t *testing.T) {
	input := strings.Replace(profile, "H1 = 100-110", "H1 = 200-300", 1)
	input = strings.Replace(input, "H2 = 200", "H2 = 100-200", 1)
	input = strings.Replace(input, "H3 = 300", "H3 = 500", 1)
	input = strings.Replace(input, "H4 = 400", "H4 = 600", 1)
	if _, err := Parse(input); err == nil {
		t.Fatal("touching H1/H2 ranges would make packet classification ambiguous")
	}
}

func TestParseJunkBurstBudget(t *testing.T) {
	base := "Jc = 0\nJmin = 10\nJmax = 20"
	accepted := map[string]struct {
		fields string
		jc     uint64
		jmax   any
	}{
		"count boundary with default sizes": {"Jc = 256", 256, nil},
		"exact payload boundary":            {"Jc = 256\nJmin = 0\nJmax = 4096", 256, uint64(4096)},
		"largest uint16 packet under cap":   {"Jc = 16\nJmin = 65535\nJmax = 65535", 16, uint64(65535)},
	}
	for name, tc := range accepted {
		t.Run(name, func(t *testing.T) {
			ep, err := Parse(strings.Replace(profile, base, tc.fields, 1))
			if err != nil {
				t.Fatal(err)
			}
			if ep["jc"] != tc.jc || ep["jmax"] != tc.jmax {
				t.Fatalf("burst rewritten: jc=%#v jmax=%#v", ep["jc"], ep["jmax"])
			}
		})
	}
	for _, fields := range []string{
		"Jc = 257",
		"Jc = 257\nJmin = 0\nJmax = 0",
		"Jc = 256\nJmin = 0\nJmax = 4097",
		"Jc = 17\nJmin = 1\nJmax = 65535",
	} {
		t.Run(fields, func(t *testing.T) {
			_, err := Parse(strings.Replace(profile, base, fields, 1))
			if err == nil || !strings.Contains(err.Error(), "junk packet burst") {
				t.Fatalf("over-budget burst accepted or misclassified: %v", err)
			}
		})
	}
}
