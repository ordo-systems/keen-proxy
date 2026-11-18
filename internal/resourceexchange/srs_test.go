package resourceexchange

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
)

func TestSRSImportVersions(t *testing.T) {
	for version := uint8(1); version <= 5; version++ {
		var buf bytes.Buffer
		rules := option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: "default", DefaultOptions: option.DefaultHeadlessRule{
			DomainSuffix: []string{"example.org", ".nested.example.net"},
			IPCIDR:       []string{"192.0.2.0/24", "2001:db8::/32"},
		}}, {Type: "default", DefaultOptions: option.DefaultHeadlessRule{
			Domain: []string{"nested.example.net"},
		}}}}
		if err := srs.Write(&buf, rules, version); err != nil {
			t.Fatal(err)
		}
		got := Decode(SRS, buf.Bytes())
		if !got.Valid || len(got.List.Entries) != 4 {
			t.Fatalf("version %d: unexpected import: %+v", version, got)
		}
	}
}

func TestSRSImportRejectsIPSuffix(t *testing.T) {
	rules := option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: "default", DefaultOptions: option.DefaultHeadlessRule{
		DomainSuffix: []string{"192.0.2.1"},
	}}}}
	var buf bytes.Buffer
	if err := srs.Write(&buf, rules, singBoxExportVersion); err != nil {
		t.Fatal(err)
	}
	got := Decode(SRS, buf.Bytes())
	if got.Valid || len(got.List.Entries) != 0 || len(got.Issues) != 1 || got.Issues[0].Location != "rules[0].domain_suffix[0]" {
		t.Fatalf("expected unrepresentable suffix rejection, got %+v", got)
	}
}

func TestSRSRoundTripRetainsAdjacentAndOverlappingPrefixes(t *testing.T) {
	list := List{Entries: []Entry{
		{Type: IPCIDR, Value: "192.0.2.0/24"},
		{Type: IPCIDR, Value: "192.0.2.0/25"},
		{Type: IPCIDR, Value: "192.0.2.128/25"},
	}}
	data, losses, err := Encode(SRS, list)
	if err != nil || len(losses) != 0 {
		t.Fatalf("export: %v, losses %v", err, losses)
	}
	got := Decode(SRS, data)
	if !got.Valid || len(got.List.Entries) != len(list.Entries) {
		t.Fatalf("round trip lost editable prefixes: %+v", got)
	}
	for i, expected := range list.Entries {
		if got.List.Entries[i] != expected {
			t.Fatalf("entry %d = %+v, want %+v", i, got.List.Entries[i], expected)
		}
	}
}

func TestSRSExportBatchesDomainsWithinMatcherBudget(t *testing.T) {
	const keysPerMatcher = maxSRSMatcherKeyBytes / (maxSuffixBytes + 1)
	domains := srsTestDomains(2*keysPerMatcher + 1)
	list := List{Entries: append(domains,
		Entry{Type: IPCIDR, Value: "192.0.2.0/24"},
		Entry{Type: IPCIDR, Value: "192.0.2.0/25"},
		Entry{Type: IPCIDR, Value: "192.0.2.128/25"},
		Entry{Type: IPCIDR, Value: "2001:db8::/32"},
	)}
	data, _, err := Encode(SRS, list)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := srs.Read(bytes.NewReader(data), true)
	if err != nil {
		t.Fatal(err)
	}
	batches := 0
	for _, rule := range exported.Options.Rules {
		suffixes := rule.DefaultOptions.DomainSuffix
		if len(suffixes) == 0 {
			continue
		}
		batches++
		keyBytes := 0
		for _, suffix := range suffixes {
			keyBytes += len(suffix) + 1 // v2 matcher marker
			if m := rule.DefaultOptions.DomainMatcher; !m.Match(suffix) || !m.Match("child."+suffix) {
				t.Fatalf("matcher lost suffix %q", suffix)
			}
		}
		if keyBytes > maxSRSMatcherKeyBytes {
			t.Fatalf("matcher uses %d key bytes, limit %d", keyBytes, maxSRSMatcherKeyBytes)
		}
	}
	if batches != 3 {
		t.Fatalf("got %d domain batches, want 3", batches)
	}
	recovered := Decode(SRS, data)
	if !recovered.Valid || len(recovered.List.Entries) != len(list.Entries) {
		t.Fatalf("reimport got %d entries and issues %v, want %d entries without issues",
			len(recovered.List.Entries), recovered.Issues, len(list.Entries))
	}
	got := make(map[Entry]bool, len(list.Entries))
	for _, entry := range recovered.List.Entries {
		got[entry] = true
	}
	for _, entry := range list.Entries {
		if !got[entry] {
			t.Errorf("reimport lost %+v", entry)
		}
	}
}

func TestSRSExportRejectsOversizedCompressedFile(t *testing.T) {
	// High-entropy domains fit the entry, matcher and decompressed budgets,
	// but their encoded output cannot fit the upload budget.
	data, _, err := Encode(SRS, List{Entries: srsTestDomains(16_000)})
	if len(data) != 0 || err == nil || !strings.Contains(err.Error(), "SRS encoded file exceeds") {
		t.Fatalf("unimportable SRS: got %d bytes and error %v", len(data), err)
	}
}

func srsTestDomains(count int) []Entry {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	random := rand.New(rand.NewPCG(21, 26))
	entries := make([]Entry, count)
	for i := range entries {
		var domain [maxSuffixBytes]byte
		for at := range domain {
			if (at+1)%64 == 0 {
				domain[at] = '.'
			} else {
				domain[at] = alphabet[random.IntN(len(alphabet))]
			}
		}
		entries[i] = Entry{Type: DomainSuffix, Value: string(domain[:])}
	}
	return entries
}

func TestSRSPreflightValidation(t *testing.T) {
	valid := packSRSTestBody(t, 2, []byte{0})
	// Each synthetic bitmap encodes a parent with out-degree from the LOUDS
	// bit stream, followed by the BFS labels. These are format unit fixtures.
	rootLeaf := srsTestTrie(3, 0b110, []byte("a"))
	deadBranch := srsTestTrie(6, 0b11001, []byte("ab"))
	duplicateSibling := srsTestTrie(6, 0b11100, []byte("aa"))
	misplacedMarker := srsTestTrie(2, 0b110, []byte{'\r'})
	badRange := srsTestRange([]byte{192, 0, 2, 2}, []byte{192, 0, 2, 1})
	mixedRange := srsTestRange([]byte{192, 0, 2, 1}, make([]byte, 16))
	for _, tc := range []struct {
		name, location string
		file           []byte
	}{
		{"bad magic", "file", []byte("BAD\x02")},
		{"unsupported version", "version", packSRSTestBody(t, 6, []byte{0})},
		{"truncated stream", "file", valid[:len(valid)-1]},
		{"extra stream", "file", append(bytes.Clone(valid), valid[4:]...)},
		{"extra body", "file", packSRSTestBody(t, 2, []byte{0, 0})},
		{"many rules", "rules", packSRSTestBody(t, 2, binary.AppendUvarint(nil, MaxEntries+1))},
		{"excess inflated bytes", "file", packSRSTestBody(t, 2, make([]byte, maxSRSBodyBytes+1))},
		{"logical rule", "rules[0].type", packSRSTestBody(t, 2, []byte{1, 1})},
		{"inverted rule", "rules[0].invert", packSRSTestBody(t, 2, srsTestRule(6, srsTestRange([]byte{192, 0, 2, 1}, []byte{192, 0, 2, 1}), 1))},
		{"unknown predicate", "rules[0].items[0]", packSRSTestBody(t, 2, []byte{1, 0, 0xFE})},
		{"known unsupported predicate", "rules[0].source_ip_cidr", packSRSTestBody(t, 2, []byte{1, 0, 5})},
		{"empty rule", "rules[0]", packSRSTestBody(t, 2, []byte{1, 0, 0xFF, 0})},
		{"empty trie key", "rules[0].domain", packSRSTestBody(t, 2, srsTestRule(2, rootLeaf, 0))},
		{"disconnected trie", "rules[0].domain", packSRSTestBody(t, 2, srsTestRule(2, deadBranch, 0))},
		{"duplicate trie edge", "rules[0].domain", packSRSTestBody(t, 2, srsTestRule(2, duplicateSibling, 0))},
		{"misplaced prefix marker", "rules[0].domain", packSRSTestBody(t, 2, srsTestRule(2, misplacedMarker, 0))},
		{"descending IP range", "rules[0].ip_cidr", packSRSTestBody(t, 2, srsTestRule(6, badRange, 0))},
		{"IP prefix expansion limit", "rules[0].ip_cidr", packSRSTestBody(t, 2, srsTestRule(6, srsTestExpandingRanges(), 0))},
		{"mixed-family IP range", "rules[0].ip_cidr", packSRSTestBody(t, 2, srsTestRule(6, mixedRange, 0))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Decode(SRS, tc.file)
			if got.Valid || len(got.Issues) == 0 || got.Issues[0].Location != tc.location {
				t.Fatalf("expected rejection at %s, got %+v", tc.location, got)
			}
		})
	}
}

func TestSRSTrieDepthLimit(t *testing.T) {
	var buf bytes.Buffer
	rules := option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: "default", DefaultOptions: option.DefaultHeadlessRule{
		DomainSuffix: []string{strings.Repeat("a", maxSRSKeyDepth) + ".test"},
	}}}}
	if err := srs.Write(&buf, rules, 2); err != nil {
		t.Fatal(err)
	}
	got := Decode(SRS, buf.Bytes())
	if got.Valid || len(got.Issues) == 0 || got.Issues[0].Location != "rules[0].domain" {
		t.Fatalf("expected an oversized trie rejection, got %+v", got)
	}
}

func srsTestExpandingRanges() []byte {
	// In each distinct /64, exclude the first and last address. This needs
	// 126 CIDR prefixes per range, even though the input only stores endpoints.
	const count = MaxEntries/126 + 1
	data := binary.BigEndian.AppendUint64([]byte{1}, count)
	for i := range count {
		from := [16]byte{0x20, 1, 0x0d, 0xb8, byte(i >> 8), byte(i)}
		to := from
		from[15] = 1
		binary.BigEndian.PutUint64(to[8:], ^uint64(1))
		data = append(append(data, 16), from[:]...)
		data = append(append(data, 16), to[:]...)
	}
	return data
}

func packSRSTestBody(t *testing.T, version byte, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("SRS")
	buf.WriteByte(version)
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func srsTestRule(item byte, data []byte, invert byte) []byte {
	body := append([]byte{1, 0, item}, data...)
	return append(body, 0xFF, invert)
}

func srsTestTrie(leaves, degree uint64, labels []byte) []byte {
	trie := binary.BigEndian.AppendUint64([]byte{0, 1}, leaves)
	trie = binary.BigEndian.AppendUint64(append(trie, 1), degree)
	return append(append(trie, byte(len(labels))), labels...)
}

func srsTestRange(from, to []byte) []byte {
	ipSet := binary.BigEndian.AppendUint64([]byte{1}, 1)
	ipSet = append(append(ipSet, byte(len(from))), from...)
	return append(append(ipSet, byte(len(to))), to...)
}
