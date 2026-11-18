package resourceexchange

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	"go4.org/netipx"
)

const (
	maxSRSBodyBytes = 7 << 20
	maxSRSKeyDepth  = maxSuffixBytes + 2 // optional leading dot and matcher marker
	maxSRSRawKeys   = MaxEntries * 2     // v1 suffixes may use two keys per entry

	// The pinned writer keeps a three-int queue entry per trie node. Bounded
	// key bytes bound the node count (one per byte, plus the root), even
	// for suffixes that share few trie edges.
	maxSRSMatcherKeyBytes = 128 << 10

	srsDomainItem = 2
	srsIPItem     = 6
	srsFinalItem  = 0xFF

	srsPrefixLabel = '\r'
	srsRootLabel   = '\n'
)

func decodeSRS(data []byte, collector *decoder) {
	if issue := preflightSRS(data); issue != nil {
		issue.report(collector)
		return
	}
	decoded, err := srs.Read(bytes.NewReader(data), true)
	if err != nil {
		collector.issue("file", "error", "cannot read SRS rules")
		return
	}
	var terms []singBoxTerm
	for ruleIndex, rule := range decoded.Options.Rules {
		for _, predicate := range [...]struct {
			field  string
			values []string
		}{
			{singBoxDomain, rule.DefaultOptions.Domain},
			{singBoxSuffix, rule.DefaultOptions.DomainSuffix},
			{singBoxCIDR, rule.DefaultOptions.IPCIDR},
		} {
			if len(predicate.values) > MaxEntries-len(terms) {
				collector.issue(ruleSetLocation(ruleIndex), "error", "too many recovered predicate values")
				return
			}
			for i, value := range predicate.values {
				terms = append(terms, singBoxTerm{predicate.field, value, ruleIndex, i})
			}
		}
	}
	collectSingBoxTerms(terms, collector)
}

func encodeSRS(list List) ([]byte, error) {
	rules, err := planSRSRules(list)
	if err != nil {
		return nil, err
	}
	var out srsExportBuffer
	if err := srs.Write(&out, rules, singBoxExportVersion); err != nil {
		return nil, err
	}
	return out.data.Bytes(), nil
}

// Plan only rules that recover one predicate per entry. Every nonempty rule
// consumes at least one of those entries, so the rule, key, and expanded prefix
// counts also fit the importer limits.
func planSRSRules(list List) (option.PlainRuleSet, error) {
	domains, addresses := splitSingBoxEntries(list)
	// All batches but the last fit at least this many maximum-sized v2 keys.
	const minBatchKeys = maxSRSMatcherKeyBytes / (maxSuffixBytes + 1)
	rules := make([]option.HeadlessRule, 0, len(addresses)+(len(domains)+minBatchKeys-1)/minBatchKeys)
	// Count the rule array header, and for each singleton IP rule count its
	// four rule framing bytes, IP set version, uint64 count, and two endpoints
	// (each at most one length byte and 16 address bytes).
	bodyBytes := binary.MaxVarintLen64 + len(addresses)*(4+1+8+2*(1+16))
	start, keyBytes := 0, 0
	for i, domain := range domains {
		size := len(domain) + 1 // one root marker per bare suffix in SRS v2
		if keyBytes+size > maxSRSMatcherKeyBytes {
			rules = append(rules, srsDomainRule(domains[start:i:i]))
			bodyBytes += srsDomainBodyBound(keyBytes)
			start, keyBytes = i, 0
		}
		keyBytes += size
	}
	if keyBytes != 0 {
		rules = append(rules, srsDomainRule(domains[start:len(domains):len(domains)]))
		bodyBytes += srsDomainBodyBound(keyBytes)
	}
	if bodyBytes > maxSRSBodyBytes {
		return option.PlainRuleSet{}, fmt.Errorf("SRS decompressed body exceeds %d bytes", maxSRSBodyBytes)
	}
	// SRS coalesces adjacent or overlapping prefixes within each rule. One
	// prefix per rule preserves distinct editable entries as well as the union.
	for i := range addresses {
		rules = append(rules, option.HeadlessRule{Type: "default", DefaultOptions: option.DefaultHeadlessRule{IPCIDR: addresses[i : i+1 : i+1]}})
	}
	return option.PlainRuleSet{Rules: rules}, nil
}

func srsDomainRule(suffixes []string) option.HeadlessRule {
	return option.HeadlessRule{Type: "default", DefaultOptions: option.DefaultHeadlessRule{DomainSuffix: suffixes}}
}

func srsDomainBodyBound(keyBytes int) int {
	// At most one edge per key byte, one node per edge plus the root.
	// The wire format has four rule framing bytes, one matcher version byte,
	// and three length-prefixed slices: two uint64 bitmaps and edge labels.
	nodes := keyBytes + 1
	return 4 + 1 + 3*binary.MaxVarintLen64 + keyBytes + 8*((nodes+63)/64+(2*nodes-1+63)/64)
}

// The compressed length depends on the actual keys, so enforce the separate
// file budget at write time without buffering a file too large to reimport.
type srsExportBuffer struct{ data bytes.Buffer }

func (b *srsExportBuffer) Write(p []byte) (int, error) {
	if len(p) > MaxFileBytes-b.data.Len() {
		return 0, fmt.Errorf("SRS encoded file exceeds %d bytes", MaxFileBytes)
	}
	return b.data.Write(p)
}

// The pinned codec does not require stream EOF or validate trie topology or
// IP-set invariants before recovery. Walk only the accepted wire subset first,
// bounding both the inflater and everything recovery can expand. This guard
// does not recover matcher keys or interpret rule semantics.
func preflightSRS(data []byte) *ruleSetInputError {
	if len(data) < 4 || !bytes.Equal(data[:3], srs.MagicBytes[:]) {
		return invalidRuleSet("file", "invalid SRS header")
	}
	if !supportedRuleSetVersion(int64(data[3])) {
		return unsupportedRuleSet("version", "supported rule-set versions are 1–5")
	}
	compressed := bytes.NewReader(data[4:])
	inflater, err := zlib.NewReader(compressed)
	if err != nil {
		return invalidRuleSet("file", "invalid zlib stream")
	}
	defer inflater.Close()
	body, err := io.ReadAll(io.LimitReader(inflater, maxSRSBodyBytes+1))
	if len(body) > maxSRSBodyBytes {
		return invalidRuleSet("file", "SRS decompression limit exceeded")
	}
	if err != nil || compressed.Len() != 0 {
		return invalidRuleSet("file", "invalid zlib stream or trailing compressed data")
	}
	guard := srsGuard{body: body}
	return guard.read()
}

type srsGuard struct {
	body       []byte
	keys       int
	ipPrefixes int
}

func (g *srsGuard) take(n int) ([]byte, bool) {
	if n > len(g.body) {
		return nil, false
	}
	data := g.body[:n]
	g.body = g.body[n:]
	return data, true
}

func (g *srsGuard) readByte() (byte, bool) {
	data, ok := g.take(1)
	if !ok {
		return 0, false
	}
	return data[0], true
}

func (g *srsGuard) readCount(max int) (int, bool) {
	value, n := binary.Uvarint(g.body)
	if n <= 0 || value > uint64(max) {
		return 0, false
	}
	g.body = g.body[n:]
	return int(value), true
}

func (g *srsGuard) read() *ruleSetInputError {
	count, ok := g.readCount(MaxEntries)
	if !ok {
		return invalidRuleSet("rules", "invalid or excessive SRS rule count")
	}
	for index := range count {
		if issue := g.readRule(ruleSetLocation(index)); issue != nil {
			return issue
		}
	}
	if len(g.body) != 0 {
		return invalidRuleSet("file", "unexpected data after the SRS rule array")
	}
	return nil
}

func (g *srsGuard) readRule(location string) *ruleSetInputError {
	ruleType, ok := g.readByte()
	if !ok {
		return invalidRuleSet(location, "missing SRS rule type")
	}
	if ruleType != 0 {
		return unsupportedRuleSet(location+".type", "only default SRS rules are supported")
	}
	var haveDomain, haveIP bool
	for index := 0; ; index++ {
		item, ok := g.readByte()
		if !ok {
			return invalidRuleSet(location, "missing SRS rule terminator")
		}
		switch item {
		case srsDomainItem:
			path := location + ".domain"
			if haveDomain {
				return invalidRuleSet(path, "duplicate SRS domain matcher")
			}
			haveDomain = true
			if err := g.checkTrie(); err != nil {
				return invalidRuleSet(path, err.Error())
			}
		case srsIPItem:
			path := location + ".ip_cidr"
			if haveIP {
				return invalidRuleSet(path, "duplicate SRS IP set")
			}
			haveIP = true
			if err := g.checkIPSet(); err != nil {
				return invalidRuleSet(path, err.Error())
			}
		case srsFinalItem:
			invert, ok := g.readByte()
			switch {
			case !ok || invert > 1:
				return invalidRuleSet(location+".invert", "invalid SRS inversion flag")
			case invert == 1:
				return unsupportedRuleSet(location+".invert", "inverted SRS rules are not supported")
			case !haveDomain && !haveIP:
				return invalidRuleSet(location, "rule must contain at least one predicate")
			}
			return nil
		default:
			path := fmt.Sprintf("%s.items[%d]", location, index)
			if int(item) < len(srsItemNames) {
				path = location + "." + srsItemNames[item]
			}
			return unsupportedRuleSet(path, fmt.Sprintf("unsupported SRS rule item %d", item))
		}
	}
}

// Item numbers in pinned sing-box/common/srs/binary.go. Unknown item payloads
// cannot be skipped: they are rejected without being handed to the codec.
var srsItemNames = [...]string{
	"query_type", "network", "domain", "domain_keyword", "domain_regex", "source_ip_cidr", "ip_cidr",
	"source_port", "source_port_range", "port", "port_range", "process_name", "process_path", "package_name",
	"wifi_ssid", "wifi_bssid", "adguard", "process_path_regex", "network_type", "network_is_expensive",
	"network_is_constrained", "network_interface_address", "default_interface_address", "package_name_regex",
}

func (g *srsGuard) readSized(width int) ([]byte, bool) {
	count, ok := g.readCount(len(g.body) / width)
	if !ok {
		return nil, false
	}
	return g.take(count * width)
}

func (g *srsGuard) checkTrie() error {
	version, ok := g.readByte()
	if !ok || version != 0 {
		return errors.New("invalid SRS domain matcher version")
	}
	leaves, ok := g.readSized(8)
	if !ok {
		return errors.New("invalid SRS domain leaf bitmap")
	}
	degrees, ok := g.readSized(8)
	if !ok {
		return errors.New("invalid SRS domain edge bitmap")
	}
	labels, ok := g.readSized(1)
	if !ok || len(labels) == 0 {
		return errors.New("missing SRS domain trie labels")
	}
	// LOUDS is breadth-first: each node has one zero per child, then a
	// terminator one. An N-node trie has N-1 labels and 2*N-1 degree bits.
	nodes := len(labels) + 1
	degreeBits := 2*nodes - 1
	if !validSRSBitmap(leaves, nodes) || !validSRSBitmap(degrees, degreeBits) || srsBit(leaves, 0) {
		return errors.New("invalid SRS domain trie bitmaps")
	}
	depth, levelEnd, edges, cursor := 0, 1, 0, 0
	for node := range nodes {
		if node >= levelEnd {
			depth++
			levelEnd = edges + 1
		}
		if depth > maxSRSKeyDepth || node > edges {
			return errors.New("disconnected or too deep SRS domain trie")
		}
		var parent byte
		if node != 0 {
			parent = labels[node-1]
		}
		leaf := srsBit(leaves, node)
		if leaf {
			g.keys++
			if g.keys > maxSRSRawKeys {
				return errors.New("too many SRS domain matcher keys")
			}
		}
		start := edges
		for cursor < degreeBits && !srsBit(degrees, cursor) {
			if edges == len(labels) {
				return errors.New("SRS domain trie has excess edges")
			}
			label := labels[edges]
			// ASCII also guarantees the pinned matcher's reverseDomain never
			// sees an invalid UTF-8 key during recovery.
			if label >= 0x80 || (edges > start && label <= labels[edges-1]) {
				return errors.New("invalid or unordered SRS domain trie labels")
			}
			if (label == srsPrefixLabel && parent != '.') || (label == srsRootLabel && (node == 0 || parent == '.')) {
				return errors.New("invalid SRS suffix marker position")
			}
			edges++
			cursor++
		}
		if cursor == degreeBits || (start == edges && !leaf) {
			return errors.New("unterminated or empty SRS domain trie branch")
		}
		if (parent == srsPrefixLabel || parent == srsRootLabel) && (!leaf || start != edges) {
			return errors.New("SRS suffix marker must terminate a key")
		}
		cursor++
	}
	if edges != len(labels) || cursor != degreeBits {
		return errors.New("invalid SRS domain trie traversal")
	}
	// The global key count and depth also bound Dump's expanded key bytes.
	return nil
}

func validSRSBitmap(data []byte, bits int) bool {
	if len(data) != ((bits+63)/64)*8 {
		return false
	}
	for i := bits; i < len(data)*8; i++ {
		if srsBit(data, i) {
			return false
		}
	}
	return true
}

func srsBit(data []byte, bit int) bool {
	// In each big-endian uint64, LOUDS indexes from the least significant bit.
	return data[bit/64*8+7-bit%64/8]&(1<<uint(bit%8)) != 0
}

func (g *srsGuard) checkIPSet() error {
	version, ok := g.readByte()
	if !ok || version != 1 {
		return errors.New("invalid SRS IP set version")
	}
	data, ok := g.take(8)
	if !ok {
		return errors.New("missing SRS IP range count")
	}
	count := binary.BigEndian.Uint64(data)
	if count == 0 || count > uint64(MaxEntries-g.ipPrefixes) {
		return errors.New("invalid or excessive SRS IP range count")
	}
	var previous netip.Addr
	// One IPv6 range expands to at most 2*128 prefixes. Reuse stack space
	// to count the exact expansion rather than multiplying every range by 256.
	var scratch [256]netip.Prefix
	for range count {
		from := g.readIPAddr()
		to := g.readIPAddr()
		ipRange := netipx.IPRangeFrom(from, to)
		if !ipRange.IsValid() || (previous.IsValid() && !previous.Less(from)) {
			return errors.New("invalid or unordered SRS IP range")
		}
		previous = to
		g.ipPrefixes += len(ipRange.AppendPrefixes(scratch[:0]))
		if g.ipPrefixes > MaxEntries {
			return errors.New("SRS IP ranges expand to too many prefixes")
		}
	}
	return nil
}

func (g *srsGuard) readIPAddr() netip.Addr {
	size, ok := g.readCount(16)
	if !ok || (size != 4 && size != 16) {
		return netip.Addr{}
	}
	data, ok := g.take(size)
	if !ok {
		return netip.Addr{}
	}
	addr, _ := netip.AddrFromSlice(data)
	return addr
}
