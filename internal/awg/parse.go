// Package awg translates a single-peer AmneziaWG .conf into a userspace
// WireGuard endpoint. Profile DNS is validated metadata, never imported policy.
package awg

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Parse validates the complete profile without returning its secrets in errors.
// The caller owns the endpoint tag; the original text belongs only in the model.
func Parse(profile string) (map[string]any, error) {
	if len(profile) > 1<<20 || !utf8.ValidString(profile) || strings.ContainsRune(profile, '\x00') {
		return nil, fmt.Errorf("invalid or oversized AmneziaWG profile")
	}
	p := profileParser{
		endpoint: map[string]any{"type": "wireguard", "system": false},
		peer:     map[string]any{"allowed_ips": []string{"0.0.0.0/0", "::/0"}},
		seen:     map[string]bool{},
	}
	index := 0
	for raw := range strings.SplitSeq(strings.TrimPrefix(profile, "\uFEFF"), "\n") {
		index++
		if err := p.line(raw); err != nil {
			return nil, fmt.Errorf("line %d: %w", index, err)
		}
	}
	return p.finish()
}

// profileParser owns one parse; sections cannot reopen or cross peer boundaries.
type profileParser struct {
	endpoint map[string]any
	peer     map[string]any
	seen     map[string]bool
	section  string
}

func (p *profileParser) line(raw string) error {
	line, _, _ := strings.Cut(raw, "#")
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if strings.HasPrefix(line, "[") {
		return p.startSection(strings.ToLower(line))
	}
	name, value, ok := strings.Cut(line, "=")
	name = strings.ToLower(strings.TrimSpace(name))
	if !ok || p.section == "" || name == "" {
		return fmt.Errorf("expected a field inside a section")
	}
	id := p.section + name
	if p.seen[id] {
		return fmt.Errorf("duplicate profile field")
	}
	p.seen[id] = true
	value = strings.TrimSpace(value)
	if p.section == "[interface]" {
		return interfaceField(p.endpoint, name, value)
	}
	return peerField(p.peer, name, value)
}

func (p *profileParser) startSection(name string) error {
	switch name {
	case "[interface]":
		if p.section == "" {
			p.section = name
			return nil
		}
	case "[peer]":
		if p.section == "[interface]" {
			p.section = name
			return nil
		}
	}
	return fmt.Errorf("expected one Interface followed by one Peer section")
}

func (p *profileParser) finish() (map[string]any, error) {
	if p.section != "[peer]" || p.endpoint["private_key"] == nil || p.endpoint["address"] == nil || p.peer["public_key"] == nil || p.peer["address"] == nil {
		return nil, fmt.Errorf("profile requires Interface PrivateKey and Address, and one Peer PublicKey and Endpoint")
	}
	if err := validateOptions(p.endpoint); err != nil {
		return nil, err
	}
	p.endpoint["peers"] = []map[string]any{p.peer}
	return p.endpoint, nil
}

func interfaceField(ep map[string]any, name, value string) error {
	if name == "dns" {
		return dnsMetadata(value)
	}
	out, parsed, err := interfaceValue(name, value)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", out, err)
	}
	ep[out] = parsed
	return nil
}

func interfaceValue(name, value string) (string, any, error) {
	var parsed any
	var err error
	out := name
	switch name {
	case "privatekey", "headerprotectionkey":
		out = profileFieldNames[name]
		parsed, err = parseKey(value)
	case "address":
		parsed, err = prefixes(value)
	case "listenport":
		out = "listen_port"
		parsed, err = number(value, 16)
	case "mtu":
		parsed, err = mtuValue(value)
	default:
		return awgValue(name, value)
	}
	return out, parsed, err
}

func mtuValue(value string) (uint64, error) {
	n, err := number(value, 16)
	if err != nil {
		return 0, err
	}
	if n < 68 {
		return 0, fmt.Errorf("MTU must be at least 68")
	}
	return n, nil
}

// DNS is accepted only as metadata; awg-quick cannot replace router DNS policy.
func dnsMetadata(value string) error {
	for item := range strings.SplitSeq(value, ",") {
		item = strings.TrimSpace(item)
		ip, err := netip.ParseAddr(item)
		if (err != nil && !hostname(item)) || (err == nil && ip.Zone() != "") {
			return fmt.Errorf("invalid DNS metadata")
		}
	}
	return nil
}

var profileFieldNames = map[string]string{
	"privatekey": "private_key", "headerprotectionkey": "header_protection_key",
	"publickey": "public_key", "presharedkey": "pre_shared_key",
	"contentpaddingaddition": "content_padding_addition", "rekeyaftertime": "rekey_after_time",
	"rekeytimeout": "rekey_timeout", "rejectaftertime": "reject_after_time",
	"keepalivetimeout": "keepalive_timeout", "maxhandshakeattempts": "max_handshake_attempts",
	"randomtrailers": "random_trailers", "disablecookies": "disable_cookies",
}

func awgValue(name, value string) (string, any, error) {
	var parsed any
	var err error
	out := name
	switch name {
	case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4":
		parsed, err = number(value, 16)
	case "h1", "h2", "h3", "h4":
		parsed, err = parseRange(value, 32)
	case "i1", "i2", "i3", "i4", "i5":
		parsed, err = cps(value)
	case "contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts":
		out = profileFieldNames[name]
		parsed, err = parseRange(value, 16)
	case "randomtrailers", "disablecookies":
		out = profileFieldNames[name]
		parsed, err = boolean(value)
	default:
		return "Interface field", nil, fmt.Errorf("unsupported option (hooks and routing directives are not imported)")
	}
	return out, parsed, err
}

func peerField(peer map[string]any, name, value string) error {
	if name == "endpoint" {
		return peerEndpoint(peer, value)
	}
	if name == "advancedsecurity" {
		// Official exports assert AWG on the peer; do not discard a false assertion.
		enabled, err := boolean(value)
		if err != nil || !enabled {
			return fmt.Errorf("AdvancedSecurity must be true for AmneziaWG")
		}
		return nil
	}
	out, parsed, err := peerValue(name, value)
	if err != nil {
		return fmt.Errorf("invalid peer %s: %w", out, err)
	}
	peer[out] = parsed
	return nil
}

func peerValue(name, value string) (string, any, error) {
	var parsed any
	var err error
	out := name
	switch name {
	case "publickey", "presharedkey":
		out = profileFieldNames[name]
		parsed, err = parseKey(value)
	case "allowedips":
		out = "allowed_ips"
		parsed, err = prefixes(value)
	case "persistentkeepalive":
		out = "persistent_keepalive_interval"
		if strings.EqualFold(value, "off") {
			value = "0"
		}
		parsed, err = parseRange(value, 16)
	default:
		return "Peer field", nil, fmt.Errorf("unsupported option")
	}
	return out, parsed, err
}

func peerEndpoint(peer map[string]any, value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid peer Endpoint")
	}
	if ip, err := netip.ParseAddr(host); err != nil {
		if !hostname(host) {
			return fmt.Errorf("invalid peer Endpoint host")
		}
	} else if ip.Zone() != "" {
		return fmt.Errorf("scoped peer Endpoint is unsupported")
	}
	p, err := number(port, 16)
	if err != nil || p == 0 {
		return fmt.Errorf("invalid peer Endpoint port")
	}
	peer["address"], peer["port"] = host, p
	return nil
}

func parseKey(value string) (string, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		return "", fmt.Errorf("expected a base64 32-byte key")
	}
	return value, nil
}

func prefixes(value string) ([]string, error) {
	items := strings.Split(value, ",")
	for i, item := range items {
		p, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil || p.Addr().Zone() != "" {
			return nil, fmt.Errorf("expected comma-separated IP prefixes")
		}
		items[i] = p.String()
	}
	return items, nil
}

func hostname(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	value = strings.TrimSuffix(value, ".")
	if strings.Trim(value, "0123456789.") == "" {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if !hostnameLabel(label) {
			return false
		}
	}
	return true
}

func hostnameLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if !hostnameCharacter(c) {
			return false
		}
	}
	return true
}

func hostnameCharacter(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

func number(value string, bits int) (uint64, error) {
	if value == "" {
		return 0, fmt.Errorf("expected an unsigned integer")
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("expected an unsigned integer")
		}
	}
	n, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("integer exceeds %d-bit range", bits)
	}
	return n, nil
}

func parseRange(value string, bits int) (any, error) {
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return nil, fmt.Errorf("expected an integer or min-max range")
	}
	lo, err := number(strings.TrimSpace(parts[0]), bits)
	if err != nil {
		return nil, err
	}
	if len(parts) == 1 {
		return lo, nil
	}
	hi, err := number(strings.TrimSpace(parts[1]), bits)
	if err != nil {
		return nil, err
	}
	if hi < lo {
		return nil, fmt.Errorf("range minimum exceeds maximum")
	}
	return strconv.FormatUint(lo, 10) + "-" + strconv.FormatUint(hi, 10), nil
}

func boolean(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("expected true or false")
	}
}

func cps(value string) (string, error) {
	rest := strings.TrimSpace(value)
	size := uint64(0)
	for rest != "" {
		if rest[0] != '<' {
			return "", fmt.Errorf("invalid CPS packet")
		}
		end := strings.IndexByte(rest, '>')
		if end < 0 {
			return "", fmt.Errorf("unterminated CPS tag")
		}
		n, err := cpsTag(strings.Fields(rest[1:end]))
		if err != nil {
			return "", err
		}
		size += n
		if size > 65507 {
			return "", fmt.Errorf("CPS packet exceeds UDP payload limit")
		}
		rest = strings.TrimSpace(rest[end+1:])
	}
	return value, nil
}

func cpsTag(fields []string) (uint64, error) {
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty CPS tag")
	}
	switch fields[0] {
	case "t", "d", "ds":
		if len(fields) != 1 {
			return 0, fmt.Errorf("invalid CPS data tag")
		}
		if fields[0] == "t" {
			return 4, nil
		}
		return 0, nil
	case "b":
		return cpsBytes(fields)
	case "r", "rc", "rd", "dz":
		if len(fields) != 2 {
			return 0, fmt.Errorf("invalid CPS random tag")
		}
		return number(fields[1], 16)
	default:
		return 0, fmt.Errorf("unsupported CPS tag")
	}
}

func cpsBytes(fields []string) (uint64, error) {
	if len(fields) != 2 || !strings.HasPrefix(fields[1], "0x") {
		return 0, fmt.Errorf("invalid CPS bytes")
	}
	// Validation needs only the encoded size, not an allocated packet.
	value := fields[1][2:]
	if len(value) == 0 || len(value)%2 != 0 {
		return 0, fmt.Errorf("invalid CPS hex bytes")
	}
	for _, c := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return 0, fmt.Errorf("invalid CPS hex bytes")
		}
	}
	return uint64(len(value) / 2), nil
}

func bounds(value any, fallback uint64) (uint64, uint64) {
	if value == nil || value == uint64(0) {
		return fallback, fallback
	}
	if n, ok := value.(uint64); ok {
		return n, n
	}
	parts := strings.Split(value.(string), "-")
	lo, _ := strconv.ParseUint(parts[0], 10, 32)
	hi, _ := strconv.ParseUint(parts[1], 10, 32)
	if hi == 0 {
		return fallback, fallback
	}
	return lo, hi
}

func validateOptions(ep map[string]any) error {
	jmin, _ := bounds(ep["jmin"], 0)
	jmax, _ := bounds(ep["jmax"], 0)
	if jmin > jmax {
		return fmt.Errorf("Jmin exceeds Jmax")
	}
	if err := validateJunk(ep); err != nil {
		return err
	}
	for i := 1; i <= 4; i++ {
		lo, hi := bounds(ep[fmt.Sprintf("h%d", i)], uint64(i))
		for j := 1; j < i; j++ {
			otherLo, otherHi := bounds(ep[fmt.Sprintf("h%d", j)], uint64(j))
			if lo <= otherHi && otherLo <= hi {
				return fmt.Errorf("H1-H4 ranges must not overlap, including default headers")
			}
		}
		if ep["header_protection_key"] != nil {
			padding, _ := bounds(ep[fmt.Sprintf("s%d", i)], 0)
			if padding < 12 {
				return fmt.Errorf("HeaderProtectionKey requires S1-S4 to be at least 12")
			}
		}
	}
	return nil
}

// MaxJunkPackets and MaxJunkPayload bound one handshake burst. The embedded
// device allocates every junk datagram before the handshake and copies that
// burst again; a swapped Jmin/Jmax is used at the larger size. A uint16 pair
// is otherwise about 4 GiB. Unset Jc sends no junk. Unset sizes are zero-size
// packets and still count toward the packet cap. Over-budget values are
// rejected, not clamped.
const (
	MaxJunkPackets = 256
	MaxJunkPayload = 1 << 20
)

// JunkBudget is the handshake allocation cap. count is Jc. maxSize is the
// larger of Jmin and Jmax after the device's swap.
func JunkBudget(count, maxSize uint64) error {
	if count > MaxJunkPackets || junkPayloadExceeds(count, maxSize) {
		return fmt.Errorf("junk packet burst exceeds %d packets or %d bytes per handshake", MaxJunkPackets, MaxJunkPayload)
	}
	return nil
}

// DeviceJunkBudget applies JunkBudget the way device.JunkPackets allocates:
// when Jmax is below Jmin, including a zero or omitted Jmax, the larger size is used.
func DeviceJunkBudget(count, minSize, maxSize uint64) error {
	if maxSize < minSize {
		maxSize = minSize
	}
	return JunkBudget(count, maxSize)
}

func validateJunk(ep map[string]any) error {
	count, _ := ep["jc"].(uint64)
	minSize, _ := ep["jmin"].(uint64)
	maxSize, _ := ep["jmax"].(uint64)
	return DeviceJunkBudget(count, minSize, maxSize)
}

func junkPayloadExceeds(count, maxSize uint64) bool {
	if count == 0 || maxSize == 0 {
		return false
	}
	return count > MaxJunkPayload/maxSize
}
