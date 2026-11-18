// Package resourceexchange converts portable resource lists without importing routing policy.
package resourceexchange

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// Format identifies the explicitly selected wire format of a resource list.
type Format string

const (
	Text    Format = "txt"
	CSV     Format = "csv"
	JSON    Format = "json"
	SingBox Format = "sing-box-json"
	SRS     Format = "srs"
)

const (
	DomainSuffix = "domain_suffix"
	IPCIDR       = "ip_cidr"
)

const (
	MaxFileBytes = 2 << 20
	MaxEntries   = 20_000

	maxNameBytes          = 1024
	maxSuffixBytes        = 253
	maxValueBytes         = 1024
	maxIssues             = 100
	maxIssueLocationBytes = 256
	maxIssueMessageBytes  = 512
)

// Entry combines a match with activation state, not a target or other config.
type Entry struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Disabled bool   `json:"disabled,omitempty"`
}

// List is the portable subset shared by groups and presets.
type List struct {
	Name    string  `json:"name,omitempty"`
	Entries []Entry `json:"entries"`
}

// Issue marks an invalid or unsupported part of the source file.
type Issue struct {
	Location string `json:"location"`
	Message  string `json:"message"`
	Kind     string `json:"kind"`
}

// Preview can retain recognized entries from an invalid file, but only a valid
// preview represents an importable list in full.
type Preview struct {
	List          List    `json:"list"`
	Issues        []Issue `json:"issues"`
	OmittedIssues int     `json:"omitted_issues"`
	Duplicates    int     `json:"duplicates"`
	Valid         bool    `json:"valid"`
}

// Decode validates a complete list using the caller's format, never sniffing it.
func Decode(format Format, data []byte) Preview {
	d := decoder{preview: Preview{List: List{Entries: []Entry{}}, Issues: []Issue{}, Valid: true}}
	if len(data) > MaxFileBytes {
		d.issue("file", "error", fmt.Sprintf("file exceeds %d bytes", MaxFileBytes))
		return d.preview
	}
	if format != SRS {
		data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
		if !utf8.Valid(data) {
			d.issue("file", "error", "invalid UTF-8")
			return d.preview
		}
	}
	switch format {
	case Text:
		decodeText(data, &d)
	case CSV:
		decodeCSV(data, &d)
	case JSON:
		decodeKeenJSON(data, &d)
	case SingBox:
		decodeSingBox(data, &d)
	case SRS:
		decodeSRS(data, &d)
	default:
		d.issue("file", "error", "unknown resource list format")
	}
	return d.preview
}

// Encode revalidates typed entries and describes metadata or activation loss.
// Formats without activation never receive disabled entries as active matches.
func Encode(format Format, list List) (data []byte, losses []string, err error) {
	var encode func(List) ([]byte, error)
	switch format {
	case Text:
		encode = encodeText
	case CSV:
		encode = encodeCSV
	case JSON:
		encode = encodeKeenJSON
	case SingBox:
		encode = encodeSingBox
	case SRS:
		encode = encodeSRS
	default:
		return nil, nil, errors.New("unknown resource list format")
	}
	if len(list.Entries) > MaxEntries {
		return nil, nil, fmt.Errorf("list exceeds %d entries", MaxEntries)
	}
	keepMetadata := format == JSON
	if keepMetadata {
		if err := validateName(list.Name); err != nil {
			return nil, nil, err
		}
	}
	normalized := List{Entries: make([]Entry, 0, len(list.Entries))}
	if keepMetadata {
		normalized.Name = list.Name
	} else if list.Name != "" {
		losses = append(losses, "The list name is not represented in this format.")
	}
	seen := make(entryStates, len(list.Entries))
	omittedDisabled := false
	for i, raw := range list.Entries {
		entry, err := Canonical(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("entries[%d]: %w", i, err)
		}
		duplicate, err := seen.insert(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("entries[%d]: %w", i, err)
		}
		if duplicate {
			continue
		}
		if !keepMetadata && entry.Disabled {
			omittedDisabled = true
			continue
		}
		normalized.Entries = append(normalized.Entries, entry)
	}
	if omittedDisabled {
		losses = append(losses, "Disabled entries are omitted in this format.")
	}
	data, err = encode(normalized)
	if err != nil {
		return nil, nil, err
	}
	if len(data) > MaxFileBytes {
		return nil, nil, fmt.Errorf("encoded file exceeds %d bytes", MaxFileBytes)
	}
	return data, losses, nil
}

// Canonical normalizes a value with the routing model, then verifies its
// explicit type. A typed entry never falls back to the other match kind.
func Canonical(entry Entry) (Entry, error) {
	if entry.Type != DomainSuffix && entry.Type != IPCIDR {
		return Entry{}, errors.New("type must be domain_suffix or ip_cidr")
	}
	parsed, err := parseResource(entry.Value)
	if err != nil {
		return Entry{}, err
	}
	if parsed.Type != entry.Type {
		return Entry{}, fmt.Errorf("value does not match type %s", entry.Type)
	}
	parsed.Disabled = entry.Disabled
	return parsed, nil
}

func parseResource(value string) (Entry, error) {
	if len(value) > maxValueBytes {
		return Entry{}, fmt.Errorf("value exceeds %d bytes", maxValueBytes)
	}
	if !utf8.ValidString(value) || strings.ContainsAny(value, "#\r\n") {
		return Entry{}, errors.New("value must be one UTF-8 entry without a comment")
	}
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "*") && !strings.HasPrefix(value, "*.") {
		return Entry{}, errors.New("wildcard must be followed by a dot")
	}
	// ParseEntry converts addresses to prefixes, which would silently strip
	// an interface zone from a scoped IPv6 address.
	if strings.Contains(value, "%") {
		return Entry{}, errors.New("IP address must not include a zone")
	}
	parsed, err := model.ParseEntry(value)
	if err != nil {
		// Model errors may include the raw entry. Do not reflect file contents.
		return Entry{}, errors.New("expected a domain suffix, IP address, or CIDR prefix")
	}
	if parsed.Kind == model.EntryPrefix {
		// Don't retain an invalid prefix even if the routing parser succeeded.
		if !parsed.Prefix.IsValid() {
			return Entry{}, errors.New("invalid IP prefix")
		}
		return Entry{Type: IPCIDR, Value: parsed.String()}, nil
	}
	if !validSuffix(parsed.Domain) {
		return Entry{}, errors.New("invalid domain suffix")
	}
	// Drafts store only the canonical string. A wildcard, leading dot, or
	// IDNA normalization can turn a domain spelling into a bare IP address.
	if _, err := netip.ParseAddr(parsed.Domain); err == nil {
		return Entry{}, errors.New("domain suffix normalizes to an IP address")
	}
	return Entry{Type: DomainSuffix, Value: parsed.String()}, nil
}

func validSuffix(domain string) bool {
	if len(domain) > maxSuffixBytes {
		return false
	}
	for label := range strings.SplitSeq(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			b := label[i]
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	return true
}

func validateName(name string) error {
	if len(name) > maxNameBytes {
		return fmt.Errorf("name exceeds %d bytes", maxNameBytes)
	}
	if !utf8.ValidString(name) {
		return errors.New("name must be UTF-8")
	}
	return nil
}

type entryKey struct{ kind, value string }
type entryStates map[entryKey]bool

func (s entryStates) insert(entry Entry) (duplicate bool, err error) {
	key := entryKey{kind: entry.Type, value: entry.Value}
	if disabled, ok := s[key]; ok {
		if disabled != entry.Disabled {
			return true, errors.New("duplicate entry has conflicting disabled state")
		}
		return true, nil
	}
	s[key] = entry.Disabled
	return false, nil
}

type decoder struct {
	preview   Preview
	seen      entryStates
	count     int
	overLimit bool
}

// reserve counts attempted rows, not just unique valid entries. It tells a
// streaming adapter to stop before parsing the next entry beyond the limit.
func (d *decoder) reserve(location string) bool {
	if d.count == MaxEntries {
		if !d.overLimit {
			d.issue(location, "error", fmt.Sprintf("file exceeds %d entries", MaxEntries))
			d.overLimit = true
		}
		return false
	}
	d.count++
	return true
}

func (d *decoder) add(location string, entry Entry) {
	if d.reserve(location) {
		d.addTyped(location, entry)
	}
}

func (d *decoder) addTyped(location string, entry Entry) {
	parsed, err := Canonical(entry)
	d.collect(location, parsed, err)
}

func (d *decoder) collect(location string, entry Entry, err error) {
	if err != nil {
		d.issue(location, "error", err.Error())
		return
	}
	if d.seen == nil {
		d.seen = make(entryStates)
	}
	duplicate, err := d.seen.insert(entry)
	if duplicate {
		d.preview.Duplicates++
		if err != nil {
			d.issue(location, "error", err.Error())
		}
		return
	}
	d.preview.List.Entries = append(d.preview.List.Entries, entry)
}

func (d *decoder) issue(location, kind, message string) {
	d.preview.Valid = false
	if len(d.preview.Issues) == maxIssues {
		d.preview.OmittedIssues++
		return
	}
	d.preview.Issues = append(d.preview.Issues, Issue{
		Location: boundDiagnostic(location, maxIssueLocationBytes),
		Kind:     kind,
		Message:  boundDiagnostic(message, maxIssueMessageBytes),
	})
}

func boundDiagnostic(s string, n int) string {
	if len(s) > n {
		i := n - len("...")
		for i > 0 && !utf8.RuneStart(s[i]) {
			i--
		}
		s = s[:i] + "..."
	}
	return strings.ToValidUTF8(s, "?")
}
