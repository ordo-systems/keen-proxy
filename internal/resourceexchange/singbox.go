package resourceexchange

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/option"
)

const singBoxExportVersion = 2

const (
	singBoxDomain = "domain"
	singBoxSuffix = DomainSuffix
	singBoxCIDR   = IPCIDR
)

type ruleSetInputError struct {
	location, kind, message string
}

func invalidRuleSet(location, message string) *ruleSetInputError {
	return &ruleSetInputError{location, "error", message}
}

func unsupportedRuleSet(location, message string) *ruleSetInputError {
	return &ruleSetInputError{location, "unsupported", message}
}

func (e *ruleSetInputError) report(collector *decoder) {
	collector.issue(e.location, e.kind, e.message)
}

func ruleSetLocation(rule int) string { return fmt.Sprintf("rules[%d]", rule) }

func supportedRuleSetVersion(version int64) bool { return version >= 1 && version <= 5 }

type singBoxTerm struct {
	field, value string
	rule, index  int
}

func (t singBoxTerm) location() string {
	return fmt.Sprintf("rules[%d].%s[%d]", t.rule, t.field, t.index)
}

func decodeSingBox(data []byte, collector *decoder) {
	parser := singBoxSource{json: json.NewDecoder(bytes.NewReader(data))}
	parser.json.UseNumber()
	if err := parser.read(); err != nil {
		err.report(collector)
		return
	}
	collectSingBoxTerms(parser.terms, collector)
}

type singBoxSource struct {
	json  *json.Decoder
	terms []singBoxTerm
}

func (s *singBoxSource) expect(want json.Delim, location, message string) *ruleSetInputError {
	token, err := s.json.Token()
	if err != nil || token != want {
		return invalidRuleSet(location, message)
	}
	return nil
}

func (s *singBoxSource) read() *ruleSetInputError {
	if err := s.expect('{', "file", "expected a rule-set object"); err != nil {
		return err
	}
	var haveVersion, haveRules bool
	for s.json.More() {
		key, err := s.json.Token()
		field, ok := key.(string)
		if err != nil || !ok {
			return invalidRuleSet("file", "invalid rule-set object")
		}
		switch field {
		case "version":
			if haveVersion {
				return invalidRuleSet("version", "duplicate field")
			}
			haveVersion = true
			value, valueErr := s.json.Token()
			number, ok := value.(json.Number)
			if valueErr != nil || !ok {
				return invalidRuleSet("version", "expected an integer")
			}
			version, numberErr := number.Int64()
			if numberErr != nil || !supportedRuleSetVersion(version) {
				return unsupportedRuleSet("version", "supported rule-set versions are 1–5")
			}
		case "rules":
			if haveRules {
				return invalidRuleSet("rules", "duplicate field")
			}
			haveRules = true
			if issue := s.readRules(); issue != nil {
				return issue
			}
		default:
			return unsupportedRuleSet(ruleSetFieldLocation("", field), "unsupported rule-set field")
		}
	}
	if err := s.expect('}', "file", "expected the end of the rule-set object"); err != nil {
		return err
	}
	if _, err := s.json.Token(); err != io.EOF {
		return invalidRuleSet("file", "unexpected data after the rule-set object")
	}
	if !haveVersion {
		return invalidRuleSet("version", "missing rule-set version")
	}
	if !haveRules {
		return invalidRuleSet("rules", "missing rule array")
	}
	return nil
}

func (s *singBoxSource) readRules() *ruleSetInputError {
	if err := s.expect('[', "rules", "expected an array of rules"); err != nil {
		return err
	}
	for rule := 0; s.json.More(); rule++ {
		if rule == MaxEntries {
			return invalidRuleSet("rules", "too many rules")
		}
		if err := s.readRule(rule); err != nil {
			return err
		}
	}
	return s.expect(']', "rules", "expected the end of the rule array")
}

func (s *singBoxSource) readRule(rule int) *ruleSetInputError {
	location := ruleSetLocation(rule)
	if err := s.expect('{', location, "expected a rule object"); err != nil {
		return err
	}
	start := len(s.terms)
	var seen uint8
	for s.json.More() {
		key, err := s.json.Token()
		field, ok := key.(string)
		if err != nil || !ok {
			return invalidRuleSet(location, "invalid rule object")
		}
		path := ruleSetFieldLocation(location, field)
		var bit uint8
		switch field {
		case "type":
			bit = 1
		case singBoxDomain:
			bit = 2
		case singBoxSuffix:
			bit = 4
		case singBoxCIDR:
			bit = 8
		default:
			return unsupportedRuleSet(path, "unsupported rule field")
		}
		if seen&bit != 0 {
			return invalidRuleSet(path, "duplicate field")
		}
		seen |= bit
		if field == "type" {
			value, err := s.json.Token()
			if _, ok := value.(string); err != nil || !ok {
				return invalidRuleSet(path, "expected a rule type string")
			}
			if value != "default" {
				return unsupportedRuleSet(path, "only default rules are supported")
			}
		} else if issue := s.readTerms(rule, field, path); issue != nil {
			return issue
		}
	}
	if err := s.expect('}', location, "expected the end of the rule object"); err != nil {
		return err
	}
	if len(s.terms) == start {
		return invalidRuleSet(location, "rule must contain at least one predicate value")
	}
	return nil
}

func ruleSetFieldLocation(location, field string) string {
	// Do not copy arbitrary unsupported keys (or their control characters) into diagnostics.
	if field == "" || len(field) > 64 || strings.ContainsFunc(field, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_')
	}) {
		field = "(unknown field)"
	}
	if location == "" {
		return field
	}
	return location + "." + field
}

func (s *singBoxSource) readTerms(rule int, field, location string) *ruleSetInputError {
	token, err := s.json.Token()
	if err == nil && token == json.Delim('[') {
		for index := 0; s.json.More(); index++ {
			token, err := s.json.Token()
			if issue := s.addTerm(rule, field, index, token, err); issue != nil {
				return issue
			}
		}
		return s.expect(']', location, "expected the end of the predicate array")
	}
	return s.addTerm(rule, field, 0, token, err)
}

func (s *singBoxSource) addTerm(rule int, field string, index int, token json.Token, err error) *ruleSetInputError {
	value, ok := token.(string)
	term := singBoxTerm{field, value, rule, index}
	if !ok || err != nil {
		return invalidRuleSet(term.location(), "expected a predicate string")
	}
	if len(s.terms) == MaxEntries {
		return invalidRuleSet(term.location(), "too many predicate values")
	}
	s.terms = append(s.terms, term)
	return nil
}

type singBoxCoverage uint8

const (
	singBoxApex singBoxCoverage = 1 << iota
	singBoxDescendants
	singBoxFullSuffix = singBoxApex | singBoxDescendants
)

// collectSingBoxTerms proves suffix equivalence over the whole rule union.
// Validation requires the original domain to be canonical: unlike a bare
// suffix, a leading dot excludes its apex, and an exact match includes only it.
func collectSingBoxTerms(terms []singBoxTerm, collector *decoder) {
	var coverage map[string]singBoxCoverage
	for i := range terms {
		term := &terms[i]
		if term.field == singBoxCIDR {
			continue
		}
		base := term.value
		leading := term.field == singBoxSuffix && strings.HasPrefix(base, ".")
		if leading {
			base = base[1:]
		}
		if !isSingBoxDomain(base) {
			collector.issue(term.location(), "unsupported", "domain must be a lowercase ASCII name without wildcard or trailing dot")
			term.field = ""
			continue
		}
		if coverage == nil {
			coverage = make(map[string]singBoxCoverage)
		}
		switch {
		case term.field == singBoxDomain:
			coverage[base] |= singBoxApex
		case leading:
			coverage[base] |= singBoxDescendants
		default:
			coverage[base] = singBoxFullSuffix
		}
	}
	for _, term := range terms {
		switch term.field {
		case singBoxCIDR:
			if !isSingBoxCIDR(term.value) {
				collector.issue(term.location(), "error", "expected an IP address or CIDR without a zone")
				continue
			}
			collector.add(term.location(), Entry{Type: singBoxCIDR, Value: term.value})
		case singBoxDomain:
			if !coveredBySingBoxSuffix(term.value, coverage) {
				collector.issue(term.location(), "unsupported", "exact domain is not covered by a suffix")
			}
		case singBoxSuffix:
			base, leading := strings.CutPrefix(term.value, ".")
			if leading && coverage[base] != singBoxFullSuffix {
				if !coveredBySingBoxSuffix(base, coverage) {
					collector.issue(term.location(), "unsupported", "leading-dot suffix excludes its apex")
				}
				continue
			}
			collector.add(term.location(), Entry{Type: singBoxSuffix, Value: base})
		}
	}
}

func coveredBySingBoxSuffix(domain string, coverage map[string]singBoxCoverage) bool {
	for {
		if coverage[domain] == singBoxFullSuffix {
			return true
		}
		_, rest, ok := strings.Cut(domain, ".")
		if !ok {
			return false
		}
		domain = rest
	}
}

func isSingBoxDomain(domain string) bool {
	if len(domain) > maxSuffixBytes || !strings.Contains(domain, ".") {
		return false
	}
	entry, err := Canonical(Entry{Type: singBoxSuffix, Value: domain})
	return err == nil && entry.Value == domain
}

func isSingBoxCIDR(value string) bool {
	if _, err := netip.ParsePrefix(value); err == nil {
		return true
	}
	addr, err := netip.ParseAddr(value)
	return err == nil && addr.Zone() == ""
}

// splitSingBoxEntries takes the validated, active entries prepared by Encode.
func splitSingBoxEntries(list List) (domains, addresses []string) {
	for _, entry := range list.Entries {
		switch entry.Type {
		case singBoxSuffix:
			domains = append(domains, entry.Value)
		case singBoxCIDR:
			addresses = append(addresses, entry.Value)
		}
	}
	return domains, addresses
}

func encodeSingBox(list List) ([]byte, error) {
	domains, addresses := splitSingBoxEntries(list)
	// Separate rules preserve the union independently of the consumer's grouping
	// of fields within one default rule.
	rules := make([]option.HeadlessRule, 0, 2)
	if len(domains) != 0 {
		rules = append(rules, option.HeadlessRule{Type: "default", DefaultOptions: option.DefaultHeadlessRule{DomainSuffix: domains}})
	}
	if len(addresses) != 0 {
		rules = append(rules, option.HeadlessRule{Type: "default", DefaultOptions: option.DefaultHeadlessRule{IPCIDR: addresses}})
	}
	return json.Marshal(struct {
		Version int                   `json:"version"`
		Rules   []option.HeadlessRule `json:"rules"`
	}{singBoxExportVersion, rules})
}
