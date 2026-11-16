package links

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// parseBool accepts only the explicit true and false spellings used in share links.
// Any other text is an error so a malformed flag is not stored as false.
func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true, nil
	case "0", "false", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean %q", v)
	}
}

func firstQuery(q url.Values, names ...string) (string, bool, error) {
	var (
		val string
		set bool
	)
	for _, name := range names {
		for _, got := range q[name] {
			if set && got != val {
				return "", true, fmt.Errorf("conflicting values for %s", names[0])
			}
			val, set = got, true
		}
	}
	return val, set, nil
}

func rejectUnrepresentableTLS(q url.Values) error {
	for name := range q {
		if _, _, err := firstQuery(q, name); err != nil {
			return err
		}
	}
	if pqv := strings.TrimSpace(q.Get("pqv")); pqv != "" {
		return fmt.Errorf("reality pqv signatures are not supported")
	}
	if fm := strings.TrimSpace(q.Get("fm")); fm != "" {
		return fmt.Errorf("xray fragment spec fm is not supported; use fragment or record_fragment")
	}
	if spx := q.Get("spx"); spx != "" && spx != "/" {
		return fmt.Errorf("reality spiderX (spx) is not supported")
	}
	return nil
}

func rejectTLSFlagsWithoutTLS(q url.Values) error {
	if q.Has("fragment") || q.Has("record_fragment") || q.Has("recordFragment") ||
		q.Has("fragment_fallback_delay") || q.Has("fragmentFallbackDelay") ||
		q.Has("key_share") || q.Has("keyShare") {
		return fmt.Errorf("tls fragment and key_share require security=tls or security=reality")
	}
	return nil
}

func applyTLSFlags(t map[string]any, q url.Values) error {
	if err := applyBoolFlag(t, q, "fragment", "fragment"); err != nil {
		return err
	}
	if err := applyBoolFlag(t, q, "record_fragment", "record_fragment", "recordFragment"); err != nil {
		return err
	}
	raw, present, err := firstQuery(q, "fragment_fallback_delay", "fragmentFallbackDelay")
	if err != nil || !present {
		return err
	}
	raw = strings.TrimSpace(raw)
	if _, err := time.ParseDuration(raw); err != nil {
		return fmt.Errorf("fragment_fallback_delay %q is not a duration", raw)
	}
	t["fragment_fallback_delay"] = raw
	return nil
}

func applyBoolFlag(t map[string]any, q url.Values, jsonKey string, names ...string) error {
	raw, present, err := firstQuery(q, names...)
	if err != nil || !present {
		return err
	}
	value, err := parseBool(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", jsonKey, err)
	}
	t[jsonKey] = value
	return nil
}

func applyRealityKeyShare(reality map[string]any, q url.Values, security string) error {
	share, present, err := firstQuery(q, "key_share", "keyShare")
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if security != "reality" {
		return fmt.Errorf("reality key_share requires security=reality")
	}
	switch strings.ToLower(strings.TrimSpace(share)) {
	case "hybrid", "classical":
		reality["key_share"] = strings.ToLower(strings.TrimSpace(share))
		return nil
	default:
		return fmt.Errorf("reality key_share %q is not supported (expected hybrid or classical)", share)
	}
}

// Preserve the server's encryption spec; the normal engine validation owns its grammar.
func applyEncryption(o Outbound, raw string) {
	raw = strings.TrimSpace(raw)
	if raw != "" && !strings.EqualFold(raw, "none") {
		o["encryption"] = raw
	}
}
