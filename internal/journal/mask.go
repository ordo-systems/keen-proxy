package journal

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

const masked = "•••"

// Masker redacts configured credentials and extra secrets from exported log
// text, including WireGuard and AmneziaWG keys, connection links, passwords, and panel tokens.
func Masker(cfg *model.Config, extra ...string) func(string) string {
	secrets := append([]string{}, extra...)
	if cfg != nil {
		for _, raw := range cfg.DNS.Upstreams {
			secrets = append(secrets, linkSecrets(raw)...)
		}
		secrets = append(secrets, linkSecrets(cfg.GeoIP.URL)...)
		for _, db := range cfg.GeoIP.Databases {
			secrets = append(secrets, linkSecrets(db.URL)...)
		}
		secrets = append(secrets, linkSecrets(cfg.Failover.URL)...)
		for _, source := range cfg.Filters.Sources {
			secrets = append(secrets, linkSecrets(source.URL)...)
		}
		for _, cn := range cfg.Connections {
			if wg := cn.WireGuard; wg != nil {
				secrets = append(secrets, wg.PrivateKey, wg.Peer.PresharedKey)
			}
			secrets = append(secrets, awgProfileSecrets(cn.AmneziaWG)...)
			secrets = append(secrets, linkSecrets(cn.Link)...)
			if cn.TrustTunnel != nil {
				secrets = append(secrets, cn.TrustTunnel.Link)
			}
			for _, m := range []map[string]any{cn.Outbound, cn.Endpoint} {
				collect(m, &secrets)
			}
		}
	}
	// Skip short secrets such as "1" or "a" to avoid corrupting unrelated text.
	var list []string
	for _, s := range secrets {
		if len(s) >= 6 {
			list = append(list, s)
		}
	}
	// Replace longer secrets first: the whole link before its parts.
	sort.Slice(list, func(i, j int) bool { return len(list[i]) > len(list[j]) })
	return func(s string) string {
		for _, sec := range list {
			s = strings.ReplaceAll(s, sec, masked)
		}
		return s
	}
}

// linkSecrets includes the complete link and, when userinfo exists, credentials and known secret query values.
func linkSecrets(link string) []string {
	if link == "" {
		return nil
	}
	out := []string{link}
	if u, err := url.Parse(link); err == nil && u.User != nil {
		out = append(out, u.User.Username())
		if p, ok := u.User.Password(); ok {
			out = append(out, p)
		}
		for _, k := range []string{"pbk", "sid", "password", "psk", "key"} {
			if v := u.Query().Get(k); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// collect walks raw JSON objects and arrays, gathering string values under credential-like keys.
func collect(v any, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok && secretKey(k) {
				*out = append(*out, secretForms(k, s)...)
				continue
			}
			collect(val, out)
		}
	case []any:
		for _, val := range x {
			collect(val, out)
		}
	}
}

func secretKey(k string) bool {
	k = strings.ToLower(k)
	if k == "header_protection_key" || k == "headerprotectionkey" {
		return true
	}
	for _, s := range []string{"password", "uuid", "private_key", "pre_shared_key", "psk", "secret", "token", "public_key", "short_id"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

func secretForms(key, value string) []string {
	if !headerKeyName(key) {
		return []string{value}
	}
	return append([]string{value}, headerKeyHex(value)...)
}

func headerKeyName(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(key, "_", ""))
	return key == "headerprotectionkey"
}

// headerKeyHex returns both hex cases. The device normalizes a base64
// header_protection_key to lowercase hex before UAPI; logs may print either case.
func headerKeyHex(value string) []string {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		decoded, err = hex.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			return nil
		}
	}
	lower := hex.EncodeToString(decoded)
	return []string{lower, strings.ToUpper(lower)}
}

func awgProfileSecrets(profile string) []string {
	if profile == "" {
		return nil
	}
	var out []string
	for line := range strings.SplitSeq(profile, "\n") {
		line, _, _ = strings.Cut(line, "#")
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch name := strings.ToLower(strings.TrimSpace(name)); name {
		case "privatekey", "presharedkey", "headerprotectionkey":
			if value = strings.TrimSpace(value); value != "" {
				out = append(out, secretForms(name, value)...)
			}
		}
	}
	return out
}
