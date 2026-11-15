package amnezia

import (
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// These are configKey::awgProtocolKeys(), not guessed spelling aliases.
var obfuscationFields = []string{
	"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
	"I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition",
	"RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
	"MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
}

var clientFields = func() map[string]bool {
	known := make(map[string]bool, len(obfuscationFields)+16)
	for _, key := range obfuscationFields {
		known[key] = true
	}
	for _, key := range []string{"config", "hostName", "port", "cascade_endpoint", "cascade_port", "client_ip", "client_priv_key", "client_pub_key", "server_pub_key", "psk_key", "clientId", "allowed_ips", "persistent_keep_alive", "mtu", "isObfuscationEnabled"} {
		known[key] = true
	}
	return known
}()

func validateClientFields(client object) error {
	if raw, ok := client["config"]; ok {
		var config string
		if json.Unmarshal(raw, &config) != nil || string(raw) == "null" {
			return ErrUnsupportedProfile
		}
	}
	for key := range client {
		if !clientFields[key] {
			return ErrUnsupportedProfile
		}
	}
	if raw, ok := client["isObfuscationEnabled"]; ok {
		var enabled bool
		if json.Unmarshal(raw, &enabled) != nil || !enabled {
			return ErrUnsupportedProfile
		}
	}
	return nil
}

// Native text is authoritative and retained byte-for-byte, but an explicit
// client-side security option must not disappear merely because config exists.
func validateNativeOptions(config string, client object) error {
	fields := make(map[string]string)
	for line := range strings.SplitSeq(config, "\n") {
		line, _, _ = strings.Cut(line, "#")
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}
	for _, key := range obfuscationFields {
		value, err := scalar(client, key)
		if err != nil {
			return err
		}
		if value != "" && fields[strings.ToLower(key)] != value {
			return ErrUnsupportedProfile
		}
	}
	for _, field := range []struct{ json, native string }{
		{"client_priv_key", "privatekey"}, {"server_pub_key", "publickey"},
		{"psk_key", "presharedkey"}, {"persistent_keep_alive", "persistentkeepalive"},
	} {
		value, err := scalar(client, field.json)
		if err != nil {
			return err
		}
		if value != "" && fields[field.native] != value {
			return ErrUnsupportedProfile
		}
	}
	return nil
}

func structuredConfig(root, server, client object) (string, error) {
	if err := validateStructuredTypes(client); err != nil {
		return "", err
	}
	address, err := clientAddress(text(client, "client_ip"))
	if err != nil {
		return "", err
	}
	endpoint, err := clientEndpoint(root, server, client)
	if err != nil {
		return "", err
	}
	if text(client, "client_priv_key") == "" || text(client, "server_pub_key") == "" {
		return "", ErrInvalidProfile
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	appendField(&b, "PrivateKey", text(client, "client_priv_key"))
	appendField(&b, "Address", address)
	if err := appendDNS(&b, root); err != nil {
		return "", err
	}
	appendField(&b, "MTU", text(client, "mtu"))
	for _, key := range obfuscationFields {
		value, err := inheritedOption(client, server, key)
		if err != nil {
			return "", err
		}
		appendField(&b, key, value)
	}
	b.WriteString("[Peer]\n")
	appendField(&b, "PublicKey", text(client, "server_pub_key"))
	appendField(&b, "PresharedKey", text(client, "psk_key"))
	allowed, err := allowedIPs(client)
	if err != nil {
		return "", err
	}
	appendField(&b, "AllowedIPs", allowed)
	appendField(&b, "Endpoint", endpoint)
	appendField(&b, "PersistentKeepalive", text(client, "persistent_keep_alive"))
	return b.String(), nil
}

func validateStructuredTypes(client object) error {
	for _, key := range []string{"config", "hostName", "cascade_endpoint", "cascade_port", "client_ip", "client_priv_key", "client_pub_key", "server_pub_key", "psk_key", "clientId", "persistent_keep_alive", "mtu"} {
		if raw, ok := client[key]; ok {
			var value string
			if json.Unmarshal(raw, &value) != nil || strings.ContainsAny(value, "\r\n\x00") {
				return ErrInvalidProfile
			}
		}
	}
	return nil
}

func clientAddress(value string) (string, error) {
	if strings.Contains(value, "/") {
		if _, err := netip.ParsePrefix(value); err != nil {
			return "", ErrInvalidProfile
		}
		return value, nil
	}
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" {
		return "", ErrInvalidProfile
	}
	return netip.PrefixFrom(ip, ip.BitLen()).String(), nil
}

func clientEndpoint(root, server, client object) (string, error) {
	host := text(client, "hostName")
	if host == "" {
		host = text(root, "hostName")
	}
	port, err := inheritedOption(client, server, "port")
	if err != nil {
		return "", err
	}
	if cascade := text(client, "cascade_endpoint"); cascade != "" {
		host = cascade
	}
	if cascade := text(client, "cascade_port"); cascade != "" {
		port = cascade
	}
	if host == "" || port == "" || strings.ContainsAny(host+port, "\r\n\x00") {
		return "", ErrInvalidProfile
	}
	return net.JoinHostPort(host, port), nil
}

func inheritedOption(client, server object, key string) (string, error) {
	if _, ok := client[key]; ok {
		return scalar(client, key)
	}
	return scalar(server, key)
}

func scalar(obj object, key string) (string, error) {
	raw, ok := obj[key]
	if !ok {
		return "", nil
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		var number uint64
		if json.Unmarshal(raw, &number) != nil {
			return "", ErrInvalidProfile
		}
		value = strconv.FormatUint(number, 10)
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", ErrInvalidProfile
	}
	return value, nil
}

func allowedIPs(client object) (string, error) {
	raw, ok := client["allowed_ips"]
	if !ok {
		return "0.0.0.0/0, ::/0", nil
	} // Official AWG template default.
	var values []string
	if json.Unmarshal(raw, &values) != nil || len(values) == 0 {
		return "", ErrInvalidProfile
	}
	for _, value := range values {
		if _, err := netip.ParsePrefix(value); err != nil {
			return "", ErrInvalidProfile
		}
	}
	return strings.Join(values, ", "), nil
}

func appendField(b *strings.Builder, key, value string) {
	if value == "" {
		return
	}
	b.WriteString(key)
	b.WriteString(" = ")
	b.WriteString(value)
	b.WriteByte('\n')
}

func appendDNS(b *strings.Builder, root object) error {
	first, err := scalar(root, "dns1")
	if err != nil {
		return err
	}
	second, err := scalar(root, "dns2")
	if err != nil {
		return err
	}
	if first == "" {
		first = second
	} else if second != "" {
		first += ", " + second
	}
	appendField(b, "DNS", first)
	return nil
}
