package trusttunnel

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ParseOutbound maps a tt:// link to one sing-box-lx trusttunnel outbound.
// Verification, a supplied certificate, SNI, and the dialed endpoint address
// are preserved. Options the native outbound cannot represent are rejected.
func ParseOutbound(link string) (map[string]any, error) {
	ep, err := ParseLink(link)
	if err != nil {
		return nil, err
	}
	if err := rejectUnsupported(ep); err != nil {
		return nil, err
	}
	host, port, err := dialAddress(ep.Addresses)
	if err != nil {
		return nil, err
	}
	tlsOpts, err := tlsOptions(ep)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"type":        "trusttunnel",
		"server":      host,
		"server_port": port,
		"username":    ep.Username,
		"password":    ep.Password,
		"tls":         tlsOpts,
	}
	if ep.HTTP3 {
		out["quic"] = true
	}
	return out, nil
}

func rejectUnsupported(ep Endpoint) error {
	switch {
	case !ep.SkipVerification && ep.CustomSNI != "" &&
		!strings.EqualFold(strings.TrimSuffix(ep.CustomSNI, "."), strings.TrimSuffix(ep.Hostname, ".")):
		return fmt.Errorf("custom_sni differs from hostname; native TLS cannot preserve separate SNI and certificate verification identities")
	case ep.SubscriptionURL != "":
		return fmt.Errorf("subscription links are not supported; export a static tt:// endpoint link")
	case strings.TrimSpace(ep.ClientRandom) != "":
		return fmt.Errorf("client_random_prefix is not supported; a server with that rule drops the TLS handshake. Export a link without client_random rules")
	case strings.TrimSpace(ep.ClientRandomAuthKey) != "":
		return fmt.Errorf("client_random_auth_key is not supported; a server with that rule drops the TLS handshake. Export a link without client_random rules")
	case ep.UpstreamProtocolSet && ep.UpstreamProtocol != 1 && ep.UpstreamProtocol != 2:
		return fmt.Errorf("upstream protocol %d is not supported; use http2 (1) or http3 (2)", ep.UpstreamProtocol)
	case ep.HTTP3 && !quicAllowed():
		return fmt.Errorf("TrustTunnel HTTP/3 requires the full build with QUIC; this lite build supports HTTP/2 only")
	case ep.HTTP3 && ep.AntiDPI:
		return fmt.Errorf("anti_dpi with HTTP/3 cannot be represented; the embedded client has no QUIC ClientHello delay. Use an HTTP/2 link or disable anti_dpi")
	default:
		return nil
	}
}

func tlsOptions(ep Endpoint) (map[string]any, error) {
	serverName := ep.Hostname
	if ep.CustomSNI != "" {
		serverName = ep.CustomSNI
	}
	if serverName == "" {
		return nil, fmt.Errorf("link is missing the TLS server name")
	}
	tlsOpts := map[string]any{
		"enabled":     true,
		"server_name": serverName,
	}
	if ep.SkipVerification {
		tlsOpts["insecure"] = true
	}
	if ep.CertificatePEM != "" {
		if err := validateCertificatePEM(ep.CertificatePEM); err != nil {
			return nil, err
		}
		tlsOpts["certificate"] = ep.CertificatePEM
	}
	// HTTP/3 uses the standard QUIC stack; uTLS with quic is a start error.
	if !ep.HTTP3 {
		tlsOpts["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		if ep.AntiDPI {
			// Official anti_dpi delays the ClientHello. tls.fragment is the
			// native equivalent for HTTP/2, not a 25 ms first-byte delay.
			tlsOpts["fragment"] = true
		}
	}
	return tlsOpts, nil
}

func validateCertificatePEM(raw string) error {
	rest := []byte(raw)
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("link certificate contains a %s block, expected CERTIFICATE", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("link certificate is not a parseable X.509 chain: %w", err)
		}
		n++
	}
	if n == 0 {
		return fmt.Errorf("link certificate is not a parseable X.509 chain")
	}
	return nil
}

type dialTarget struct {
	host string
	port int
	ip   netip.Addr
}

func dialAddress(addresses []string) (string, int, error) {
	seen := map[string]bool{}
	var targets []dialTarget
	for _, raw := range addresses {
		target, err := parseDialTarget(raw)
		if err != nil {
			return "", 0, err
		}
		key := target.host + "\x00" + strconv.Itoa(target.port)
		if seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		return "", 0, fmt.Errorf("link is missing server addresses")
	}
	chosen, err := chooseDialTarget(targets)
	if err != nil {
		return "", 0, err
	}
	return chosen.host, chosen.port, nil
}

func parseDialTarget(raw string) (dialTarget, error) {
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return dialTarget{}, fmt.Errorf("address %q must be host:port", raw)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return dialTarget{}, fmt.Errorf("address %q has an invalid port", raw)
	}
	target := dialTarget{host: host, port: port}
	if ip, err := netip.ParseAddr(host); err == nil {
		target.ip = ip.Unmap()
		target.host = target.ip.String()
	}
	if target.host == "" {
		return dialTarget{}, fmt.Errorf("address %q must be host:port", raw)
	}
	return target, nil
}

func chooseDialTarget(targets []dialTarget) (dialTarget, error) {
	if len(targets) == 1 {
		return targets[0], nil
	}
	port := targets[0].port
	for _, target := range targets[1:] {
		if target.port != port {
			return dialTarget{}, fmt.Errorf("link lists endpoint addresses on different ports (%s); the embedded client dials one server_port", addressList(targets))
		}
	}
	for _, target := range targets {
		if target.ip.IsValid() && target.ip.Is4() {
			return target, nil
		}
	}
	for _, target := range targets {
		if target.ip.IsValid() {
			return target, nil
		}
	}
	host := targets[0].host
	for _, target := range targets[1:] {
		if !strings.EqualFold(target.host, host) {
			return dialTarget{}, fmt.Errorf("link lists multiple endpoint hostnames (%s); the embedded client dials one server", addressList(targets))
		}
	}
	return targets[0], nil
}

func addressList(targets []dialTarget) string {
	parts := make([]string, len(targets))
	for i, target := range targets {
		parts[i] = net.JoinHostPort(target.host, strconv.Itoa(target.port))
	}
	return strings.Join(parts, ", ")
}
