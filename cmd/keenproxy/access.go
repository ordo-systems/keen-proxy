package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// ifaceLookup returns addresses configured on a local interface. It must not
// resolve names or open a connection.
type ifaceLookup func(name string) ([]netip.Addr, error)

// rejectAccessConflict refuses combined disclosure and daemon actions before
// any token or URL is printed. Daemon-only flags keep their existing precedence.
func rejectAccessConflict(key, showURL, dryRun, uiDemo bool) error {
	if !key && !showURL {
		return nil
	}
	switch {
	case key && showURL:
		return errors.New("cannot combine -key and -url")
	case dryRun:
		return errors.New("cannot combine -key or -url with -dry-run")
	case uiDemo:
		return errors.New("cannot combine -key or -url with -ui-demo")
	default:
		return nil
	}
}

// discloseAccess prints the current token or configured panel URL.
// A printed URL is only an address from configuration; it is not a reachability check.
func discloseAccess(w io.Writer, configPath string, key bool) error {
	cfg, err := model.Load(configPath)
	if err != nil {
		return err
	}
	if key {
		return printToken(w, cfg.API.TokenFile)
	}
	return printPanelURL(w, cfg.API.Listen, cfg.LAN.Interface, interfaceAddrs)
}

// printToken writes the trimmed token already stored at path.
// Missing, unreadable, and empty files are errors and are left unchanged.
func printToken(w io.Writer, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return fmt.Errorf("token file %s is empty", path)
	}
	_, err = fmt.Fprintln(w, token)
	return err
}

// printPanelURL writes one http URL for listen. An explicit host is kept as
// configured, including bracketed IPv6. A wildcard uses an address configured
// on iface in the listener's address family and never substitutes 0.0.0.0 or ::.
func printPanelURL(w io.Writer, listen, iface string, lookup ifaceLookup) error {
	raw, err := panelURL(listen, iface, lookup)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, raw)
	return err
}

func panelURL(listen, iface string, lookup ifaceLookup) (string, error) {
	ap, err := netip.ParseAddrPort(listen)
	if err != nil {
		return "", fmt.Errorf("api.listen: %w", err)
	}
	if ap.Port() == 0 {
		return "", errors.New("api.listen: port is 0; bound port is unknown")
	}
	if ap.Addr().IsUnspecified() {
		return wildcardURL(ap, iface, lookup)
	}
	return explicitURL(listen, ap)
}

func explicitURL(listen string, ap netip.AddrPort) (string, error) {
	if ap.Addr().Zone() == "" {
		raw := "http://" + listen
		if _, err := url.Parse(raw); err != nil {
			return "", fmt.Errorf("api.listen: %w", err)
		}
		return raw, nil
	}
	return formatHostURL(ap.Addr(), ap.Port())
}

func wildcardURL(ap netip.AddrPort, iface string, lookup ifaceLookup) (string, error) {
	if lookup == nil {
		return "", errors.New("lan interface: address lookup is unavailable")
	}
	addrs, err := lookup(iface)
	if err != nil {
		return "", fmt.Errorf("lan interface %s: %w", iface, err)
	}
	addr, ok := pickPanelAddr(addrs, ap.Addr().Is4())
	if !ok {
		return "", fmt.Errorf("lan interface %s: no %s address", iface, familyName(ap.Addr().Is4()))
	}
	if addr.Is6() && addr.IsLinkLocalUnicast() && addr.Zone() == "" {
		addr = addr.WithZone(iface)
	}
	return formatHostURL(addr, ap.Port())
}

func familyName(v4 bool) string {
	if v4 {
		return "IPv4"
	}
	return "IPv6"
}

// pickPanelAddr chooses the first non-link-local address in the listener
// family, then any other usable address in that family. It does not invent one.
func pickPanelAddr(addrs []netip.Addr, v4 bool) (netip.Addr, bool) {
	if addr, ok := firstFamily(addrs, v4, true); ok {
		return addr, true
	}
	return firstFamily(addrs, v4, false)
}

func firstFamily(addrs []netip.Addr, v4, skipLinkLocal bool) (netip.Addr, bool) {
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !usablePanelAddr(addr) || addr.Is4() != v4 {
			continue
		}
		if skipLinkLocal && addr.IsLinkLocalUnicast() {
			continue
		}
		return addr, true
	}
	return netip.Addr{}, false
}

func usablePanelAddr(addr netip.Addr) bool {
	return addr.IsValid() && !addr.IsUnspecified() && !addr.IsMulticast()
}

// Callers supply a validated address and nonzero port. Keep stdlib URL escaping
// authoritative, including percent-encoded IPv6 zones.
func formatHostURL(addr netip.Addr, port uint16) (string, error) {
	host := net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))
	raw := (&url.URL{Scheme: "http", Host: host}).String()
	if _, err := url.Parse(raw); err != nil {
		return "", errors.New("api.listen: cannot format URL")
	}
	return raw, nil
}

func interfaceAddrs(name string) ([]netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	raw, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, addr := range raw {
		if ip, ok := addrIP(addr); ok {
			out = append(out, ip)
		}
	}
	return out, nil
}

func addrIP(addr net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch v := addr.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	default:
		return netip.Addr{}, false
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return parsed.Unmap(), true
}
