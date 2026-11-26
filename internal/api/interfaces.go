package api

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
)

// routerInterface identifies a kernel device. Label is optional display metadata;
// Up is the administrative link flag, not a reachability result.
type routerInterface struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
	Up    bool   `json:"up"`
}

func (s *Server) interfaces(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, demo := s.D.(*Demo); demo {
		writeJSON(w, http.StatusOK, []routerInterface{
			{Name: "eth0", Label: "Internet", Up: true},
			{Name: "nwg0", Label: "Home WireGuard", Up: true},
			{Name: "wg0"},
		})
		return
	}
	links, err := net.Interfaces()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "router interfaces unavailable")
		return
	}
	writeJSON(w, http.StatusOK, interfaceInventory(links, ndmInterfaceLabels(readNDMInterfaces(r.Context())), (*net.Interface).Addrs))
}

// readNDMInterfaces never runs a shell or consults PATH. Other firmware and
// unavailable NDM both leave the kernel inventory usable.
func readNDMInterfaces(ctx context.Context) []byte {
	if info, err := os.Stat("/var/run/ndm.core.socket"); err != nil || info.Mode()&os.ModeSocket == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/ndmc", "-c", "show interface")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}
	defer stdout.Close()
	if cmd.Start() != nil {
		return nil
	}
	const maxOutput = 1 << 20
	raw, readErr := io.ReadAll(io.LimitReader(stdout, maxOutput+1))
	if readErr != nil || len(raw) > maxOutput {
		cancel()
	}
	if err := cmd.Wait(); err != nil || readErr != nil || len(raw) > maxOutput {
		return nil
	}
	return raw
}

// ndmInterfaceLabels reads only top-level IPv4 addresses and descriptions.
// Keenetic's interface IDs are not Linux device names. Duplicate addresses
// on the NDM side cannot identify a device, even when only one has a label.
func ndmInterfaceLabels(raw []byte) map[netip.Addr]string {
	labels := make(map[netip.Addr]string)
	var addresses []netip.Addr
	var description string
	column := -2 // No top-level record; -1 means the header is waiting for its id.
	flush := func() {
		for _, address := range addresses {
			if _, duplicate := labels[address]; duplicate {
				labels[address] = ""
			} else {
				labels[address] = description
			}
		}
		addresses, description = addresses[:0], ""
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		// Headers are unindented. Indented subrecords can also have their own
		// id fields, and the top-level alignment varies between interface types.
		if strings.HasPrefix(line, "Interface, name = ") {
			flush()
			column = -1
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		if column == -1 {
			if key == "id" && i > 0 {
				column = i
			} else {
				column = -2
			}
			continue
		}
		if key == "id" && i == column {
			// An unexpected record boundary must not mix fields from two links.
			addresses, description = addresses[:0], ""
			column = -2
			continue
		}
		if i != column {
			continue
		}
		value := strings.TrimSpace(line[i+1:])
		switch key {
		case "address":
			address, err := netip.ParseAddr(value)
			if err != nil {
				prefix, _ := netip.ParsePrefix(value)
				address = prefix.Addr()
			}
			if address.Is4() && !address.IsUnspecified() && !address.IsLoopback() && !slices.Contains(addresses, address) {
				addresses = append(addresses, address)
			}
		case "description":
			description = ""
			if len(value) <= 253 && strings.IndexFunc(value, unicode.IsControl) < 0 {
				description = value
			}
		}
	}
	if scanner.Err() != nil {
		return nil
	}
	flush()
	return labels
}

// interfaceInventory enriches kernel names only when the same IPv4 address
// identifies exactly one NDM record and one kernel link. Ambiguous or missing
// metadata never hides a device, changes its name, or invents a binding.
func interfaceInventory(links []net.Interface, labels map[netip.Addr]string, addrs func(*net.Interface) ([]net.Addr, error)) []routerInterface {
	result := make([]routerInterface, 0, len(links))
	owners := make(map[netip.Addr]string)
	complete := len(labels) > 0
	for i := range links {
		link := &links[i]
		if link.Flags&net.FlagLoopback == 0 {
			result = append(result, routerInterface{Name: link.Name, Up: link.Flags&net.FlagUp != 0})
		}
		if !complete {
			continue
		}
		ips, err := addrs(link)
		if err != nil {
			complete = false
			continue
		}
		for _, ip := range ips {
			prefix, err := netip.ParsePrefix(ip.String())
			if err != nil || labels[prefix.Addr()] == "" {
				continue
			}
			addr := prefix.Addr()
			if owner, found := owners[addr]; found && owner != link.Name {
				owners[addr] = ""
			} else {
				owners[addr] = link.Name
			}
		}
	}
	if complete {
		byName := make(map[string]string)
		for addr, name := range owners {
			if name == "" {
				continue
			}
			if previous, found := byName[name]; found && previous != labels[addr] {
				byName[name] = ""
			} else {
				byName[name] = labels[addr]
			}
		}
		for i := range result {
			result[i].Label = byName[result[i].Name]
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
