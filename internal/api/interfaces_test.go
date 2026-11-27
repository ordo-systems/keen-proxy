package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestRouterInterfaceInventory(t *testing.T) {
	// Field alignment and record headers follow the captured NDM CLI format.
	const ndm = `Interface, name = Wireguard0
               id: Wireguard0
            index: 0
   interface-name: Wireguard0
             type: Wireguard
      description: Home WireGuard: remote
             link: up
          address: 192.0.2.7/24
        wireguard:
               status:
                 peer:
                    id: NestedPeer
                     description: Not the interface name
                         address: 192.0.2.8

Interface, name = Wireguard1
               id: Wireguard1
      description: Ambiguous source
          address: 192.0.2.9
Interface, name = Bridge0
                id: Bridge0
       description:
           address: 192.0.2.9
Interface, name = Wireguard2
               id: Wireguard2
      description: Ambiguous kernel
          address: 192.0.2.10
Interface, name = Wireguard3
               id: Wireguard3
      description: Not present locally
          address: 192.0.2.11
`
	links := []net.Interface{
		{Name: "wg0", Flags: net.FlagUp}, {Name: "nwg3"}, {Name: "nwg2"},
		{Name: "nwg1"}, {Name: "nwg0", Flags: net.FlagUp}, {Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
	}
	ips := map[string]string{"nwg0": "192.0.2.7", "wg0": "192.0.2.8", "nwg1": "192.0.2.9", "nwg2": "192.0.2.10", "nwg3": "192.0.2.10"}
	addresses := func(link *net.Interface) ([]net.Addr, error) {
		if ip := net.ParseIP(ips[link.Name]); ip != nil {
			return []net.Addr{&net.IPNet{IP: ip, Mask: net.CIDRMask(24, 32)}}, nil
		}
		return nil, nil
	}
	wantPlain := []routerInterface{{Name: "nwg0", Up: true}, {Name: "nwg1"}, {Name: "nwg2"}, {Name: "nwg3"}, {Name: "wg0", Up: true}}
	for _, tc := range []struct {
		name, raw string
		addrs     func(*net.Interface) ([]net.Addr, error)
		label     string
	}{
		{"Keenetic", ndm, addresses, "Home WireGuard: remote"},
		{"OpenWrt", "", func(*net.Interface) ([]net.Addr, error) { t.Fatal("kernel addresses requested without firmware metadata"); return nil, nil }, ""},
		{"incomplete lookup", ndm, func(link *net.Interface) ([]net.Addr, error) {
			if link.Name == "lo" {
				return nil, errors.New("interface removed")
			}
			return addresses(link)
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := append([]routerInterface(nil), wantPlain...)
			want[0].Label = tc.label
			if got := interfaceInventory(links, ndmInterfaceLabels([]byte(tc.raw)), tc.addrs); !reflect.DeepEqual(want, got) {
				t.Fatalf("inventory = %+v, want %+v", got, want)
			}
		})
	}
}

// Exercise the production handler against the actual kernel inventory, including
// when this test binary is run in the disposable OpenWrt userspace.
func TestRouterInterfacesProduction(t *testing.T) {
	s, _ := newServer()
	w := do(t, s.Handler(), "GET", "/api/interfaces", "", "secret", lan)
	var got []routerInterface
	if err := json.Unmarshal(w.Body.Bytes(), &got); w.Code != http.StatusOK || err != nil || got == nil {
		t.Fatalf("unexpected kernel inventory: %d %s (%v)", w.Code, w.Body, err)
	}
	_, ndmErr := os.Stat("/var/run/ndm.core.socket")
	expected := os.Getenv("KEENPROXY_TEST_ROUTER_INTERFACE")
	seen := make(map[string]routerInterface, len(got))
	for _, link := range got {
		if _, duplicate := seen[link.Name]; link.Name == "" || link.Name == "lo" || link.Name == "lo0" || duplicate {
			t.Fatalf("unselectable or duplicate kernel interface exposed: %+v", link)
		}
		seen[link.Name] = link
		if os.IsNotExist(ndmErr) && link.Label != "" {
			t.Fatalf("unexpected firmware description without NDM: %+v", link)
		}
	}
	if expected != "" {
		got, found := seen[expected]
		if !found || !got.Up || got.Label != "" {
			t.Fatalf("expected an enabled, unlabeled kernel interface %q, got %+v", expected, got)
		}
	}
}

func TestRouterInterfacesAPI(t *testing.T) {
	s, d := newServer()
	s.D = NewDemo(d.cfg)
	for _, req := range []struct {
		token, remote string
		status        int
	}{{"", lan, http.StatusUnauthorized}, {"secret", "203.0.113.10:4567", http.StatusForbidden}, {"secret", lan, http.StatusOK}} {
		w := do(t, s.Handler(), "GET", "/api/interfaces", "", req.token, req.remote)
		if w.Code != req.status {
			t.Fatalf("status = %d, want %d: %s", w.Code, req.status, w.Body)
		}
		if w.Code == http.StatusOK {
			var got []map[string]any
			want := []map[string]any{
				{"name": "br0", "label": "LAN", "up": true},
				{"name": "eth3", "label": "Internet", "up": true},
				{"name": "nwg0", "label": "Home WireGuard", "up": true},
				{"name": "wg0", "up": false},
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("unexpected interface response: %s (%v)", w.Body, err)
			}
		}
	}
}

func TestRouterInterfaceProfileValidateAndApply(t *testing.T) {
	s, d := newServer()
	cfg := *d.cfg
	out := map[string]any{"type": "direct", "bind_interface": "wg0"}
	cfg.Connections = []model.Connection{{ID: "native", Name: "Router tunnel", Type: model.ConnSingBox, Outbound: out}}
	raw, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	w := do(t, s.Handler(), "POST", "/api/config/validate", string(raw), "secret", lan)
	if w.Code != http.StatusOK || len(d.cfg.Connections) != 0 {
		t.Fatalf("validation did not accept profile without saving: %d %s", w.Code, w.Body)
	}
	w = do(t, s.Handler(), "PUT", "/api/config", string(raw), "secret", lan)
	if w.Code != http.StatusOK || len(d.cfg.Connections) != 1 || !reflect.DeepEqual(d.cfg.Connections[0].Outbound, out) {
		t.Fatalf("the kernel binding did not survive Apply: %d %s", w.Code, w.Body)
	}
}
