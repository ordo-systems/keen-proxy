package netfilter

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func TestUpdateGuardKernelRegistrationUsesEnabledFamilies(t *testing.T) {
	root := fstest.MapFS{
		"proc/net/ip_tables_names":              {Data: []byte("nat\nfilter\n")},
		"proc/net/ip_tables_matches":            {Data: []byte("comment\nconntrack\n")},
		"proc/net/ip6_tables_names":             {Data: []byte("filter\n")},
		"proc/net/ip6_tables_matches":           {},
		"proc/sys/net/ipv6/conf/all/forwarding": {Data: []byte("0\n")},
		"proc/sys/net/ipv6/conf/lan/forwarding": {Data: []byte("0\n")},
	}
	ipv6, known := ipv6Forwarding(root)
	if got := guardRegistrations(root, ipv6, known); got.IPv4 != "registered" || got.IPv6 != "not_required" || got.combined() != "registered" {
		t.Fatalf("IPv4-only guard: %+v", got)
	}
	root["proc/sys/net/ipv6/conf/lan/forwarding"].Data = []byte("1\n")
	ipv6, known = ipv6Forwarding(root)
	if got := guardRegistrations(root, ipv6, known); got.IPv4 != "registered" || got.IPv6 != "unregistered" || got.combined() != "unregistered" {
		t.Fatalf("guard with IPv6 forwarding on a LAN interface: %+v", got)
	}
	delete(root, "proc/net/ip6_tables_matches")
	root["proc/net/ip_tables_matches"].Data = nil
	if got := guardRegistrations(root, ipv6, known); got.IPv4 != "unregistered" || got.IPv6 != "unknown" || got.combined() != "unknown" {
		t.Fatalf("IPv4 evidence lost when IPv6 inventory cannot be read: %+v", got)
	}
}

func TestKernelModuleLoadRequiresEligibilityAndRegistration(t *testing.T) {
	for _, tc := range []struct {
		name        string
		target      string
		listed      bool
		openErr     error
		permitted   bool
		register    bool
		loadErr     error
		wantLoad    bool
		wantRefusal bool
		wantError   string
	}{
		{name: "already registered", target: "TPROXY\n"},
		{name: "loaded but unregistered", listed: true, wantRefusal: true, wantError: "already loaded"},
		{name: "missing file", openErr: fs.ErrNotExist, wantRefusal: true, wantError: "file not found"},
		{name: "unverifiable file", openErr: fs.ErrPermission, wantRefusal: true, wantError: "could not be verified"},
		{name: "without capability", wantRefusal: true, wantError: "not permitted"},
		{name: "empty inventory permits recovery", permitted: true, register: true, wantLoad: true},
		{name: "wrong facility after load", permitted: true, wantLoad: true, wantError: "did not report"},
		{name: "kernel rejection", permitted: true, loadErr: fs.ErrPermission, wantLoad: true, wantError: "permission denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fstest.MapFS{
				ipv4Targets[1:]:   {Data: []byte(tc.target)},
				kernelModules[1:]: {},
			}
			if tc.listed {
				root[kernelModules[1:]].Data = []byte("xt_TPROXY 1 0 - Live 0x00\n")
			}
			firmware, err := os.CreateTemp(t.TempDir(), "*.ko")
			if err != nil {
				t.Fatal(err)
			}
			defer firmware.Close()
			open := func(_, _ string) (*os.File, error) {
				if tc.openErr != nil {
					return nil, tc.openErr
				}
				return os.Open(firmware.Name())
			}
			loaded := false
			err = loadKernelModule(t.Context(), root, "4.9-ndm-5", "xt_TPROXY", tproxyRegistration, open, func() bool { return tc.permitted }, func(f *os.File) error {
				loaded = true
				if f.Name() != firmware.Name() {
					t.Fatalf("unexpected module descriptor: %s", f.Name())
				}
				if tc.register {
					root[ipv4Targets[1:]].Data = []byte("TPROXY\n")
				}
				return tc.loadErr
			})
			if loaded != tc.wantLoad || errors.Is(err, ErrModuleNotLoadable) != tc.wantRefusal ||
				(tc.wantError == "" && err != nil) || (tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError))) {
				t.Fatalf("load called: %t; error: %v", loaded, err)
			}
		})
	}
}

func TestCanceledKernelModuleLoadDoesNotProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := loadKernelModule(ctx, nil, "4.9-ndm-5", "xt_TPROXY", tproxyRegistration, nil, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}
