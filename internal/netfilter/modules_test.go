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
		noTargets   bool
		autoload    bool
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
		{name: "startup loads with deferred registration evidence", noTargets: true, autoload: true, permitted: true, wantLoad: true},
		{name: "already loaded on boot but inventory unavailable", noTargets: true, autoload: true, listed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fstest.MapFS{
				ipv4Targets[1:]:   {Data: []byte(tc.target)},
				kernelModules[1:]: {},
			}
			if tc.noTargets {
				delete(root, ipv4Targets[1:])
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
			verified, err := loadKernelModule(t.Context(), root, "4.9-ndm-5", "xt_TPROXY", tproxyRegistration, open, func() bool { return tc.permitted }, func(f *os.File) error {
				loaded = true
				if f.Name() != firmware.Name() {
					t.Fatalf("unexpected module descriptor: %s", f.Name())
				}
				if tc.register {
					root[ipv4Targets[1:]].Data = []byte("TPROXY\n")
				}
				return tc.loadErr
			}, tc.autoload)
			if loaded != tc.wantLoad || verified != tc.register || errors.Is(err, ErrModuleNotLoadable) != tc.wantRefusal ||
				(tc.wantError == "" && err != nil) || (tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError))) {
				t.Fatalf("load called: %t; registration verified after load: %t; error: %v", loaded, verified, err)
			}
		})
	}
}

func TestCanceledKernelModuleLoadDoesNotProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := loadKernelModule(ctx, nil, "4.9-ndm-5", "xt_TPROXY", tproxyRegistration, nil, nil, nil, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}

func TestKernelModuleAutoloadEnrollmentRequiresRegistrationAndFirmware(t *testing.T) {
	for _, tc := range []struct {
		registration string
		loaded       bool
		firmwareErr  error
		wantOpen     bool
		wantAutoload bool
		wantFirmware bool
	}{
		{registration: moduleRegistered, wantOpen: true, wantAutoload: true, wantFirmware: true},
		{registration: moduleRegistered, wantOpen: true, firmwareErr: fs.ErrNotExist},
		{registration: moduleRegistered, wantOpen: true, firmwareErr: fs.ErrPermission},
		{registration: moduleUnregistered, wantOpen: true, wantFirmware: true},
		{registration: moduleUnregistered, loaded: true, wantOpen: true, wantFirmware: true},
		{registration: moduleUnregistered, loaded: true, wantOpen: true, firmwareErr: fs.ErrNotExist},
		{registration: moduleUnregistered, loaded: true, wantOpen: true, firmwareErr: fs.ErrPermission},
		{registration: ModuleUnknown},
	} {
		root := fstest.MapFS{kernelModules[1:]: {}}
		if tc.loaded {
			root[kernelModules[1:]].Data = []byte("xt_comment 1 0 - Live 0x00\n")
		}
		opened := false
		status := moduleStatus(root, "4.9-ndm-5", "xt_comment", tc.registration, func(release, name string) (*os.File, error) {
			opened = true
			if release != "4.9-ndm-5" || name != "xt_comment" {
				t.Fatalf("unexpected firmware descriptor %q, %q", release, name)
			}
			if tc.firmwareErr != nil {
				return nil, tc.firmwareErr
			}
			return os.Open(os.DevNull)
		}, func() bool { return true })
		if opened != tc.wantOpen || status.CanAutoload != tc.wantAutoload || status.FirmwarePresent != tc.wantFirmware ||
			(tc.loaded && (status.State != moduleLoadedUnregistered || status.CanLoad)) ||
			(tc.registration == moduleRegistered && status.State != moduleRegistered) {
			t.Errorf("%+v: opened descriptor=%t, status=%+v", tc, opened, status)
		}
	}
}

func TestUpdateGuardReportsFirmwareWhenOneFamilyIsKnownUnregistered(t *testing.T) {
	for _, tc := range []struct {
		families     GuardFamilies
		firmwareErr  error
		wantFirmware bool
	}{
		{families: GuardFamilies{IPv4: moduleUnregistered, IPv6: ModuleUnknown}, wantFirmware: true},
		{families: GuardFamilies{IPv4: ModuleUnknown, IPv6: moduleUnregistered}, wantFirmware: true},
		{families: GuardFamilies{IPv4: moduleUnregistered, IPv6: ModuleUnknown}, firmwareErr: fs.ErrNotExist},
		{families: GuardFamilies{IPv4: moduleRegistered, IPv6: ModuleUnknown}},
	} {
		open := func(string, string) (*os.File, error) {
			if tc.firmwareErr != nil {
				return nil, tc.firmwareErr
			}
			return os.Open(os.DevNull)
		}
		status := guardModuleStatus(nil, "4.9-ndm-5", tc.families, open, func() bool { return true })
		if status.State != ModuleUnknown || status.CanLoad || status.CanAutoload || status.FirmwarePresent != tc.wantFirmware {
			t.Errorf("%+v: unexpected diagnostic evidence %+v", tc, status)
		}
	}
}

func TestGuardKernelModuleBootWithMissingFilterInventory(t *testing.T) {
	for _, tc := range []struct {
		name         string
		autoload     bool
		modules      string
		noModules    bool
		afterMatches string
		openErr      error
		wantLoad     bool
		wantVerified bool
		wantErr      string
	}{
		{name: "temporary load stays strict", wantErr: "could not be verified"},
		{name: "module already present", autoload: true, modules: "xt_comment 1 0 - Live 0x00\n"},
		{name: "module inventory unavailable", autoload: true, noModules: true, wantErr: "could not be verified"},
		{name: "current firmware missing", autoload: true, openErr: fs.ErrNotExist, wantErr: "file not found"},
		{name: "load without inventing registration", autoload: true, wantLoad: true},
		{name: "load with registration", autoload: true, afterMatches: "comment\n", wantLoad: true, wantVerified: true},
		{name: "confirmed missing match is a failure", autoload: true, afterMatches: "other\n", wantLoad: true, wantErr: "did not report"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fstest.MapFS{
				kernelModules[1:]:          {Data: []byte(tc.modules)},
				"proc/net/ip_tables_names": {Data: []byte("nat\n")},
			}
			if tc.noModules {
				delete(root, kernelModules[1:])
			}
			opened := false
			open := func(release, name string) (*os.File, error) {
				opened = true
				if release != "4.9-ndm-5" || name != "xt_comment" {
					t.Fatalf("unexpected firmware descriptor %q, %q", release, name)
				}
				if tc.openErr != nil {
					return nil, tc.openErr
				}
				return os.Open(os.DevNull)
			}
			loaded := false
			load := func(file *os.File) error {
				loaded = true
				if file.Name() != os.DevNull {
					t.Fatalf("incorrect descriptor: %q", file.Name())
				}
				if tc.afterMatches != "" {
					root["proc/net/ip_tables_names"].Data = []byte("nat\nfilter\n")
					root["proc/net/ip_tables_matches"] = &fstest.MapFile{Data: []byte(tc.afterMatches)}
				}
				return nil
			}
			verified, err := loadKernelModule(t.Context(), root, "4.9-ndm-5", "xt_comment", guardAutoloadRegistration, open, func() bool { return true }, load, tc.autoload)
			if opened != (tc.wantLoad || tc.openErr != nil) || loaded != tc.wantLoad || verified != tc.wantVerified ||
				(tc.wantErr == "" && err != nil) || (tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr))) {
				t.Fatalf("opened=%t loaded=%t verified=%t error=%v", opened, loaded, verified, err)
			}
			if tc.afterMatches == "" && guardRegistrations(root, false, true).combined() != ModuleUnknown {
				t.Fatalf("guard boot changed unknown registration evidence")
			}
		})
	}
}
