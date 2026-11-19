package netfilter

import (
	"context"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"
)

type tproxyRunner func(context.Context, string, string, ...string) error

func (r tproxyRunner) Run(ctx context.Context, input, name string, args ...string) error {
	return r(ctx, input, name, args...)
}

func TestTProxyReadiness(t *testing.T) {
	const (
		keenetic = "4.9-ndm-5\n"
		openwrt  = "6.6.119\n"
		legacy   = "iptables v1.4.21\n"
		nft      = "iptables v1.8.10 (nf_tables)\n"
		present  = "REDIRECT\nTPROXY\n"
		absent   = "REDIRECT\nMY_TPROXY\n"
	)
	unknown := TProxyReadiness{State: TProxyUnknown, Reason: TProxyProbeFailed}
	targetMissing := TProxyReadiness{State: TProxyUnavailable, Reason: "target_not_registered"}
	unverified := TProxyReadiness{State: TProxyUnknown}
	tests := []struct {
		name, release, version string
		targets                string
		missingTargets         bool
		moduleFile             bool
		modules                string
		missingModules         bool
		tables                 string
		missingTables          bool
		want                   TProxyReadiness
		readsVersion           bool
	}{
		{name: "Keenetic without registered target", release: keenetic, version: legacy, targets: absent, want: targetMissing, readsVersion: true},
		{name: "Keenetic with unloaded firmware module", release: keenetic, version: legacy, targets: absent, moduleFile: true, modules: "xt_socket 8600 1 - Live 0x0\n", want: TProxyReadiness{State: TProxyUnavailable, Reason: "module_not_loaded"}, readsVersion: true},
		{name: "Keenetic with listed module but absent target", release: keenetic, version: legacy, targets: absent, moduleFile: true, modules: "xt_TPROXY 8600 0 - Live 0x0\n", want: targetMissing, readsVersion: true},
		{name: "Keenetic with unreadable modules list", release: keenetic, version: legacy, targets: absent, moduleFile: true, missingModules: true, want: targetMissing, readsVersion: true},
		{name: "Keenetic with empty targets", release: keenetic, version: legacy, targets: "\n", want: unknown, readsVersion: true},
		{name: "Keenetic with missing targets", release: keenetic, version: legacy, missingTargets: true, want: unknown, readsVersion: true},
		{name: "Keenetic with ready legacy backend", release: "4.9.337-ndm-5\n", version: "iptables v1.8.10 (legacy)\n", targets: present, tables: "nat\n mangle\n", want: TProxyReadiness{State: TProxyReady}, readsVersion: true},
		{name: "Keenetic with unregistered mangle", release: keenetic, version: legacy, targets: present, tables: "filter\nnat\nnot_mangle\n", want: unverified, readsVersion: true},
		{name: "Keenetic with empty table inventory", release: keenetic, version: legacy, targets: present, want: unverified, readsVersion: true},
		{name: "Keenetic with missing table inventory", release: keenetic, version: legacy, targets: present, missingTables: true, want: unknown, readsVersion: true},
		{name: "Keenetic with nft and absent legacy target", release: keenetic, version: nft, targets: absent, want: unverified, readsVersion: true},
		{name: "OpenWrt nft with empty legacy proc", release: openwrt, version: nft, want: unverified},
		{name: "OpenWrt nft with missing legacy proc", release: openwrt, version: nft, missingTargets: true, want: unverified},
		{name: "OpenWrt legacy with absent targets", release: openwrt, version: legacy, targets: absent, want: unverified},
		{name: "synthetic nft namespace with populated legacy proc", release: "6.12.54-linuxkit", version: nft, targets: absent, want: unverified},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var readsVersion bool
			firewall := &Firewall{IPTables: "fixture-iptables", Run: tproxyRunner(func(context.Context, string, string, ...string) error {
				t.Fatal("passive probe ran an iptables table command")
				return nil
			})}
			read := func(path string) ([]byte, error) {
				switch path {
				case kernelRelease:
					return []byte(tc.release), nil
				case ipv4Targets:
					if !tc.missingTargets {
						return []byte(tc.targets), nil
					}
				case ipv4Tables:
					if !tc.missingTables {
						return []byte(tc.tables), nil
					}
				case kernelModules:
					if !tc.missingModules {
						return []byte(tc.modules), nil
					}
				default:
					t.Errorf("unexpected file read: %s", path)
				}
				return nil, fs.ErrNotExist
			}
			stat := func(path string) (os.FileInfo, error) {
				if path != "/lib/modules/4.9-ndm-5/xt_TPROXY.ko" {
					t.Errorf("unexpected firmware module path: %q", path)
				}
				if tc.moduleFile {
					return fs.Stat(fstest.MapFS{"xt_TPROXY.ko": {Mode: 0o644}}, "xt_TPROXY.ko")
				}
				return nil, fs.ErrNotExist
			}
			version := func(ctx context.Context, name string) ([]byte, error) {
				readsVersion = true
				if _, ok := ctx.Deadline(); !ok || name != "fixture-iptables" {
					t.Errorf("invalid version check for %q (deadline: %v)", name, ok)
				}
				return []byte(tc.version), nil
			}
			if got := firewall.probeTProxy(context.Background(), read, stat, version); got != tc.want || readsVersion != tc.readsVersion {
				t.Fatalf("got %+v (version=%v), want %+v (version=%v)", got, readsVersion, tc.want, tc.readsVersion)
			}
		})
	}
}

func TestTProxyCanceledTableInventoryIsInconclusive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firewall := &Firewall{IPTables: "fixture-iptables"}
	read := func(path string) ([]byte, error) {
		switch path {
		case kernelRelease:
			return []byte("4.9-ndm-5\n"), nil
		case ipv4Targets:
			return []byte("TPROXY\n"), nil
		case ipv4Tables:
			cancel()
			return []byte("mangle\n"), nil
		default:
			t.Fatalf("unexpected read: %s", path)
			return nil, fs.ErrNotExist
		}
	}
	version := func(context.Context, string) ([]byte, error) { return []byte("iptables v1.4.21\n"), nil }
	if got := firewall.probeTProxy(ctx, read, nil, version); got.State != TProxyUnknown || got.Reason != TProxyProbeFailed {
		t.Fatalf("interrupted check = %+v", got)
	}
}
