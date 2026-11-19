package netfilter

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// TProxyReadiness reports preliminary IPv4 TPROXY readiness, not traffic health.
type TProxyReadiness struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

const (
	TProxyReady       = "ready"
	TProxyUnavailable = "unavailable"
	TProxyUnknown     = "unknown"
	TProxyProbeFailed = "probe_failed"
)

const (
	kernelRelease = "/proc/sys/kernel/osrelease"
	ipv4Targets   = "/proc/net/ip_tables_targets"
	ipv4Tables    = "/proc/net/ip_tables_names"
	kernelModules = "/proc/modules"
)

var (
	keeneticRelease = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?-ndm(-[0-9]+)?$`)
	legacyVersion   = regexp.MustCompile(`^iptables v(1\.[0-9]+\.[0-9]+ \(legacy\)|1\.[0-6]\.[0-9]+)$`)
)

// TProxyReadiness checks the configured firewall tools without installing rules.
// A legacy kernel inventory does not describe the nftables backend.
func (f *Firewall) TProxyReadiness(ctx context.Context) TProxyReadiness {
	if f == nil || f.IPTables == "" {
		return TProxyReadiness{State: TProxyUnknown, Reason: TProxyProbeFailed}
	}
	return f.probeTProxy(ctx, os.ReadFile, os.Stat, iptablesVersion)
}

func iptablesVersion(ctx context.Context, name string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, "--version")
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	cmd.WaitDelay = 100 * time.Millisecond
	return cmd.Output()
}

func (f *Firewall) probeTProxy(ctx context.Context, readFile func(string) ([]byte, error), stat func(string) (os.FileInfo, error), version func(context.Context, string) ([]byte, error)) TProxyReadiness {
	unknown := TProxyReadiness{State: TProxyUnknown, Reason: TProxyProbeFailed}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	release, err := readFile(kernelRelease)
	release = bytes.TrimSpace(release)
	if err != nil {
		return unknown
	}
	if !keeneticRelease.Match(release) {
		return TProxyReadiness{State: TProxyUnknown}
	}
	ver, err := version(ctx, f.IPTables)
	if err != nil || ctx.Err() != nil {
		return unknown
	}
	if !legacyVersion.Match(bytes.TrimSpace(ver)) {
		return TProxyReadiness{State: TProxyUnknown}
	}
	// Empty and unreadable inventories are not evidence that a target is absent.
	targets, err := readFile(ipv4Targets)
	if err != nil || len(bytes.TrimSpace(targets)) == 0 || ctx.Err() != nil {
		return unknown
	}
	if !inventoryContains(targets, "TPROXY") {
		reason := "target_not_registered"
		if info, err := stat(filepath.Join("/lib/modules", string(release), "xt_TPROXY.ko")); err == nil && info.Mode().IsRegular() {
			if modules, err := readFile(kernelModules); err == nil && !moduleListed(modules, "xt_TPROXY") {
				reason = "module_not_loaded"
			}
		}
		if ctx.Err() != nil {
			return unknown
		}
		return TProxyReadiness{State: TProxyUnavailable, Reason: reason}
	}
	// Looking up a missing legacy table can autoload its kernel module even
	// with the iptables userspace loader disabled. Read only the inventory:
	// an unregistered table might simply not be loaded yet.
	tables, err := readFile(ipv4Tables)
	if err != nil || ctx.Err() != nil {
		return unknown
	}
	if inventoryContains(tables, "mangle") {
		return TProxyReadiness{State: TProxyReady}
	}
	return TProxyReadiness{State: TProxyUnknown}
}

func inventoryContains(inventory []byte, name string) bool {
	for line := range bytes.SplitSeq(inventory, []byte("\n")) {
		if bytes.Equal(bytes.TrimSpace(line), []byte(name)) {
			return true
		}
	}
	return false
}

func moduleListed(modules []byte, name string) bool {
	for line := range bytes.SplitSeq(modules, []byte("\n")) {
		// /proc/modules starts each line with the module name followed by a space.
		module, _, ok := bytes.Cut(line, []byte(" "))
		if ok && bytes.Equal(module, []byte(name)) {
			return true
		}
	}
	return false
}
