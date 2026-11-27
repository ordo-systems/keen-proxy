//go:build linux && keenproxy_netns

package daemon

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

// Run only in the disposable namespace created by make integration.
func TestEnrolledTProxyRollbackPreservesExistingPolicyRoute(t *testing.T) {
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Intercept.UDPPort = uint16(udp.LocalAddr().(*net.UDPAddr).Port)
	udp.Close()
	path := writeSavedConfig(t, cfg)
	writeAutoloadFixture(t, path+".autoload-tproxy", "")
	route := netfilter.TProxyRoute{Mark: cfg.Intercept.FWMark, Table: cfg.Intercept.RouteTable}
	ip := func(args ...string) string {
		t.Helper()
		data, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, data)
		}
		return string(data)
	}
	conflictTable := strconv.Itoa(route.Table + 1)
	policyRule := func(mark, mask uint32) []string {
		return []string{"priority", strconv.Itoa(netfilter.RulePriority), "fwmark", fmt.Sprintf("%#x/%#x", mark, mask), "lookup", conflictTable}
	}
	ip("-4", "route", "add", "local", "default", "dev", "lo", "table", conflictTable)
	// A same-priority rule whose mark cannot overlap must be left alone.
	disjoint := policyRule(route.Mark&(route.Mark-1), ^uint32(0))
	ip(append([]string{"-4", "rule", "add"}, disjoint...)...)
	if err := route.Apply(); err != nil {
		t.Fatal(err)
	}
	beforeRule := ip("-4", "rule", "show")
	beforeRoutes := ip("-4", "route", "show", "table", "all")
	checkRouting := func(phase string) {
		t.Helper()
		if rules, routes := ip("-4", "rule", "show"), ip("-4", "route", "show", "table", "all"); rules != beforeRule || routes != beforeRoutes {
			t.Fatalf("%s changed preexisting routing: rules=%q routes=%q", phase, rules, routes)
		}
	}
	runner := &recoveryFirewall{jumps: make(map[[3]string]bool), chains: make(map[[2]string]bool)}
	d := newMemoryDaemon(t, path, runner)
	d.moduleAutoload = func(_ context.Context, feature string) (bool, error) {
		t.Errorf("REDIRECT startup or live Apply tried to autoload %s", feature)
		return false, nil
	}
	d.tproxyProbe = func(context.Context) netfilter.TProxyReadiness {
		return netfilter.TProxyReadiness{State: netfilter.TProxyReady}
	}
	ctx := t.Context()
	d.mu.Lock()
	blocked, err := d.startLocked(ctx, d.applyLocked)
	d.mu.Unlock()
	stop := sync.OnceFunc(d.shutdown)
	defer stop()
	if err != nil || blocked != nil {
		t.Fatalf("REDIRECT startup: blocked=%t, err=%v", blocked != nil, err)
	}
	redirect := d.Config()
	tproxy := redirect.Clone()
	tproxy.Intercept.Mode = model.InterceptTProxy
	checkConflict := func(description string) {
		t.Helper()
		rules := ip("-4", "rule", "show")
		if err := d.Apply(ctx, tproxy); err == nil || !strings.Contains(err.Error(), "conflicting policy rule") {
			t.Fatalf("TPROXY accepted %s: %v", description, err)
		}
		if status := d.Status(ctx); status.Mode != string(model.InterceptRedirect) || !status.Firewall {
			t.Fatalf("%s did not preserve REDIRECT: mode=%s firewall=%t", description, status.Mode, status.Firewall)
		}
		if ip("-4", "rule", "show") != rules || ip("-4", "route", "show", "table", "all") != beforeRoutes {
			t.Fatalf("%s changed routing", description)
		}
	}
	for _, mask := range []uint32{route.Mark, ^uint32(0)} {
		rule := policyRule(route.Mark, mask)
		ip(append([]string{"-4", "rule", "add"}, rule...)...)
		checkConflict(fmt.Sprintf("an overlapping lookup with mask %#x", mask))
		ip(append([]string{"-4", "rule", "del"}, rule...)...)
	}

	// Specify the action and the table independently so only the action
	// differs from the preexisting lookup rule.
	terminal := netlink.NewRule()
	terminal.Family = unix.AF_INET
	terminal.Priority = netfilter.RulePriority
	terminal.Mark, terminal.Mask, terminal.Table = route.Mark, &route.Mark, route.Table
	terminal.Type = unix.FR_ACT_UNREACHABLE
	if err := netlink.RuleAdd(terminal); err != nil {
		t.Fatalf("add terminal policy rule: %v", err)
	}
	checkConflict("an unreachable rule with matching lookup metadata")
	if err := netlink.RuleDel(terminal); err != nil {
		t.Fatalf("remove terminal policy rule: %v", err)
	}

	if err := d.Apply(ctx, tproxy); err != nil {
		t.Fatalf("first switch to TPROXY: %v", err)
	}
	checkRouting("first TPROXY apply")

	attempts := runner.attempts
	runner.onRestore = func() { runner.fail = runner.attempts == attempts }
	if err := d.Apply(ctx, redirect); err == nil || !strings.Contains(err.Error(), "jump insertion failed") {
		t.Fatalf("wanted firewall failure on REDIRECT switch, got %v", err)
	}
	if status := d.Status(ctx); status.Mode != string(model.InterceptTProxy) || !status.Firewall {
		t.Fatalf("rollback did not restore TPROXY: mode=%s firewall=%t", status.Mode, status.Firewall)
	}
	checkRouting("rollback to TPROXY")
	if err := d.Apply(ctx, redirect); err != nil {
		t.Fatalf("switch to REDIRECT: %v", err)
	}
	checkRouting("switch to REDIRECT")
	if err := d.Apply(ctx, tproxy); err != nil {
		t.Fatalf("switch back to TPROXY: %v", err)
	}
	stop()
	checkRouting("shutdown from TPROXY")
}
