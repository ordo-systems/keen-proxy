//go:build linux && keenproxy_netns

package daemon

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

// Run only in the disposable namespace created by make integration.
func TestEnrolledTProxyRollbackPreservesExistingPolicyRoute(t *testing.T) {
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.Intercept.Mode = model.InterceptTProxy
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Intercept.UDPPort = uint16(udp.LocalAddr().(*net.UDPAddr).Port)
	udp.Close()
	path := writeSavedConfig(t, cfg)
	writeAutoloadFixture(t, path+".autoload-tproxy", "")
	route := netfilter.TProxyRoute{Mark: cfg.Intercept.FWMark, Table: cfg.Intercept.RouteTable}
	if err := route.Apply(); err != nil {
		t.Fatal(err)
	}
	ip := func(args ...string) string {
		t.Helper()
		data, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, data)
		}
		return string(data)
	}
	beforeRule := ip("-4", "rule", "show")
	beforeRoutes := ip("-4", "route", "show", "table", "all")
	runner := &recoveryFirewall{jumps: make(map[[3]string]bool), chains: make(map[[2]string]bool)}
	d := newMemoryDaemon(t, path, runner)
	d.moduleAutoload = func(context.Context, string) (bool, error) { return false, nil }
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
		t.Fatalf("TPROXY startup: blocked=%t, err=%v", blocked != nil, err)
	}
	runner.onRestore = func() { runner.fail = runner.attempts == 1 }
	redirect := d.Config()
	redirect.Intercept.Mode = model.InterceptRedirect
	if err := d.Apply(ctx, redirect); err == nil || !strings.Contains(err.Error(), "jump insertion failed") {
		t.Fatalf("wanted firewall failure on REDIRECT switch, got %v", err)
	}
	if status := d.Status(ctx); status.Mode != string(model.InterceptTProxy) || !status.Firewall {
		t.Fatalf("rollback did not restore TPROXY: mode=%s firewall=%t", status.Mode, status.Firewall)
	}
	stop()
	if rules, routes := ip("-4", "rule", "show"), ip("-4", "route", "show", "table", "all"); rules != beforeRule || routes != beforeRoutes {
		t.Fatalf("rollback and shutdown changed preexisting routing: rules=%q routes=%q", rules, routes)
	}
}
