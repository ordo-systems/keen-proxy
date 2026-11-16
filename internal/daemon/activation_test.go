package daemon

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/domaincache"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestDisabledHealthAndSelectionAfterRecompile(t *testing.T) {
	d := New(Options{})
	d.cfg = &model.Config{Connections: []model.Connection{{ID: "primary", Type: model.ConnLink, Link: "socks5://203.0.113.1:1080", Disabled: true, Fallback: "reserve"}, {ID: "reserve", Type: model.ConnLink, Link: "socks5://203.0.113.2:1080", Disabled: true}}}
	d.cfg.Defaults()
	d.live.Store(d.cfg)
	d.active["primary"] = "primary"
	d.health["primary"] = &health{known: true, ok: true}
	out, err := compile.Compile(compile.Input{Config: d.cfg})
	if err != nil {
		t.Fatal(err)
	}
	d.chains = out.Failover
	d.reselectLocked()
	fo, hs := d.failoverInfoLocked()
	if fo["primary"].Active != model.TargetBlock || hs["primary"].OK || hs["primary"].Error != "connection is disabled" {
		t.Fatalf("stale runtime state: %v %v", fo, hs)
	}
	if len(probeMembers(d.cfg)) != 0 || len(d.health) != 0 {
		t.Fatal("disabled probe state retained")
	}
	d.switchLocked(time.Now())
	if _, err := d.DiagnosticChecks(context.Background(), "primary"); !errors.Is(err, ErrDiagnosticConnection) {
		t.Fatalf("disabled diagnostic = %v", err)
	}
	if _, err := d.probe(context.Background(), "primary", "http://invalid.invalid/"); err == nil {
		t.Fatal("disabled probe accepted")
	}

	d.cfg.Connections[1].Disabled = false
	out, err = compile.Compile(compile.Input{Config: d.cfg})
	if err != nil {
		t.Fatal(err)
	}
	d.chains = out.Failover
	d.reselectLocked()
	fo, _ = d.failoverInfoLocked()
	if fo["primary"].Active != "reserve" || !slices.Equal(probeMembers(d.cfg), []string{"reserve"}) {
		t.Fatalf("re-enabled reserve not restored: %v", fo)
	}
}

func TestDisabledDomainsLeaveCacheRefreshAndConflicts(t *testing.T) {
	now := time.Now()
	cfg := &model.Config{Groups: []model.Group{
		{Name: "off", Target: "direct", Entries: []string{"off.example"}, DisabledEntries: []string{"OFF.EXAMPLE"}},
		{Name: "active", Target: "direct", Entries: []string{"active.example"}},
	}}
	records := []domaincache.Record{{Name: "off.example", ObservedAt: now}, {Name: "www.off.example", ObservedAt: now}, {Name: "www.active.example", ObservedAt: now}}
	if got := refreshDomainNames(cfg, records, now); !slices.Equal(got, []string{"active.example", "www.active.example"}) {
		t.Fatalf("refresh = %v", got)
	}
	d := New(Options{})
	d.live.Store(cfg)
	if _, err := d.RefreshDomains(context.Background(), []string{"off.example"}, false); err == nil {
		t.Fatal("inactive domain accepted for live refresh")
	}
	if got := domainConflicts(cfg, records); len(got) != 0 {
		t.Fatalf("inactive conflicts = %v", got)
	}
}
