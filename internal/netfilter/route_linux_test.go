//go:build linux

package netfilter

import (
	"net"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type routingFixture struct {
	rules                   []netlink.Rule
	routes                  []netlink.Route
	addRouteErr, addRuleErr error
	calls                   []string
}

func (f *routingFixture) RuleListFiltered(int, *netlink.Rule, uint64) ([]netlink.Rule, error) {
	return f.rules, nil
}

func (f *routingFixture) RouteListFiltered(int, *netlink.Route, uint64) ([]netlink.Route, error) {
	return f.routes, nil
}

func (f *routingFixture) RuleAdd(*netlink.Rule) error {
	f.calls = append(f.calls, "add rule")
	return f.addRuleErr
}

func (f *routingFixture) RouteAdd(*netlink.Route) error {
	f.calls = append(f.calls, "add route")
	return f.addRouteErr
}

func (f *routingFixture) RuleDel(*netlink.Rule) error {
	f.calls = append(f.calls, "delete rule")
	return nil
}

func (f *routingFixture) RouteDel(*netlink.Route) error {
	f.calls = append(f.calls, "delete route")
	return nil
}

func TestTProxyRouteAcquisitionOnlyReleasesOwnedObjects(t *testing.T) {
	p := TProxyRoute{Mark: 0x400, Table: 101}
	rule := *p.rule()
	_, def, _ := net.ParseCIDR("0.0.0.0/0")
	route := netlink.Route{Dst: def, Table: p.Table, LinkIndex: 1, Type: unix.RTN_LOCAL, Scope: netlink.SCOPE_HOST}
	listed := route
	listed.Dst = nil // Linux omits the default route's destination in dumps.
	conflicting := listed
	conflicting.Type = unix.RTN_UNICAST
	scoped := rule
	scoped.IifName = "br-lan"
	for _, tc := range []struct {
		name    string
		fixture routingFixture
		fail    bool
		want    []string
	}{
		{"new objects", routingFixture{}, false, []string{"add route", "add rule", "delete rule", "delete route"}},
		{"borrow both", routingFixture{rules: []netlink.Rule{rule}, routes: []netlink.Route{listed}, addRouteErr: unix.EEXIST}, false, []string{"add route"}},
		{"borrow the rule only", routingFixture{rules: []netlink.Rule{rule}}, false, []string{"add route", "delete route"}},
		{"borrow the route only", routingFixture{routes: []netlink.Route{listed}, addRouteErr: unix.EEXIST}, false, []string{"add route", "add rule", "delete rule"}},
		{"different default route", routingFixture{routes: []netlink.Route{conflicting}, addRouteErr: unix.EEXIST}, true, []string{"add route"}},
		{"ambiguous rule deletion", routingFixture{rules: []netlink.Rule{scoped}}, true, nil},
		{"rule add fails after route add", routingFixture{addRuleErr: unix.EPERM}, true, []string{"add route", "add rule", "delete route"}},
		{"rule add fails with borrowed route", routingFixture{routes: []netlink.Route{listed}, addRouteErr: unix.EEXIST, addRuleErr: unix.EPERM}, true, []string{"add route", "add rule"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release, err := p.acquire(&tc.fixture, &route)
			if (err != nil) != tc.fail {
				t.Fatalf("acquire error = %v, want failure = %t", err, tc.fail)
			}
			if !tc.fail {
				if err := release(); err != nil {
					t.Fatal(err)
				}
			}
			if calls := tc.fixture.calls; !slices.Equal(calls, tc.want) {
				t.Fatalf("routing changes = %v, want %v", calls, tc.want)
			}
		})
	}
}
