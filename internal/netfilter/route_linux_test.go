//go:build linux

package netfilter

import (
	"net"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type routingFixture struct {
	rules                   [][]byte
	ruleDumpErr             error
	routes                  []netlink.Route
	addRouteErr, addRuleErr error
	calls                   []string
}

func (f *routingFixture) dumpIPv4Rules(visit func([]byte) bool) error {
	for _, rule := range f.rules {
		if !visit(rule) {
			break
		}
	}
	return f.ruleDumpErr
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
	ruleMessage := func(action uint8, mark uint32) []byte {
		hdr := nl.RtMsg{RtMsg: unix.RtMsg{Family: unix.AF_INET, Table: uint8(p.Table), Type: action}}
		data := hdr.Serialize()
		for _, attr := range []*nl.RtAttr{
			nl.NewRtAttr(unix.FRA_PRIORITY, nl.Uint32Attr(RulePriority)),
			nl.NewRtAttr(unix.FRA_TABLE, nl.Uint32Attr(uint32(p.Table))),
			nl.NewRtAttr(unix.FRA_FWMARK, nl.Uint32Attr(mark)),
			nl.NewRtAttr(unix.FRA_FWMASK, nl.Uint32Attr(p.Mark)),
			nl.NewRtAttr(unix.FRA_SUPPRESS_PREFIXLEN, nl.Uint32Attr(^uint32(0))),
			nl.NewRtAttr(unix.FRA_PROTOCOL, nl.Uint8Attr(unix.RTPROT_BOOT)),
		} {
			data = append(data, attr.Serialize()...)
		}
		return data
	}
	rule := ruleMessage(unix.FR_ACT_TO_TBL, p.Mark)
	terminal := ruleMessage(unix.FR_ACT_UNREACHABLE, p.Mark)
	disjoint := ruleMessage(unix.FR_ACT_UNREACHABLE, 0)
	scoped := append(slices.Clone(rule), nl.NewRtAttr(unix.FRA_IIFNAME, []byte("br-lan\x00")).Serialize()...)
	_, def, _ := net.ParseCIDR("0.0.0.0/0")
	route := netlink.Route{Dst: def, Table: p.Table, LinkIndex: 1, Type: unix.RTN_LOCAL, Scope: netlink.SCOPE_HOST}
	listed := route
	listed.Dst = nil // Linux omits the default route's destination in dumps.
	conflicting := listed
	conflicting.Type = unix.RTN_UNICAST
	for _, tc := range []struct {
		name    string
		fixture routingFixture
		fail    bool
		want    []string
	}{
		{"new objects", routingFixture{}, false, []string{"add route", "add rule", "delete rule", "delete route"}},
		{"borrow both", routingFixture{rules: [][]byte{rule}, routes: []netlink.Route{listed}, addRouteErr: unix.EEXIST}, false, []string{"add route"}},
		{"borrow the rule only", routingFixture{rules: [][]byte{rule}}, false, []string{"add route", "delete route"}},
		{"borrow the route only", routingFixture{routes: []netlink.Route{listed}, addRouteErr: unix.EEXIST}, false, []string{"add route", "add rule", "delete rule"}},
		{"different default route", routingFixture{routes: []netlink.Route{conflicting}, addRouteErr: unix.EEXIST}, true, []string{"add route"}},
		{"ambiguous rule deletion", routingFixture{rules: [][]byte{scoped}}, true, nil},
		{"terminal rule is not a lookup", routingFixture{rules: [][]byte{terminal}}, true, nil},
		{"terminal rule after an equal lookup still conflicts", routingFixture{rules: [][]byte{rule, terminal}}, true, nil},
		{"disjoint terminal rule", routingFixture{rules: [][]byte{disjoint}}, false, []string{"add route", "add rule", "delete rule", "delete route"}},
		{"interrupted rule dump", routingFixture{rules: [][]byte{rule}, ruleDumpErr: nl.ErrDumpInterrupted}, true, nil},
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
