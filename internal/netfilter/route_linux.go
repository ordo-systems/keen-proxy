//go:build linux

package netfilter

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// RulePriority places our rule before main (32766) but after Keenetic system
// rules (priorities 0 and 1158 on Netcraze Titan SE).
const RulePriority = 10100

// TProxyRoute installs a fwmark policy rule and a local default route via lo.
// These deliver marked TPROXY packets to the sing-box socket.
type TProxyRoute struct {
	Mark  uint32
	Table int
}

func (r TProxyRoute) rule() *netlink.Rule {
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Mark = r.Mark
	mask := r.Mark
	rule.Mask = &mask
	rule.Table = r.Table
	rule.Priority = RulePriority
	return rule
}

func (r TProxyRoute) route() (*netlink.Route, error) {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return nil, fmt.Errorf("lo interface: %w", err)
	}
	_, def, _ := net.ParseCIDR("0.0.0.0/0")
	return &netlink.Route{
		LinkIndex: lo.Attrs().Index, Dst: def, Table: r.Table,
		Type: unix.RTN_LOCAL, Scope: netlink.SCOPE_HOST,
	}, nil
}

// Apply installs the policy rule and local route idempotently.
func (r TProxyRoute) Apply() error {
	rt, err := r.route()
	if err != nil {
		return err
	}
	if err := netlink.RouteReplace(rt); err != nil {
		return fmt.Errorf("local default route in table %d: %w", r.Table, err)
	}
	if err := netlink.RuleAdd(r.rule()); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("ip rule fwmark 0x%x: %w", r.Mark, err)
	}
	return nil
}

// Acquire creates the policy objects without replacing existing routes. Its
// release function removes only objects created by this acquisition.
func (r TProxyRoute) Acquire() (release func() error, err error) {
	rt, err := r.route()
	if err != nil {
		return nil, err
	}
	return r.acquire(&netlink.Handle{}, rt)
}

type routeOps interface {
	RuleAdd(*netlink.Rule) error
	RuleDel(*netlink.Rule) error
	RuleListFiltered(int, *netlink.Rule, uint64) ([]netlink.Rule, error)
	RouteAdd(*netlink.Route) error
	RouteDel(*netlink.Route) error
	RouteListFiltered(int, *netlink.Route, uint64) ([]netlink.Route, error)
}

func (r TProxyRoute) acquire(ops routeOps, rt *netlink.Route) (func() error, error) {
	rule := r.rule()
	borrowRule, err := existingPolicyRule(ops, rule)
	if err != nil {
		return nil, fmt.Errorf("ip rule fwmark 0x%x: %w", r.Mark, err)
	}
	routeErr := ops.RouteAdd(rt)
	if errors.Is(routeErr, unix.EEXIST) {
		found, err := matchingLocalDefault(ops, rt)
		if err != nil {
			return nil, fmt.Errorf("inspect local default route in table %d: %w", r.Table, err)
		}
		if !found {
			return nil, fmt.Errorf("local default route in table %d: %w", r.Table, routeErr)
		}
	} else if routeErr != nil {
		return nil, fmt.Errorf("local default route in table %d: %w", r.Table, routeErr)
	}
	releaseRoute := func() error {
		if routeErr == nil {
			if err := ops.RouteDel(rt); err != nil && !errors.Is(err, unix.ESRCH) {
				return fmt.Errorf("remove local default route in table %d: %w", r.Table, err)
			}
		}
		return nil
	}
	if borrowRule {
		return releaseRoute, nil
	}
	rule.Type = unix.RTN_UNICAST
	if err := ops.RuleAdd(rule); err != nil {
		return nil, errors.Join(fmt.Errorf("ip rule fwmark 0x%x: %w", r.Mark, err), releaseRoute())
	}
	return func() error {
		err := ops.RuleDel(rule)
		if err != nil && !errors.Is(err, unix.ESRCH) {
			return errors.Join(fmt.Errorf("remove ip rule fwmark 0x%x: %w", r.Mark, err), releaseRoute())
		}
		return releaseRoute()
	}, nil
}

func existingPolicyRule(ops routeOps, want *netlink.Rule) (bool, error) {
	rules, err := ops.RuleListFiltered(unix.AF_INET, want, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_MARK|netlink.RT_FILTER_MASK)
	if err != nil {
		return false, err
	}
	for _, rule := range rules {
		// Filters already matched the mask value. RuleList does not populate
		// Type; the lookup rule's table distinguishes it from terminal actions.
		rule.Mask, rule.Protocol = want.Mask, want.Protocol
		if rule == *want {
			return true, nil
		}
	}
	if len(rules) != 0 {
		// A delete on older kernels can match a rule with extra selectors.
		return false, errors.New("conflicting policy rule already exists")
	}
	return false, nil
}

func matchingLocalDefault(ops routeOps, want *netlink.Route) (bool, error) {
	routes, err := ops.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: want.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return false, err
	}
	for _, rt := range routes {
		// A dumped IPv4 default can omit RTA_DST entirely.
		if (rt.Dst == nil || rt.Dst.String() == want.Dst.String()) &&
			rt.Type == want.Type && rt.Scope == want.Scope && rt.LinkIndex == want.LinkIndex &&
			rt.Priority == want.Priority && rt.Tos == want.Tos && len(rt.Gw) == 0 && len(rt.MultiPath) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// Remove deletes every copy of the policy rule and removes the local route.
func (r TProxyRoute) Remove() error {
	for netlink.RuleDel(r.rule()) == nil {
	}
	rt, err := r.route()
	if err != nil {
		return err
	}
	if err := netlink.RouteDel(rt); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}
