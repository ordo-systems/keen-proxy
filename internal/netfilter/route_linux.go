//go:build linux

package netfilter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
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
	return r.acquire(&kernelRouteOps{}, rt)
}

type routeOps interface {
	RuleAdd(*netlink.Rule) error
	RuleDel(*netlink.Rule) error
	dumpIPv4Rules(func([]byte) bool) error
	RouteAdd(*netlink.Route) error
	RouteDel(*netlink.Route) error
	RouteListFiltered(int, *netlink.Route, uint64) ([]netlink.Route, error)
}

type kernelRouteOps struct{ netlink.Handle }

// RuleListFiltered in netlink v1.3.1 omits the action. Read it and the rule's
// selectors from the same dump rather than trying to join two snapshots.
func (*kernelRouteOps) dumpIPv4Rules(visit func([]byte) bool) error {
	req := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP)
	req.AddData(&nl.RtMsg{RtMsg: unix.RtMsg{Family: unix.AF_INET}})
	return req.ExecuteIter(unix.NETLINK_ROUTE, unix.RTM_NEWRULE, visit)
}

func (r TProxyRoute) acquire(ops routeOps, rt *netlink.Route) (func() error, error) {
	rule := r.rule()
	rule.Type = unix.FR_ACT_TO_TBL
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
	var found bool
	var ruleErr error
	err := ops.dumpIPv4Rules(func(data []byte) bool {
		matched, err := matchingPolicyRule(data, want)
		if err != nil {
			ruleErr = err
			return false
		}
		found = found || matched
		return true
	})
	if err != nil {
		return false, err
	}
	return found && ruleErr == nil, ruleErr
}

var errInvalidPolicyRule = errors.New("invalid policy rule in netlink dump")

func matchingPolicyRule(data []byte, want *netlink.Rule) (bool, error) {
	if len(data) < unix.SizeofRtMsg {
		return false, errInvalidPolicyRule
	}
	// fib_rule_hdr shares the rtmsg layout; its action occupies rtmsg.Type.
	hdr := nl.DeserializeRtMsg(data)
	if int(hdr.Family) != want.Family {
		return false, nil
	}
	const disabled = ^uint32(0)
	table := uint32(hdr.Table)
	suppressPrefixlen, suppressIfgroup := disabled, disabled
	var priority, mark, mask uint32
	var maskSet, extra bool
	for attrs := data[unix.SizeofRtMsg:]; len(attrs) > 0; {
		if len(attrs) < unix.SizeofRtAttr {
			return false, errInvalidPolicyRule
		}
		length := int(binary.NativeEndian.Uint16(attrs[:2]))
		aligned := (length + unix.NLA_ALIGNTO - 1) &^ (unix.NLA_ALIGNTO - 1)
		if length < unix.SizeofRtAttr || aligned > len(attrs) {
			return false, errInvalidPolicyRule
		}
		kind, value := binary.NativeEndian.Uint16(attrs[2:4]), attrs[unix.SizeofRtAttr:length]
		attrs = attrs[aligned:]
		var field *uint32
		switch kind {
		case unix.FRA_PRIORITY:
			field = &priority
		case unix.FRA_TABLE:
			field = &table
		case unix.FRA_FWMARK:
			field = &mark
		case unix.FRA_FWMASK:
			field, maskSet = &mask, true
		case unix.FRA_SUPPRESS_PREFIXLEN:
			field = &suppressPrefixlen
		case unix.FRA_SUPPRESS_IFGROUP:
			field = &suppressIfgroup
		case unix.FRA_PROTOCOL, unix.FRA_PAD:
			continue // Provenance and padding do not affect the lookup.
		default:
			extra = true // Do not borrow rules with extra or unknown selectors.
			continue
		}
		if len(value) != 4 {
			return false, errInvalidPolicyRule
		}
		*field = binary.NativeEndian.Uint32(value)
	}
	if priority != uint32(want.Priority) {
		return false, nil
	}
	if !maskSet && mark != 0 {
		mask = ^uint32(0) // A legacy fwmark without a mask compares all bits.
	}
	// A different mask can still match a socket mark we produce. Inverted
	// selectors are conservatively treated as overlapping.
	if hdr.Flags&unix.FIB_RULE_INVERT == 0 && (mark^want.Mark)&(mask&*want.Mask) != 0 {
		return false, nil
	}
	if hdr.Type != want.Type || table != uint32(want.Table) || mark != want.Mark || mask != *want.Mask ||
		hdr.Src_len != 0 || hdr.Dst_len != 0 || hdr.Tos != 0 || hdr.Flags&^unix.FIB_RULE_PERMANENT != 0 ||
		extra || suppressPrefixlen != disabled || suppressIfgroup != disabled {
		// A delete on older kernels can also match a rule with extra selectors.
		return false, errors.New("conflicting policy rule already exists")
	}
	return true, nil
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
