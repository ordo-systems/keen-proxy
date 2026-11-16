// Package model defines the canonical keenProxy configuration. internal/compile
// derives sing-box configuration and firewall rules from this model.
package model

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ordo-systems/keen-proxy/internal/awg"
	"github.com/ordo-systems/keen-proxy/internal/links"
)

// Built-in route targets may be used instead of a connection ID.
const (
	TargetDirect = "direct"
	TargetBlock  = "block"
)

// Mode controls whether a source uses split routing, a full tunnel, or bypass.
type Mode string

const (
	ModeInherit Mode = ""      // client inherits its network mode
	ModeSplit   Mode = "split" // only matching groups use tunnels
	ModeFull    Mode = "full"  // all traffic uses the selected connection
	ModeOff     Mode = "off"   // kernel routing bypasses keenProxy
)

// InterceptMode selects kernel interception mechanisms for TCP and UDP.
type InterceptMode string

const (
	// InterceptRedirect intercepts TCP with REDIRECT and rejects QUIC.
	InterceptRedirect InterceptMode = "redirect"
	// InterceptTProxy uses REDIRECT for TCP and TPROXY for UDP.
	InterceptTProxy InterceptMode = "tproxy"
)

// Config is the persisted schema shared by the compiler, daemon, and API.
type Config struct {
	SchemaVersion int          `yaml:"schema_version" json:"schema_version"`
	System        System       `yaml:"system,omitempty" json:"system,omitempty"`
	Filters       Filters      `yaml:"filters,omitempty" json:"filters"`
	API           API          `yaml:"api" json:"api"`
	LAN           LAN          `yaml:"lan" json:"lan"`
	DNS           DNS          `yaml:"dns" json:"dns"`
	Intercept     Intercept    `yaml:"intercept" json:"intercept"`
	GeoIP         GeoIP        `yaml:"geoip" json:"geoip"`
	Failover      Failover     `yaml:"failover" json:"failover"`
	Connections   []Connection `yaml:"connections" json:"connections"`
	Groups        []Group      `yaml:"groups" json:"groups"`
	Networks      []Network    `yaml:"networks" json:"networks"`
	Clients       []Client     `yaml:"clients" json:"clients"`
}

// maxMemoryLimitMiB is the largest MiB count whose byte size fits in int64.
const maxMemoryLimitMiB MemoryLimitMiB = 8796093022207

// MemoryLimitMiB is an integer-only MiB scalar; YAML floats must not be truncated.
type MemoryLimitMiB int64

// UnmarshalYAML preserves the same integer contract as JSON without bypassing known-field checks.
func (m *MemoryLimitMiB) UnmarshalYAML(node *yaml.Node) error {
	if node.Tag != "!!int" {
		return fmt.Errorf("system.memory_limit_mib: expected an integer number of MiB")
	}
	var value int64
	if err := node.Decode(&value); err != nil {
		return err
	}
	*m = MemoryLimitMiB(value)
	return nil
}

// System holds process settings that are not compiled into sing-box.
type System struct {
	// MemoryLimitMiB is an optional soft memory recommendation in mebibytes.
	// Nil uses the daemon default, which honors startup limits before its built-in budget.
	// Zero and negative values are rejected and are never forwarded to the runtime.
	MemoryLimitMiB *MemoryLimitMiB `yaml:"memory_limit_mib,omitempty" json:"memory_limit_mib,omitempty"`
}

// MemoryLimitBytes converts an optional MiB recommendation to a process byte limit.
// A nil config or recommendation returns baseline. ok is false when the value must not be applied.
func MemoryLimitBytes(cfg *Config, baseline int64) (int64, bool) {
	if cfg == nil || cfg.System.MemoryLimitMiB == nil {
		return baseline, true
	}
	mib := int64(*cfg.System.MemoryLimitMiB)
	if mib < 1 || mib > int64(maxMemoryLimitMiB) {
		return 0, false
	}
	return mib * 1024 * 1024, true
}

// API configures the web interface and HTTP API.
type API struct {
	Listen    string `yaml:"listen" json:"listen"`         // 0.0.0.0:8086
	TokenFile string `yaml:"token_file" json:"token_file"` // login token created on first startup
	// NoTokenFrom permits dashboard access without a token from these CIDR ranges.
	NoTokenFrom []string `yaml:"no_token_from,omitempty" json:"no_token_from,omitempty"`
}

// NoTokenPrefixes parses API.NoTokenFrom, skipping invalid ranges that Validate rejects.
func (a API) NoTokenPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range a.NoTokenFrom {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// LAN identifies the client-facing and provider network interfaces.
type LAN struct {
	Interface string `yaml:"interface" json:"interface"` // br0
	WAN       string `yaml:"wan" json:"wan"`             // provider interface excluded from interception
}

// DNS configures local interception, upstream transport, and failure policy.
type DNS struct {
	// Route is empty for legacy system fallback, or explicitly direct/connection.
	Route      string `yaml:"route,omitempty" json:"route,omitempty"`
	Connection string `yaml:"connection,omitempty" json:"connection,omitempty"`
	Failure    string `yaml:"failure,omitempty" json:"failure,omitempty"`
	// Bootstrap pins upstream hostnames to IPs without an initial DNS lookup.
	Bootstrap      map[string]string `yaml:"bootstrap,omitempty" json:"bootstrap,omitempty"`
	BlockEncrypted bool              `yaml:"block_encrypted,omitempty" json:"block_encrypted,omitempty"`
	FirefoxCanary  bool              `yaml:"firefox_canary,omitempty" json:"firefox_canary,omitempty"`
	Listen         string            `yaml:"listen" json:"listen"`       // frontend address receiving LAN port 53 DNAT
	Upstreams      []string          `yaml:"upstreams" json:"upstreams"` // https://…, tls://…, udp://… in priority order
	// Fallback is the system resolver (Keenetic ndnproxy) used when all upstreams fail.
	Fallback string `yaml:"fallback" json:"fallback"`
}

// GeoIP configures the country databases used by country groups and connection flags.
type GeoIP struct {
	// Databases lists country databases in lookup priority order: the first
	// enabled database that knows an address decides its country. Defaults
	// adds missing built-ins, which can be reordered and disabled but not removed.
	Databases []GeoIPDatabase `yaml:"databases" json:"databases"`
	// URL and File are the single-database settings of earlier versions.
	// Defaults migrates them into Databases.
	URL  string `yaml:"url,omitempty" json:"url,omitempty"`
	File string `yaml:"file,omitempty" json:"file,omitempty"`
}

// GeoIPDatabase references a built-in source by ID, or defines a custom
// database with either an HTTPS URL or a local MMDB file.
type GeoIPDatabase struct {
	ID   string `yaml:"id" json:"id"`
	Name string `yaml:"name,omitempty" json:"name,omitempty"` // custom databases only
	// URL is downloaded daily; {month} expands to YYYY-MM with a fallback to
	// the previous month. gzip and tar.gz archives are unpacked.
	URL string `yaml:"url,omitempty" json:"url,omitempty"`
	// File is a local MMDB with country.iso_code that is never downloaded.
	File string `yaml:"file,omitempty" json:"file,omitempty"`
	// Kind is empty for a country database or "category" for a database of
	// labels used by Group.Categories. Built-ins take their kind from the catalog.
	Kind    string `yaml:"kind,omitempty" json:"kind,omitempty"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

// Failover configures health probes for connections with Connection.Fallback.
type Failover struct {
	// URL is requested through each connection; any HTTP response counts as success.
	URL string `yaml:"url" json:"url"`
	// Interval is the probe interval in seconds.
	Interval int `yaml:"interval" json:"interval"`
	// DownAfter is the continuous failure duration in seconds before switching to a fallback.
	DownAfter int `yaml:"down_after" json:"down_after"`
	// UpAfter is the continuous success duration in seconds before returning
	// to a higher-priority connection.
	UpAfter int `yaml:"up_after" json:"up_after"`
}

// Intercept assigns listener ports and policy-routing identifiers for interception.
type Intercept struct {
	Mode       InterceptMode `yaml:"mode" json:"mode"`
	TCPPort    uint16        `yaml:"tcp_port" json:"tcp_port"`
	UDPPort    uint16        `yaml:"udp_port" json:"udp_port"`
	FWMark     uint32        `yaml:"fwmark" json:"fwmark"`
	RouteTable int           `yaml:"route_table" json:"route_table"`
}

// Connection types select exactly one protocol description.
const (
	ConnWireGuard   = "wireguard"   // WireGuard through sing-box
	ConnAmneziaWG   = "amneziawg"   // AmneziaWG .conf through sing-box-lx
	ConnLink        = "link"        // vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, anytls://, socks5://, tt:// link
	ConnSingBox     = "singbox"     // raw sing-box outbound or endpoint
	ConnTrustTunnel = "trusttunnel" // legacy input type; normalized to link before validation
)

// Connection defines one outbound protocol and its optional fallback target.
type Connection struct {
	ID   string `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
	Type string `yaml:"type" json:"type"`
	// Disabled retains the profile and incoming references while excluding the
	// tunnel from runtime use. Configured fallbacks remain available.
	Disabled  bool       `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	WireGuard *WireGuard `yaml:"wireguard,omitempty" json:"wireguard,omitempty"`
	AmneziaWG string     `yaml:"amneziawg,omitempty" json:"amneziawg,omitempty"`
	Link      string     `yaml:"link,omitempty" json:"link,omitempty"`
	// Outbound or Endpoint contains a sing-box object with its tag derived from ID.
	// A singbox connection must set exactly one of these fields.
	Outbound    map[string]any `yaml:"outbound,omitempty" json:"outbound,omitempty"`
	Endpoint    map[string]any `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	TrustTunnel *TrustTunnel   `yaml:"trusttunnel,omitempty" json:"trusttunnel,omitempty"`
	// Fallback names another connection or direct. After Failover.DownAfter of
	// failure, traffic follows this chain to the next available member.
	Fallback string `yaml:"fallback,omitempty" json:"fallback,omitempty"`
}

// Chain returns a connection and its fallbacks in priority order, or just the
// connection if none are configured. Validate rejects cyclic chains.
func (c *Config) Chain(id string) []string {
	chain := []string{id}
	for cur := id; ; {
		var next string
		for _, cn := range c.Connections {
			if cn.ID == cur {
				next = cn.Fallback
				break
			}
		}
		if next == "" || slices.Contains(chain, next) {
			return chain
		}
		chain = append(chain, next)
		cur = next
	}
}

// TrustTunnel is the legacy external-client section. It is accepted when a
// file or API body is loaded and cleared by normalization, so a saved
// configuration does not keep binary or socks_port.
type TrustTunnel struct {
	Link      string `yaml:"link" json:"link"`                                 // tt://?…
	Binary    string `yaml:"binary,omitempty" json:"binary,omitempty"`         // obsolete external client path
	SocksPort uint16 `yaml:"socks_port,omitempty" json:"socks_port,omitempty"` // obsolete local SOCKS5 port
}

// WireGuard configures a userspace tunnel and its single peer.
type WireGuard struct {
	PrivateKey string   `yaml:"private_key" json:"private_key"`
	Address    []string `yaml:"address" json:"address"`
	MTU        uint32   `yaml:"mtu,omitempty" json:"mtu,omitempty"` // bytes; zero uses the engine default
	Peer       WGPeer   `yaml:"peer" json:"peer"`
}

// WGPeer supplies the remote endpoint, keys, and allowed tunnel destinations.
type WGPeer struct {
	Endpoint     string   `yaml:"endpoint" json:"endpoint"` // host:port
	PublicKey    string   `yaml:"public_key" json:"public_key"`
	PresharedKey string   `yaml:"preshared_key,omitempty" json:"preshared_key,omitempty"`
	AllowedIPs   []string `yaml:"allowed_ips,omitempty" json:"allowed_ips,omitempty"`
	Keepalive    uint16   `yaml:"keepalive,omitempty" json:"keepalive,omitempty"` // seconds; zero omits persistent keepalive
}

// Group routes either domain/address entries or IP-database selectors to one
// target. Countries come from country databases and Categories from category
// databases (labels such as RU-BLOCKED); Except negates their union.
type Group struct {
	Disabled   bool     `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	Preset     *Preset  `yaml:"preset,omitempty" json:"preset,omitempty"`
	Name       string   `yaml:"name" json:"name"`
	Target     string   `yaml:"target" json:"target"` // connection ID, direct, or block
	Entries    []string `yaml:"entries,omitempty" json:"entries"`
	Countries  []string `yaml:"countries,omitempty" json:"countries,omitempty"`   // uppercase ISO country codes
	Categories []string `yaml:"categories,omitempty" json:"categories,omitempty"` // uppercase category labels
	Except     bool     `yaml:"except,omitempty" json:"except,omitempty"`

	// Disabled selectors retain their configured values and preset membership.
	// Sets are value-based, so reordering rules cannot change activation state.
	DisabledEntries    []string `yaml:"disabled_entries,omitempty" json:"disabled_entries,omitempty"`
	DisabledCountries  []string `yaml:"disabled_countries,omitempty" json:"disabled_countries,omitempty"`
	DisabledCategories []string `yaml:"disabled_categories,omitempty" json:"disabled_categories,omitempty"`
}

// IsGeo reports whether the group matches IP-database selectors rather than entries.
func (g Group) IsGeo() bool { return len(g.Countries) > 0 || len(g.Categories) > 0 }

// Network applies a routing policy to a CIDR unless a client overrides it.
type Network struct {
	Name   string `yaml:"name" json:"name"`
	CIDR   string `yaml:"cidr" json:"cidr"`
	Mode   Mode   `yaml:"mode" json:"mode"`
	Target string `yaml:"target,omitempty" json:"target,omitempty"` // connection for full mode and inherited client targets
}

// Client identifies a device by MAC and optionally overrides its network policy.
type Client struct {
	Name   string `yaml:"name" json:"name"`
	MAC    string `yaml:"mac" json:"mac"`
	IP     string `yaml:"ip,omitempty" json:"ip,omitempty"` // static address; otherwise resolved from ARP/DHCP
	Mode   Mode   `yaml:"mode,omitempty" json:"mode,omitempty"`
	Target string `yaml:"target,omitempty" json:"target,omitempty"`
}

// Defaults fills unset fields and normalizes country codes before validation.
func (c *Config) Defaults() {
	if c.SchemaVersion == 0 {
		c.SchemaVersion = 1
	}
	c.GeoIP.defaults()
	for i := range c.Groups {
		g := &c.Groups[i]
		for _, labels := range [...][]string{g.Countries, g.Categories, g.DisabledCountries, g.DisabledCategories} {
			for j, label := range labels {
				labels[j] = strings.ToUpper(strings.TrimSpace(label))
			}
		}
	}
	if c.API.Listen == "" {
		c.API.Listen = "0.0.0.0:8086"
	}
	if c.API.TokenFile == "" {
		c.API.TokenFile = "/opt/etc/keenproxy/token"
	}
	if c.LAN.Interface == "" {
		c.LAN.Interface = "br0"
	}
	if c.DNS.Listen == "" {
		c.DNS.Listen = "0.0.0.0:5354"
	}
	if c.DNS.Fallback == "" {
		c.DNS.Fallback = "127.0.0.1:53"
	}
	if c.Failover.URL == "" {
		// Plain HTTP avoids requiring root certificates that may be absent
		// on the router.
		c.Failover.URL = "http://cp.cloudflare.com/generate_204"
	}
	if c.Failover.Interval == 0 {
		c.Failover.Interval = 15
	}
	if c.Failover.DownAfter == 0 {
		c.Failover.DownAfter = 60
	}
	if c.Failover.UpAfter == 0 {
		c.Failover.UpAfter = 120
	}
	if c.Intercept.Mode == "" {
		c.Intercept.Mode = InterceptRedirect
	}
	if c.Intercept.TCPPort == 0 {
		c.Intercept.TCPPort = 7901
	}
	if c.Intercept.UDPPort == 0 {
		c.Intercept.UDPPort = 7902
	}
	if c.Intercept.FWMark == 0 {
		c.Intercept.FWMark = 0x2000
	}
	if c.Intercept.RouteTable == 0 {
		c.Intercept.RouteTable = 120
	}
	c.normalizeConnections()
}

// normalizeConnections rewrites legacy TrustTunnel connections to canonical
// link connections. A malformed mix of the old section and a current payload
// is reported and left unchanged.
func (c *Config) normalizeConnections() []string {
	var errs []string
	for i := range c.Connections {
		if err := normalizeConnection(&c.Connections[i]); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return errs
}

func normalizeConnection(cn *Connection) error {
	where := fmt.Sprintf("connection %q", cn.ID)
	legacy := cn.TrustTunnel
	if cn.Type == ConnTrustTunnel {
		if cn.WireGuard != nil || cn.AmneziaWG != "" || cn.Outbound != nil || cn.Endpoint != nil {
			return fmt.Errorf("%s: legacy trusttunnel connection also has another protocol section; refusing to drop it", where)
		}
		if legacy == nil || strings.TrimSpace(legacy.Link) == "" {
			return fmt.Errorf("%s: legacy trusttunnel connection requires trusttunnel.link", where)
		}
		link := strings.TrimSpace(legacy.Link)
		if cn.Link != "" && strings.TrimSpace(cn.Link) != link {
			return fmt.Errorf("%s: link conflicts with trusttunnel.link; refusing to drop either", where)
		}
		cn.Type = ConnLink
		cn.Link = link
		cn.TrustTunnel = nil
		return nil
	}
	if legacy == nil {
		return nil
	}
	link := strings.TrimSpace(legacy.Link)
	current := strings.TrimSpace(cn.Link)
	switch {
	case link != "" && current != "" && current != link:
		return fmt.Errorf("%s: trusttunnel.link conflicts with link; refusing to drop either", where)
	case link != "" && cn.Type != ConnLink:
		return fmt.Errorf("%s: trusttunnel.link conflicts with type %q; refusing to drop it", where, cn.Type)
	case link != "" && cn.Type == ConnLink && current == "":
		return fmt.Errorf("%s: type link is missing link and also has trusttunnel.link; refusing to choose one", where)
	case cn.Type == ConnLink && (link == "" || link == current):
		cn.TrustTunnel = nil
		return nil
	default:
		return fmt.Errorf("%s: trusttunnel section conflicts with type %q; refusing to drop it", where, cn.Type)
	}
}

// Validate checks the complete configuration and aggregates errors.
func (c *Config) Validate() error {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	errs = append(errs, c.normalizeConnections()...)
	c.validateFeatures(add)
	c.GeoIP.validate(add)
	if mib := c.System.MemoryLimitMiB; mib != nil && (*mib < 1 || *mib > maxMemoryLimitMiB) {
		add("system.memory_limit_mib: must be a positive integer no greater than %d", maxMemoryLimitMiB)
	}

	switch c.Intercept.Mode {
	case InterceptRedirect, InterceptTProxy:
	default:
		add("intercept.mode: unknown mode %q", c.Intercept.Mode)
	}
	if c.Intercept.RouteTable < 1 || c.Intercept.RouteTable > 252 {
		// Keenetic BusyBox ip accepts table IDs up to 255; 253–255 are reserved.
		add("intercept.route_table: %d outside range 1–252", c.Intercept.RouteTable)
	}
	if _, err := netip.ParseAddrPort(c.DNS.Listen); err != nil {
		add("dns.listen: %v", err)
	}
	if _, err := netip.ParseAddrPort(c.API.Listen); err != nil {
		add("api.listen: %v", err)
	}
	for i, s := range c.API.NoTokenFrom {
		if _, err := netip.ParsePrefix(strings.TrimSpace(s)); err != nil {
			add("api.no_token_from[%d]: %q requires a network such as 192.168.1.0/24", i, s)
		}
	}
	for i, u := range c.DNS.Upstreams {
		if _, err := ParseUpstream(u); err != nil {
			add("dns.upstreams[%d]: %v", i, err)
		}
	}

	conns := map[string]bool{}
	for i, cn := range c.Connections {
		switch {
		case cn.ID == "":
			add("connections[%d]: empty id", i)
		case cn.ID == TargetDirect || cn.ID == TargetBlock:
			add("connections[%d]: id %q is reserved", i, cn.ID)
		case conns[cn.ID]:
			add("connections[%d]: duplicate id %q", i, cn.ID)
		}
		conns[cn.ID] = true
		validateConnection(cn, add)
	}
	for i, cn := range c.Connections {
		where := fmt.Sprintf("connections[%d] %q", i, cn.ID)
		switch {
		case cn.Fallback == "" || cn.Fallback == TargetDirect:
		case cn.Fallback == cn.ID:
			add("%s: fallback cannot be the connection itself", where)
		case cn.Fallback == TargetBlock:
			add("%s: fallback must be a connection or direct, not block", where)
		case !conns[cn.Fallback]:
			add("%s: unknown fallback %q", where, cn.Fallback)
		default:
			// Chain stops before repeats; a fallback on its final member indicates a cycle.
			chain := c.Chain(cn.ID)
			if next := fallbackOf(c, chain[len(chain)-1]); next != "" {
				add("%s: fallback cycle: %s → %s", where, strings.Join(chain, " → "), next)
			}
		}
	}
	if u, err := url.Parse(c.Failover.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		add("failover.url: expected http:// or https:// URL, got %q", c.Failover.URL)
	}
	if c.Failover.Interval < 1 || c.Failover.DownAfter < c.Failover.Interval || c.Failover.UpAfter < c.Failover.Interval {
		add("failover: interval must be at least 1 s; down_after and up_after must be at least interval")
	}
	target := func(where, t string, allowEmpty bool) {
		if t == "" && allowEmpty {
			return
		}
		if t != TargetDirect && t != TargetBlock && !conns[t] {
			add("%s: unknown target %q", where, t)
		}
	}

	for i, g := range c.Groups {
		where := fmt.Sprintf("groups[%d] %q", i, g.Name)
		target(where, g.Target, false)
		if g.IsGeo() && len(g.Entries) > 0 {
			add("%s: entries and countries or categories must be in separate groups", where)
		}
		if g.Except && !g.IsGeo() {
			add("%s: except requires at least one country or category", where)
		}
		for j, cat := range g.Categories {
			if !geoCategory.MatchString(cat) {
				add("%s categories[%d]: %q requires a label of Latin letters, digits and hyphens, such as RU-BLOCKED", where, j, cat)
			}
		}
		activeCategories := false
		for range g.ActiveCategories() {
			activeCategories = true
			break
		}
		if activeCategories && !c.GeoIP.hasCategories() {
			add("%s: categories require an enabled category database in geoip.databases", where)
		}
		for j, cc := range g.Countries {
			if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
				add("%s countries[%d]: %q requires an uppercase two-letter ISO code, such as RU", where, j, cc)
			}
		}
		for j, e := range g.Entries {
			if _, err := ParseEntry(e); err != nil {
				add("%s entries[%d]: %v", where, j, err)
			}
		}
	}
	for i, n := range c.Networks {
		where := fmt.Sprintf("networks[%d] %q", i, n.Name)
		if _, err := netip.ParsePrefix(n.CIDR); err != nil {
			add("%s: cidr: %v", where, err)
		}
		validateMode(where, n.Mode, false, add)
		target(where, n.Target, n.Mode != ModeFull)
		if n.Target == TargetBlock {
			add("%s: a whole network cannot target block; disable it with mode: off", where)
		}
	}
	macs := map[string]bool{}
	for i, cl := range c.Clients {
		where := fmt.Sprintf("clients[%d] %q", i, cl.Name)
		mac, err := net.ParseMAC(cl.MAC)
		if err != nil {
			add("%s: mac: %v", where, err)
		} else if macs[mac.String()] {
			add("%s: duplicate mac %s", where, mac)
		} else {
			macs[mac.String()] = true
		}
		if cl.IP != "" {
			if _, err := netip.ParseAddr(cl.IP); err != nil {
				add("%s: ip: %v", where, err)
			}
		}
		validateMode(where, cl.Mode, true, add)
		target(where, cl.Target, true)
		if cl.Target == TargetBlock {
			add("%s: target block is not supported for devices", where)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

func fallbackOf(c *Config, id string) string {
	for _, cn := range c.Connections {
		if cn.ID == id {
			return cn.Fallback
		}
	}
	return ""
}

func validateMode(where string, m Mode, allowInherit bool, add func(string, ...any)) {
	switch m {
	case ModeSplit, ModeFull, ModeOff:
	case ModeInherit:
		if !allowInherit {
			add("%s: missing mode", where)
		}
	default:
		add("%s: unknown mode %q", where, m)
	}
}

// validateConnection checks that the selected protocol has exactly one valid description.
func validateConnection(cn Connection, add func(string, ...any)) {
	where := fmt.Sprintf("connection %q", cn.ID)
	set := 0
	for _, has := range []bool{cn.WireGuard != nil, cn.AmneziaWG != "", cn.Link != "", cn.Outbound != nil, cn.Endpoint != nil, cn.TrustTunnel != nil} {
		if has {
			set++
		}
	}
	if set > 1 {
		add("%s: multiple connection definitions; expected one", where)
	}
	switch cn.Type {
	case ConnWireGuard:
		if cn.WireGuard == nil {
			add("%s: missing wireguard section", where)
			return
		}
		validateWireGuard(cn.ID, cn.WireGuard, add)
	case ConnAmneziaWG:
		if cn.AmneziaWG == "" {
			add("%s: missing amneziawg profile", where)
		} else if _, err := awg.Parse(cn.AmneziaWG); err != nil {
			add("%s: amneziawg: %v", where, err)
		}
	case ConnLink:
		if cn.Link == "" {
			add("%s: missing link", where)
		} else if _, err := links.Parse(cn.Link); err != nil {
			add("%s: link: %v", where, err)
		}
	case ConnSingBox:
		obj := cn.Outbound
		if obj == nil {
			obj = cn.Endpoint
		}
		if obj == nil {
			add("%s: outbound or endpoint is required", where)
			return
		}
		if t, _ := obj["type"].(string); t == "" {
			add("%s: sing-box object is missing type", where)
		}
		if _, ok := obj["tag"]; ok {
			add("%s: tag must not be set; it is derived from id", where)
		}
	case ConnTrustTunnel:
		// normalizeConnections already reported why this legacy type was not rewritten.
	default:
		add("%s: unknown type %q (wireguard, amneziawg, link, singbox)", where, cn.Type)
	}
}

// validateWireGuard checks tunnel addresses, endpoint syntax, and required key fields.
func validateWireGuard(id string, wg *WireGuard, add func(string, ...any)) {
	if wg.PrivateKey == "" {
		add("connection %q: empty private_key", id)
	}
	if len(wg.Address) == 0 {
		add("connection %q: missing address", id)
	}
	for _, a := range wg.Address {
		if _, err := netip.ParsePrefix(a); err != nil {
			add("connection %q: address %q: %v", id, a, err)
		}
	}
	if _, _, err := net.SplitHostPort(wg.Peer.Endpoint); err != nil {
		add("connection %q: peer.endpoint: %v", id, err)
	}
	if wg.Peer.PublicKey == "" {
		add("connection %q: empty peer.public_key", id)
	}
}

// Load reads, defaults, and validates a YAML configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse accepts exactly one YAML document, then applies defaults and validation.
func Parse(raw []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("expected exactly one YAML document")
	}
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Marshal serializes configuration as YAML for persistence.
func (c *Config) Marshal() ([]byte, error) {
	return yaml.Marshal(c)
}

// Clone deep-copies the small configuration through YAML, including nested
// raw sing-box objects.
func (c *Config) Clone() *Config {
	raw, err := c.Marshal()
	if err != nil {
		panic(err)
	}
	var out Config
	if err := yaml.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return &out
}
