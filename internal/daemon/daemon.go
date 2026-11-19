// Package daemon coordinates configuration, compilation, sing-box, DNS, and
// firewall lifecycle. Its watchdog restores runtime state, while Apply updates
// configuration and restarts only components whose inputs changed.
package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/catalog"
	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/devices"
	"github.com/ordo-systems/keen-proxy/internal/dnsfront"
	"github.com/ordo-systems/keen-proxy/internal/domaincache"
	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/filterlist"
	"github.com/ordo-systems/keen-proxy/internal/geoip"
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/lists"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
	"github.com/ordo-systems/keen-proxy/internal/stats"
)

// Options supplies local paths, runtime dependencies, and watchdog settings.
type Options struct {
	ConfigPath    string
	ARPPath       string        // /proc/net/arp
	RuleSetDir    string        // local sing-box client address rule-sets
	WatchInterval time.Duration // watchdog interval for firewall and neighbor checks
	Firewall      *netfilter.Firewall
	Log           *slog.Logger
	Journals      journal.Set                                                          // nil creates in-memory journals
	SingBoxLog    string                                                               // sing-box log destination (see engine.LogOutput)
	DeviceNames   func(context.Context, map[string]netip.Addr) map[string]devices.Name // optional local name source
	// OnStartupBlocked runs under the daemon lock once management-only startup
	// is initialized. It must return promptly without calling daemon methods.
	OnStartupBlocked func()
	// OnStartupActive runs under the daemon lock after the initial apply in Run,
	// not after a later Apply or recovery. It must return promptly without calling daemon methods.
	OnStartupActive func()
}

// Daemon owns runtime components and coordinates serialized configuration changes.
type Daemon struct {
	domainGeneration  atomic.Pointer[domainGeneration]
	filters           *filterlist.Manager
	featureMu         sync.Mutex
	dnsInfo           DNSInfo
	domains           *domaincache.Cache
	domainSlots       chan struct{}
	domainMu          sync.Mutex
	domainError       string
	domainWritten     time.Time
	domainFingerprint []byte
	opt               Options
	log               *slog.Logger
	tproxyProbe       func(context.Context) netfilter.TProxyReadiness

	// startupBlocked is protected by mu and closed on first successful activation.
	startupBlocked chan struct{}

	mu           sync.Mutex // serializes apply and protects runtime state below, except atomic live
	runCtx       context.Context
	closed       bool
	cfg          *model.Config
	eng          engine.Engine
	dns          *dnsfront.Server
	route        netfilter.TProxyRoute
	routeOn      bool
	routeRelease func() error // ownership-aware cleanup for a recovered TPROXY route
	plan         netfilter.Plan
	planOn       bool
	planPending  bool // installation failed after the plan and its dependencies were prepared
	neighbors    map[string]netip.Addr
	deviceNames  map[string]cachedDeviceName
	started      time.Time
	restored     int // number of watchdog firewall restorations
	stats        *stats.Tracker
	geo          geoState
	// geoStore owns downloaded IP databases; geoWake triggers a check.
	geoStore *geoip.Store
	geoWake  chan struct{}
	// firewallWake coalesces external checks; the watchdog remains the sole consumer.
	firewallWake chan struct{}
	// serverHosts maps connection IDs to server hosts from the latest compilation.
	serverHosts map[string]string
	journals    journal.Set
	// live publishes the current configuration to route logging without d.mu.
	live atomic.Pointer[model.Config]
	// coreRestarted records whether the latest applyLocked restarted the engine.
	coreRestarted bool
	// memoryBaseline is the process limit captured before configuration is applied.
	memoryBaseline int64
	// memoryDefault honors the startup limit, falling back to 768 MiB when unset.
	memoryDefault int64
	// memoryActive is the limit from the last successful activation.
	memoryActive int64
	// Fallback chains, selected members, and probe results from the latest
	// compilation (see failover.go).
	chains  []compile.FailoverChain
	active  map[string]string
	health  map[string]*health
	allDown map[string]bool
}

// New creates a daemon with default paths and in-memory journals when omitted.
// It captures the current process memory limit and does not start listeners
// or install interception rules.
func New(opt Options) *Daemon {
	baseline := debug.SetMemoryLimit(-1)
	memoryDefault := baseline
	if baseline == math.MaxInt64 && os.Getenv("GOMEMLIMIT") == "" {
		memoryDefault = 768 * 1024 * 1024
	}
	if opt.DeviceNames == nil {
		opt.DeviceNames = devices.NewNameLookup()
	}
	if opt.WatchInterval == 0 {
		opt.WatchInterval = 30 * time.Second
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if opt.RuleSetDir == "" {
		opt.RuleSetDir = "/opt/var/lib/keenproxy/rule-sets"
	}
	if opt.Journals == nil {
		opt.Journals = journal.NewSet("")
	}
	d := &Daemon{
		domains: domaincache.New(time.Now), domainSlots: make(chan struct{}, 4), opt: opt, log: opt.Log, stats: stats.NewTracker(), journals: opt.Journals,
		active: map[string]string{}, health: map[string]*health{}, allDown: map[string]bool{},
	}
	d.tproxyProbe = opt.Firewall.TProxyReadiness
	d.memoryBaseline = baseline
	d.memoryDefault = memoryDefault
	d.memoryActive = baseline
	d.filters = filterlist.New(filepath.Join(filepath.Dir(opt.RuleSetDir), "filters"), nil)
	d.geoStore = geoip.NewStore(filepath.Join(filepath.Dir(opt.RuleSetDir), "geoip"))
	d.geoWake = make(chan struct{}, 1)
	d.firewallWake = make(chan struct{}, 1)
	d.resetDomainGeneration()
	d.stats.OnRoute = d.onRoute
	d.eng.Tracker = d.stats
	d.eng.LogOutput = opt.SingBoxLog
	return d
}

// Run serves until ctx is canceled. Interception starts last and stops first
// so clients retain access to a DNS resolver during lifecycle transitions.
func (d *Daemon) Run(ctx context.Context) error {
	d.mu.Lock()
	if d.runCtx != nil || d.closed {
		d.mu.Unlock()
		return errors.New("daemon cannot run more than once")
	}
	d.runCtx = ctx
	defer d.shutdown()
	activated, err := func() (<-chan struct{}, error) {
		defer d.mu.Unlock()
		activated, err := d.startLocked(ctx)
		if err != nil {
			d.closed = true
		}
		return activated, err
	}()
	if err != nil {
		d.audit("system", "Start keenProxy", "core", "error", err.Error())
		return err
	}
	go d.stats.Run(ctx)
	if activated != nil {
		// The API can activate interception by applying a configuration while Run waits.
		select {
		case <-activated:
		case <-ctx.Done():
		}
	}
	if ctx.Err() == nil {
		go d.runGeoUpdates(ctx)
		go d.runFailover(ctx)
		go d.runDomains(ctx)
		go d.runFilterUpdates(ctx)
		go d.runDeviceNames(ctx)
		d.runWatchdog(ctx)
	}
	d.log.Info("stopping keenProxy")
	d.audit("system", "Stop keenProxy", "core", "info", "interception rules removed, network uses direct routing")
	return nil
}

func (d *Daemon) startLocked(ctx context.Context) (<-chan struct{}, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	cfg, err := model.Load(d.opt.ConfigPath)
	if err != nil {
		return nil, err
	}
	catalog.AutoUpdate(cfg)
	d.started = time.Now()
	blocked := d.tproxyPreflight(ctx, cfg)
	if ctx.Err() != nil {
		return nil, nil
	}
	// Apply the saved recommendation before geo databases and the embedded core start.
	if blocked == nil {
		if err := d.stageMemoryLimit(cfg); err != nil {
			return nil, err
		}
	}
	d.adoptLegacyGeo(cfg)
	d.reloadGeoLocked(cfg)
	d.neighbors = d.readNeighbors(cfg)
	if blocked != nil {
		d.stopInterceptionLocked()
		if err := d.detachStartupJumps(); err != nil {
			return nil, fmt.Errorf("detach residual interception rules: %w", err)
		}
		if ctx.Err() != nil {
			return nil, nil
		}
		d.startupBlocked = make(chan struct{})
		d.cfg = cfg
		d.live.Store(cfg)
		d.log.Warn("keenProxy started without interception", "err", blocked)
		d.audit("system", "Start keenProxy without interception", "core", "warn", blocked.Error())
		if d.opt.OnStartupBlocked != nil {
			d.opt.OnStartupBlocked()
		}
		return d.startupBlocked, nil
	}
	if err := d.applyLocked(ctx, cfg); err != nil {
		return nil, err
	}
	d.log.Info("keenProxy started", "mode", cfg.Intercept.Mode, "sources", len(d.plan.Sources), "dns", d.dns.Addr())
	d.audit("system", "Start keenProxy", "core", "ok",
		fmt.Sprintf("interception %s, sources %d, DNS %s", cfg.Intercept.Mode, len(d.plan.Sources), d.dns.Addr()))
	if ctx.Err() == nil && d.opt.OnStartupActive != nil {
		d.opt.OnStartupActive()
	}
	return nil, nil
}

// Apply validates, applies, and persists configuration. Recovery from blocked
// startup commits only after saving; an already-active daemon can report an
// applied-but-unsaved change.
func (d *Daemon) Apply(ctx context.Context, cfg *model.Config) error {
	by, from := applyActor(ctx)
	cfg.Defaults()
	catalog.AutoUpdate(cfg)
	if err := cfg.Validate(); err != nil {
		d.audit(by, "Configuration rejected", "config", "error", err.Error()+from)
		return err
	}
	// Compile first so protocol errors do not disturb the running configuration.
	if _, err := compile.Compile(compile.Input{Config: cfg, RuleSetDir: d.opt.RuleSetDir}); err != nil {
		d.audit(by, "Configuration rejected", "config", "error", err.Error()+from)
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.applyConfigLocked(ctx, cfg, true)
}

func applyActor(ctx context.Context) (by, from string) {
	who := actorOf(ctx)
	if who.From != "" {
		from = " (from " + who.From + ")"
	}
	return who.Who, from
}

func (d *Daemon) applyAdmissionLocked(ctx context.Context) error {
	if d.closed || (d.runCtx != nil && d.runCtx.Err() != nil) {
		return errors.New("daemon is stopping")
	}
	return ctx.Err()
}

// applyConfigLocked is shared by draft Apply and saved recovery.
func (d *Daemon) applyConfigLocked(ctx context.Context, cfg *model.Config, save bool) error {
	if err := d.applyAdmissionLocked(ctx); err != nil {
		return err
	}
	by, from := applyActor(ctx)
	if err := d.tproxyPreflight(ctx, cfg); err != nil {
		d.audit(by, "Configuration rejected", "config", "error", err.Error()+from)
		return err
	}
	if err := d.applyAdmissionLocked(ctx); err != nil {
		return err
	}
	prev := d.cfg
	changes := configChanges(prev, cfg)
	activation := d.startupBlocked
	neighbors := d.neighbors
	if err := d.applyLocked(ctx, cfg); err != nil {
		details := err.Error()
		restore := journalRestoreFailure(err)
		var rollbackRestore *journal.RestoreDiagnostic
		if activation != nil {
			d.log.Error("configuration failed to activate, interception remains inactive", "err", err)
			d.restoreInactiveLocked(prev)
			d.neighbors = neighbors
			details += "; interception remains inactive"
		} else if prev != nil {
			d.log.Error("new configuration failed to apply, restoring previous configuration", "err", err)
			if rbErr := d.applyLocked(ctx, prev); rbErr != nil {
				d.log.Error("rollback also failed", "err", rbErr)
				details += "; rollback also failed: " + rbErr.Error()
				rollbackRestore = journalRestoreFailure(rbErr)
			} else {
				details += "; previous configuration restored"
			}
		}
		entry := journal.Entry{Actor: by, Action: "Configuration apply failed", Target: "config", Result: "error", Details: details + from}
		if restore != nil || rollbackRestore != nil {
			entry.FirewallApply = &journal.FirewallApplyDiagnostic{Restore: restore, RollbackRestore: rollbackRestore}
		}
		d.auditEntry(entry)
		return err
	}
	if activation != nil {
		err := d.applyAdmissionLocked(ctx)
		if err == nil && save {
			err = d.persistConfig(cfg, true)
		}
		if err != nil {
			d.restoreInactiveLocked(prev)
			d.neighbors = neighbors
			d.audit(by, "Configuration apply failed", "config", "error", err.Error()+"; interception remains inactive"+from)
			return err
		}
		d.commitMemoryLimit(cfg)
		d.live.Store(cfg)
		d.startupBlocked = nil
		close(activation)
	} else if save {
		if err := d.persistConfig(cfg, false); err != nil {
			d.audit(by, "Configuration applied but not saved", "config", "warn", err.Error()+from)
			return fmt.Errorf("configuration applied but not saved: %w", err)
		}
	}
	action := "Apply configuration"
	if save {
		d.log.Info("configuration applied and saved")
	} else {
		action = "Activate saved configuration"
		d.log.Info("saved configuration activated")
	}
	core := "core not restarted"
	if d.coreRestarted {
		core = "core restarted"
	}
	d.audit(by, action, "config", "ok", changes+"; "+core+from)
	if prev == nil || !reflect.DeepEqual(prev.GeoIP, cfg.GeoIP) {
		// New or re-enabled databases download without waiting for the next check.
		d.wakeGeo()
	}
	go d.refreshConnCountries(context.Background())
	return nil
}

func (d *Daemon) persistConfig(cfg *model.Config, recovery bool) error {
	raw, err := cfg.Marshal()
	if err != nil {
		return err
	}
	if previous, err := os.ReadFile(d.opt.ConfigPath); err == nil {
		if recovery {
			return persistRecoveryConfig(d.opt.ConfigPath, previous, raw)
		}
		if err := writeFile(d.opt.ConfigPath+".previous", previous, 0o600); err != nil {
			return fmt.Errorf("previous configuration was not saved: %w", err)
		}
	} else if recovery {
		return fmt.Errorf("previous configuration could not be read: %w", err)
	}
	if err := writeFile(d.opt.ConfigPath, raw, 0o600); err != nil {
		return fmt.Errorf("configuration was not saved: %w", err)
	}
	return nil
}

// persistRecoveryConfig stages the main YAML before publishing its backup.
// If the final rename fails, the original rollback snapshot can be restored
// without allocating disk space. Ordinary active applies keep their best-effort
// persistence behavior.
func persistRecoveryConfig(path string, original, next []byte) error {
	mainChanged := !bytes.Equal(original, next)
	var mainTemp string
	if mainChanged {
		var err error
		mainTemp, err = stageRecoveryFile(path, next)
		if err != nil {
			return fmt.Errorf("configuration was not saved: %w", err)
		}
		defer os.Remove(mainTemp)
	}

	previousPath := path + ".previous"
	previous, err := os.ReadFile(previousPath)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return fmt.Errorf("rollback snapshot could not be read: %w", err)
	}
	previousChanged := missing || !bytes.Equal(previous, original)
	var rollbackTemp string
	if previousChanged {
		if mainChanged && !missing {
			rollbackTemp, err = stageRecoveryFile(previousPath+".recovery", previous)
			if err != nil {
				return fmt.Errorf("rollback snapshot was not saved: %w", err)
			}
			defer func() {
				if rollbackTemp != "" {
					os.Remove(rollbackTemp)
				}
			}()
		}
		previousTemp, err := stageRecoveryFile(previousPath, original)
		if err != nil {
			return fmt.Errorf("previous configuration was not saved: %w", err)
		}
		defer os.Remove(previousTemp)
		if err := os.Rename(previousTemp, previousPath); err != nil {
			return fmt.Errorf("previous configuration was not saved: %w", err)
		}
	}

	if !mainChanged {
		return nil
	}
	if err := os.Rename(mainTemp, path); err != nil {
		saveErr := fmt.Errorf("configuration was not saved: %w", err)
		if previousChanged {
			if missing {
				if err := os.Remove(previousPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					return errors.Join(saveErr, fmt.Errorf("rollback snapshot could not be removed: %w", err))
				}
			} else if err := os.Rename(rollbackTemp, previousPath); err != nil {
				preserved := rollbackTemp
				rollbackTemp = "" // Keep the distinct snapshot available for manual recovery.
				return errors.Join(saveErr, fmt.Errorf("could not restore rollback snapshot from %s: %w", preserved, err))
			}
		}
		return saveErr
	}
	return nil
}

func stageRecoveryFile(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// applyLocked reconciles runtime state with cfg while d.mu is held.
func (d *Daemon) applyLocked(ctx context.Context, cfg *model.Config) error {
	prev := d.cfg
	if d.startupBlocked != nil {
		d.neighbors = d.readNeighbors(cfg)
	}
	// A new attempt may change the old plan's dependencies before it reaches iptables.
	d.planPending = false
	if err := d.stageMemoryLimit(cfg); err != nil {
		return err
	}
	applied := false
	defer func() {
		if !applied {
			debug.SetMemoryLimit(d.memoryActive)
		}
	}()
	d.resetDomainGeneration()
	if prev != nil && !reflect.DeepEqual(prev.GeoIP, cfg.GeoIP) {
		d.reloadGeoLocked(cfg)
	}
	d.cfg = cfg
	if d.startupBlocked == nil {
		d.live.Store(cfg)
	}
	d.coreRestarted = false
	out, err := d.compileLocked()
	if err != nil {
		return err
	}
	if restarted, err := d.eng.Apply(out.SingBox); err != nil {
		return err
	} else if restarted && prev != nil && d.startupBlocked == nil {
		d.coreRestarted = true
		d.log.Info("sing-box core restarted with new configuration")
	}
	d.reselectLocked()
	d.filters.Configure(cfg.Filters)

	if d.dns == nil || prev == nil || dnsFrontendChanged(prev.DNS, cfg.DNS) || dnsGroupsChanged(prev.Groups, cfg.Groups) {
		if d.dns != nil {
			d.dns.Close()
			d.dns = nil
		}
		if err := d.startDNS(); err != nil {
			return fmt.Errorf("DNS: %w", err)
		}
	}

	newRoute := netfilter.TProxyRoute{Mark: cfg.Intercept.FWMark, Table: cfg.Intercept.RouteTable}
	wantRoute := cfg.Intercept.Mode == model.InterceptTProxy
	if d.routeOn && (!wantRoute || newRoute != d.route) {
		d.removeRouteLocked()
	}
	if wantRoute && !d.routeOn {
		var err error
		if d.startupBlocked != nil {
			d.routeRelease, err = newRoute.Acquire()
		} else {
			err = newRoute.Apply()
		}
		if err != nil {
			return err
		}
		d.routeOn = true
	}
	d.route = newRoute

	// Interception mode changes require removing the complete previous chain set.
	if d.planOn && d.plan.Mode != out.Plan.Mode {
		d.removeFirewall()
	}
	d.plan = out.Plan
	if err := d.installFirewall(ctx); err != nil {
		if d.startupBlocked == nil {
			d.removeFirewall()
			d.planPending = true
		}
		return fmt.Errorf("interception rules: %w", err)
	}
	if d.startupBlocked == nil {
		d.commitMemoryLimit(cfg)
	}
	applied = true
	return nil
}

// dnsFrontendChanged ignores the firewall-only source exemptions.
func dnsFrontendChanged(prev, next model.DNS) bool {
	prev.BypassSources, next.BypassSources = nil, nil
	// The serialized config can contain an empty list for omitted upstreams.
	if len(prev.Upstreams) == 0 && len(next.Upstreams) == 0 {
		prev.Upstreams, next.Upstreams = nil, nil
	}
	return !reflect.DeepEqual(prev, next)
}

// dnsGroupsChanged treats the empty lists inserted by the panel as omissions.
func dnsGroupsChanged(prev, next []model.Group) bool {
	return !slices.EqualFunc(prev, next, func(a, b model.Group) bool {
		if len(a.Entries) == 0 && len(b.Entries) == 0 {
			a.Entries, b.Entries = nil, nil
		}
		return reflect.DeepEqual(a, b)
	})
}

// shutdown removes interception before stopping the services it depends on
// and restores the process memory limit captured at initialization.
func (d *Daemon) shutdown() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	if g := d.domainGeneration.Load(); g != nil {
		g.cancel()
	}
	d.stopInterceptionLocked()
	d.geo.set.Close()
	d.geo.cats.Close()
	d.geo.set, d.geo.cats = nil, nil
	debug.SetMemoryLimit(d.memoryBaseline)
	d.memoryActive = d.memoryBaseline
}

// stopInterceptionLocked detaches firewall and routing state before closing listeners.
func (d *Daemon) stopInterceptionLocked() {
	if d.planOn || d.planPending {
		d.removeFirewall()
	}
	d.removeRouteLocked()
	if d.dns != nil {
		d.dns.Close()
		d.dns = nil
	}
	d.eng.Close()
}

func (d *Daemon) removeRouteLocked() {
	if !d.routeOn {
		return
	}
	release := d.routeRelease
	if release == nil {
		release = d.route.Remove
	}
	if err := release(); err != nil {
		d.log.Warn("remove TPROXY route", "err", err)
	}
	d.routeOn, d.routeRelease = false, nil
}

// restoreInactiveLocked tears down a failed first activation without activating
// the saved configuration that was intentionally skipped at startup.
func (d *Daemon) restoreInactiveLocked(cfg *model.Config) {
	d.stopInterceptionLocked()
	debug.SetMemoryLimit(d.memoryActive)
	d.plan = netfilter.Plan{}
	if !reflect.DeepEqual(d.cfg.GeoIP, cfg.GeoIP) {
		d.reloadGeoLocked(cfg)
	}
	d.cfg = cfg
	d.chains, d.serverHosts = nil, nil
	d.reselectLocked()
	d.filters.Configure(cfg.Filters)
	d.resetDomainGeneration()
}

// stageMemoryLimit applies cfg's recommendation, or the selected startup/default budget when unset.
// A rejected value is not forwarded to the runtime. Success is recorded only by commitMemoryLimit.
func (d *Daemon) stageMemoryLimit(cfg *model.Config) error {
	limit, ok := model.MemoryLimitBytes(cfg, d.memoryDefault)
	if !ok {
		return fmt.Errorf("system.memory_limit_mib: value cannot be applied")
	}
	debug.SetMemoryLimit(limit)
	return nil
}

// commitMemoryLimit records the recommendation after activation succeeds.
func (d *Daemon) commitMemoryLimit(cfg *model.Config) {
	if limit, ok := model.MemoryLimitBytes(cfg, d.memoryDefault); ok {
		d.memoryActive = limit
	}
}

// startDNS installs runtime matchers and opens both DNS transports before interception.
func (d *Daemon) startDNS() error {
	var blocks []model.Group
	for _, g := range d.cfg.Groups {
		if !g.Disabled && g.Target == model.TargetBlock {
			blocks = append(blocks, g)
		}
	}
	m := lists.New(blocks)
	cfg := d.dnsConfig(d.cfg.DNS)
	cfg.Observe = d.observeDomain
	cfg.DropAAAA = true
	cfg.Blocked = func(name string) bool { return m.Domain(name) != lists.NoMatch }
	canary := d.cfg.DNS.FirefoxCanary
	cfg.BlockReason = func(name string) string {
		if canary && strings.EqualFold(strings.TrimSuffix(name, "."), "use-application-dns.net") {
			return "firefox-canary"
		}
		return d.filters.Match(name)
	}
	cfg.OnRoute = d.recordDNSRoute
	cfg.OnBlock = d.recordDNSBlock
	d.dns = dnsfront.New(cfg)
	return d.dns.Start()
}

// watch refreshes neighbor addresses and restores missing interception rules.
func (d *Daemon) watch(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ctx.Err() != nil || (!d.planOn && !d.planPending) {
		return
	}
	if n := d.readNeighbors(d.cfg); !maps.Equal(n, d.neighbors) {
		d.audit("watchdog", "Device addresses updated", "clients", "info", neighborsChange(d.neighbors, n))
		d.neighbors = n
		out, err := d.compileLocked()
		if err != nil {
			d.log.Error("recompile", "err", err)
			return
		}
		// Client addresses live in watched rule-set files, so sing-box can
		// pick up changes without restarting.
		if restarted, err := d.eng.Apply(out.SingBox); err != nil {
			d.log.Error("restart sing-box", "err", err)
		} else if restarted {
			d.log.Warn("sing-box configuration changed after address updates, core restarted")
			d.reselectLocked()
		}
		d.plan = out.Plan
		if !d.planPending {
			if err := d.installFirewall(ctx); err != nil && ctx.Err() == nil {
				d.log.Error("rule update", "err", err)
			}
			return
		}
	}
	d.checkFirewall(ctx, "watchdog")
}

// compileLocked compiles configuration and writes local rule-sets while d.mu
// is held. sing-box loads the files at startup and watches subsequent changes.
func (d *Daemon) compileLocked() (compile.Output, error) {
	out, err := compile.Compile(compile.Input{Config: d.cfg, Neighbors: d.neighbors, RuleSetDir: d.opt.RuleSetDir})
	if err != nil {
		return out, err
	}
	if err := os.MkdirAll(d.opt.RuleSetDir, 0o755); err != nil {
		return out, err
	}
	for name, raw := range out.RuleSets {
		if strings.HasPrefix(name, "dns-") {
			continue
		}
		if err := writeFile(filepath.Join(d.opt.RuleSetDir, name), raw, 0o644); err != nil {
			return out, err
		}
	}
	if err := d.writeCountrySetsLocked(out.Countries); err != nil {
		return out, err
	}
	if err := d.writeCategorySetsLocked(out.Categories); err != nil {
		return out, err
	}
	d.writeDNSLocked()
	if d.domainError != "" {
		return out, fmt.Errorf("DNS rule-sets: %s", d.domainError)
	}
	d.serverHosts = out.ServerHosts
	d.chains = out.Failover
	return out, nil
}

// writeFile atomically replaces a file through a temporary file and rename.
// Identical contents are left untouched to avoid unnecessary watcher reloads.
func writeFile(path string, data []byte, perm os.FileMode) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readNeighbors builds the MAC-to-IP snapshot for the configured LAN interface.
func (d *Daemon) readNeighbors(cfg *model.Config) map[string]netip.Addr {
	n, err := devices.ReadARP(d.opt.ARPPath, cfg.LAN.Interface)
	if err != nil {
		d.log.Warn("ARP unavailable, clients without static IP are excluded", "err", err)
		return map[string]netip.Addr{}
	}
	return n
}

// removeFirewall removes active interception rules using a fresh bounded context.
func (d *Daemon) removeFirewall() {
	// Use a fresh context because cleanup must run after the serving context is canceled.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.opt.Firewall.Remove(ctx, d.plan); err != nil && !errors.Is(err, context.Canceled) {
		d.log.Warn("remove rules", "err", err)
	}
	d.planOn, d.planPending = false, false
}

// NoTokenFrom returns trusted dashboard networks from the atomic configuration
// snapshot, avoiding locks and configuration copies on every API request.
func (d *Daemon) NoTokenFrom() []netip.Prefix {
	if cfg := d.live.Load(); cfg != nil {
		return cfg.API.NoTokenPrefixes()
	}
	return nil
}

// Config returns a deep copy of the current configuration.
func (d *Daemon) Config() *model.Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg == nil {
		return nil
	}
	return d.cfg.Clone()
}

// Status summarizes daemon, engine, interception, and connection health for the API.
type Status struct {
	Started       time.Time `json:"started"`
	Mode          string    `json:"mode"`
	Sources       int       `json:"sources"`
	Connections   int       `json:"connections"`
	Groups        int       `json:"groups"`
	Entries       int       `json:"entries"`
	Clients       int       `json:"clients"`
	OnlineDevices int       `json:"online_devices"`
	DNS           string    `json:"dns"`
	Firewall      bool      `json:"firewall"`
	Restored      int       `json:"restored"`
	GeoIP         GeoInfo   `json:"geoip"`
	// ConnCountries maps connection IDs to server country codes for flags.
	ConnCountries map[string]string `json:"conn_countries"`
	// Failover maps fallback-enabled connection IDs to their selected members.
	Failover map[string]FailoverInfo `json:"failover"`
	// Health maps connection IDs to their latest probe results.
	Health map[string]ConnHealth `json:"health"`
}

// Status snapshots runtime health under d.mu and checks active firewall entry jumps.
func (d *Daemon) Status(ctx context.Context) Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := Status{Started: d.started, Restored: d.restored, OnlineDevices: len(d.neighbors)}
	if d.cfg == nil {
		return st
	}
	st.Mode = string(d.cfg.Intercept.Mode)
	st.Sources = len(d.plan.Sources)
	st.Connections = len(d.cfg.Connections)
	st.Groups = len(d.cfg.Groups)
	st.Clients = len(d.cfg.Clients)
	for _, g := range d.cfg.Groups {
		st.Entries += len(g.Entries)
	}
	if d.dns != nil {
		st.DNS = d.dns.Addr()
	}
	st.Firewall = d.planOn && d.opt.Firewall.Healthy(ctx, d.plan)
	st.GeoIP = d.geoInfoLocked()
	st.ConnCountries = d.geo.conns
	st.Failover, st.Health = d.failoverInfoLocked()
	return st
}

// Stats returns connection traffic history and summaries.
func (d *Daemon) Stats(withSeries bool) stats.Snapshot { return d.stats.Snapshot(withSeries) }

// Hosts returns per-host traffic for one connection.
func (d *Daemon) Hosts(tag, query string, limit int) ([]stats.Host, int) {
	return d.stats.Hosts(tag, query, limit)
}

// Device combines an ARP neighbor, configured client identity, and observed hostname.
type Device struct {
	MAC            string     `json:"mac"`
	IP             string     `json:"ip"`
	Client         string     `json:"client,omitempty"` // configured client name
	Mode           model.Mode `json:"mode,omitempty"`
	Hostname       string     `json:"hostname,omitempty"`
	HostnameSource string     `json:"hostname_source,omitempty"`
}

// Devices merges current LAN neighbors with configured client names and identities.
func (d *Daemon) Devices() []Device {
	d.mu.Lock()
	defer d.mu.Unlock()
	known := map[string]model.Client{}
	if d.cfg != nil {
		for _, c := range d.cfg.Clients {
			if mac, err := net.ParseMAC(c.MAC); err == nil {
				known[mac.String()] = c
			}
		}
	}
	var out []Device
	for mac, ip := range d.neighbors {
		dev := Device{MAC: mac, IP: ip.String()}
		if cached, ok := d.deviceNames[mac]; ok && cached.ip == ip && time.Now().Before(cached.expires) {
			dev.Hostname, dev.HostnameSource = cached.name.Hostname, cached.name.Source
		}
		if c, ok := known[mac]; ok {
			dev.Client, dev.Mode = c.Name, c.Mode
		}
		out = append(out, dev)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParseAddr(out[i].IP)
		b, _ := netip.ParseAddr(out[j].IP)
		return a.Less(b)
	})
	return out
}
