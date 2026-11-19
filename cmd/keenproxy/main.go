// Command keenproxy runs the router daemon with an embedded sing-box engine.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/api"
	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/devices"
	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/ndmhook"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
	"github.com/ordo-systems/keen-proxy/internal/update"
	"github.com/ordo-systems/keen-proxy/web"

	// Routers often lack a CA bundle. The Mozilla roots are used only when the
	// system has none, so HTTPS downloads (country databases, filter lists) work.
	_ "golang.org/x/crypto/x509roots/fallback"
)

// main selects read-only disclosure, dry-run, synthetic demo, or the live router lifecycle.
func main() {
	configPath := flag.String("config", "/opt/etc/keenproxy/config.yaml", "configuration file path")
	arpPath := flag.String("arp", "/proc/net/arp", "ARP table path")
	ruleSetDir := flag.String("rule-sets", "/opt/var/lib/keenproxy/rule-sets", "derived rule-set directory")
	watch := flag.Duration("watch", 30*time.Second, "watchdog interval for firewall and device discovery")
	dryRun := flag.Bool("dry-run", false, "print derived engine/firewall settings without applying them")
	iptables := flag.String("iptables", "/opt/sbin/iptables", "Entware iptables executable")
	restore := flag.String("iptables-restore", "/opt/sbin/iptables-restore", "Entware iptables-restore executable")
	uiDemo := flag.Bool("ui-demo", false, "serve synthetic UI demo data without changing network state")
	key := flag.Bool("key", false, "print the current panel token and exit")
	showURL := flag.Bool("url", false, "print the configured panel URL and exit")
	startupProtocol := flag.Bool("startup-state-protocol", false, "print the service readiness protocol version and exit")
	flag.Parse()
	if *startupProtocol {
		fmt.Println("1")
		return
	}

	if err := rejectAccessConflict(*key, *showURL, *dryRun, *uiDemo); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *key || *showURL {
		if err := discloseAccess(os.Stdout, *configPath, *key); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if *dryRun {
		if err := printDryRun(*configPath, *arpPath, *ruleSetDir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Keep journals beside derived rule sets; the UI demo uses memory only.
	journalDir := filepath.Join(filepath.Dir(*ruleSetDir), "journal")
	if *uiDemo {
		journalDir = ""
	}
	journals := journal.NewSet(journalDir)
	defer func() {
		for _, j := range journals {
			j.Close()
		}
	}()
	log := slog.New(journal.NewHandler(slog.NewTextHandler(os.Stderr, nil), journals[journal.System]))

	cfg, err := model.Load(*configPath)
	if err != nil {
		log.Error("configuration", "err", err)
		os.Exit(1)
	}
	if *uiDemo {
		if err := serveAPI(ctx, cfg, api.NewDemo(cfg), nil, log, nil); err != nil {
			log.Error("web interface", "err", err)
			os.Exit(1)
		}
		return
	}

	fw := netfilter.NewFirewall()
	fw.IPTables, fw.Restore = *iptables, *restore
	var onStartupActive func()
	var onStartupBlocked func()
	var onAPIListening func(context.Context)
	// Keep the environment variable compatible with existing service controllers.
	if path := os.Getenv("KEENPROXY_STARTUP_STATE_FILE"); path != "" {
		state := make(chan string, 1)
		listening := make(chan context.Context, 1)
		// One initial outcome comes from Run, whose callbacks execute under its lock.
		onStartupActive = func() { state <- "active" }
		onStartupBlocked = func() { state <- "management-only" }
		onAPIListening = func(ctx context.Context) { listening <- ctx }
		go publishStartupState(ctx, state, listening, path, log)
	}
	d := daemon.New(daemon.Options{
		ConfigPath: *configPath, ARPPath: *arpPath, RuleSetDir: *ruleSetDir, WatchInterval: *watch,
		Firewall: fw, Log: log, Journals: journals, SingBoxLog: singBoxLog(journals[journal.System], log),
		OnStartupActive:  onStartupActive,
		OnStartupBlocked: onStartupBlocked,
	})
	hook, err := ndmhook.Start(*configPath, d.NotifyFirewallChange, log)
	if err != nil {
		log.Warn("netfilter event hook unavailable; polling remains active", "err", err)
	} else if hook != nil {
		log.Info("netfilter event hook enabled; polling remains active")
	}
	defer hook.Close()
	updates := update.NewManaged(*configPath, log)
	go updates.Run(ctx)
	// A management API failure must not stop the independent routing daemon.
	go func() {
		if err := serveAPI(ctx, cfg, d, updates, log, onAPIListening); err != nil {
			log.Error("web interface failed to start", "err", err)
		}
	}()
	if err := d.Run(ctx); err != nil {
		log.Error("keenProxy stopped with an error", "err", err)
		hook.Close()
		os.Exit(1)
	}
}

// singBoxLog exposes a retained pipe to each engine instance and mirrors its
// output into the system journal and stderr. Linux uses /proc/self/fd.
func singBoxLog(j *journal.Journal, log *slog.Logger) string {
	r, w, err := os.Pipe()
	if err != nil {
		log.Warn("sing-box logs will not be collected", "err", err)
		return ""
	}
	go journal.ReadSingBox(r, j, os.Stderr)
	singBoxPipe = w
	return engine.PipeLogPath(w.Fd())
}

// singBoxPipe retains the writer so garbage collection cannot close the descriptor.
var singBoxPipe *os.File

// publishStartupState waits for a positive startup result from Run. Active
// interception does not depend on the API; a parked daemon needs a bound API.
func publishStartupState(ctx context.Context, state <-chan string, listening <-chan context.Context, path string, log *slog.Logger) {
	var mode string
	select {
	case <-ctx.Done():
		return
	case mode = <-state:
	}
	if mode == "management-only" {
		select {
		case <-ctx.Done():
			return
		case apiCtx := <-listening:
			if apiCtx.Err() != nil {
				return
			}
		}
	}
	if ctx.Err() != nil {
		return
	}
	if err := writeStartupState(path, mode); err != nil {
		log.Warn("could not report startup state", "state", mode, "err", err)
	}
}

func writeStartupState(path, mode string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".startup-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = fmt.Fprintf(f, "%s %d\n", mode, os.Getpid())
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

// serveAPI serves management requests until cancellation, using startup bind
// and token settings; it does not apply routing changes itself.
func serveAPI(ctx context.Context, cfg *model.Config, d api.Daemon, updates *update.Manager, log *slog.Logger, onListening func(context.Context)) error {
	token, created, err := api.LoadToken(cfg.API.TokenFile)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	if created {
		log.Info("web interface login token created", "file", cfg.API.TokenFile, "token", token)
	}
	srv := &http.Server{
		Addr:              cfg.API.Listen,
		Handler:           (&api.Server{D: d, Token: token, UI: web.FS(), Log: log, Updates: updates}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	log.Info("web interface", "addr", "http://"+cfg.API.Listen)
	if onListening != nil {
		onListening(ctx)
	}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// printDryRun renders derived settings without enabling interception; output may contain secrets.
func printDryRun(configPath, arpPath, ruleSetDir string) error {
	cfg, err := model.Load(configPath)
	if err != nil {
		return err
	}
	neighbors, _ := devices.ReadARP(arpPath, cfg.LAN.Interface)
	out, err := compile.Compile(compile.Input{Config: cfg, Neighbors: neighbors, RuleSetDir: ruleSetDir})
	if err != nil {
		return err
	}
	fmt.Println("# sing-box")
	fmt.Println(string(out.SingBox))
	names := make([]string, 0, len(out.RuleSets))
	for name := range out.RuleSets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("\n# %s/%s\n%s\n", ruleSetDir, name, out.RuleSets[name])
	}
	fmt.Println("\n# iptables-restore --noflush")
	fmt.Print(out.Plan.Render())
	fmt.Println("\n# jumps")
	for _, j := range out.Plan.Jumps() {
		fmt.Printf("iptables -t %s -I %s 1 -j %s\n", j.Table, j.From, j.To)
	}
	return nil
}
