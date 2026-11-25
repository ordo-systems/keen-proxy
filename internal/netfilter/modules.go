package netfilter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// KernelModuleStatus describes a preliminary capability check, not traffic health.
type KernelModuleStatus struct {
	State   string `json:"state"`
	CanLoad bool   `json:"can_load,omitempty"`
}

// GuardFamilies retains independent registration evidence for each IP family.
// Empty fields mean the platform was not confirmed to be Keenetic legacy.
type GuardFamilies struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

// GuardModuleStatus combines module eligibility with per-family evidence.
type GuardModuleStatus struct {
	KernelModuleStatus
	GuardFamilies
}

// KernelModules reports only the two firmware modules used by KeenProxy.
type KernelModules struct {
	Guard  GuardModuleStatus  `json:"guard"`
	TProxy KernelModuleStatus `json:"tproxy"`
}

// ErrModuleNotLoadable means the requested module is not an eligible recovery action.
var ErrModuleNotLoadable = errors.New("firmware module is not available to load")

const ipv6Conf = "/proc/sys/net/ipv6/conf"

// ModuleUnknown means the kernel inventory or firmware file could not be verified.
const ModuleUnknown = "unknown"

const (
	moduleRegistered         = "registered"
	moduleUnregistered       = "unregistered" // Registration alone says nothing about the file.
	moduleNotRequired        = "not_required"
	moduleLoadedUnregistered = "loaded_unregistered"
	moduleNotFound           = "not_found"
	moduleUnloaded           = "unloaded"
)

// FirmwareModuleName returns the only module allowed for a diagnostics feature.
func FirmwareModuleName(feature string) string {
	switch feature {
	case "guard":
		return "xt_comment"
	case "tproxy":
		return "xt_TPROXY"
	default:
		return ""
	}
}

func (f *Firewall) legacyKeenetic(ctx context.Context, readFile func(string) ([]byte, error), version func(context.Context, string) ([]byte, error)) (string, error) {
	release, err := readFile(kernelRelease)
	if err != nil {
		return "", err
	}
	release = bytes.TrimSpace(release)
	if !keeneticRelease.Match(release) || f == nil || f.IPTables == "" {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ver, err := version(ctx, f.IPTables)
	if err != nil || !legacyVersion.Match(bytes.TrimSpace(ver)) {
		return "", err
	}
	return string(release), nil
}

// KernelModuleDiagnostics reads kernel inventories without opening a firewall table.
func (f *Firewall) KernelModuleDiagnostics(ctx context.Context) KernelModules {
	release, _ := f.legacyKeenetic(ctx, os.ReadFile, iptablesVersion)
	unknown := KernelModuleStatus{State: ModuleUnknown}
	if release == "" || ctx.Err() != nil {
		return KernelModules{Guard: GuardModuleStatus{KernelModuleStatus: unknown}, TProxy: unknown}
	}
	root := os.DirFS("/")
	ipv6, known := ipv6Forwarding(root)
	families := guardRegistrations(root, ipv6, known)
	return KernelModules{
		Guard: GuardModuleStatus{
			KernelModuleStatus: moduleStatus(root, release, FirmwareModuleName("guard"), families.combined(), openFirmwareModule, firmwareCanLoad),
			GuardFamilies:      families,
		},
		TProxy: moduleStatus(root, release, FirmwareModuleName("tproxy"), tproxyRegistration(root), openFirmwareModule, firmwareCanLoad),
	}
}

// Diagnostics reports target registration; Settings separately checks mangle
// availability before treating the interception mode as ready.
func tproxyRegistration(root fs.FS) string {
	targets, ok := procInventory(root, ipv4Targets[1:])
	if !ok {
		return ModuleUnknown
	}
	if inventoryContains(targets, "TPROXY") {
		return moduleRegistered
	}
	return moduleUnregistered
}

func moduleStatus(root fs.FS, release, name, registration string, open func(string, string) (*os.File, error), canLoad func() bool) KernelModuleStatus {
	status, file := inspectModule(root, release, name, registration, open, canLoad)
	if file != nil {
		file.Close()
	}
	return status
}

// inspectModule returns the verified descriptor to its caller when the file is found.
func inspectModule(root fs.FS, release, name, registration string, open func(string, string) (*os.File, error), canLoad func() bool) (KernelModuleStatus, *os.File) {
	if registration != moduleUnregistered {
		return KernelModuleStatus{State: registration}, nil
	}
	modules, err := fs.ReadFile(root, kernelModules[1:])
	if err != nil {
		return KernelModuleStatus{State: ModuleUnknown}, nil
	}
	if moduleListed(modules, name) {
		return KernelModuleStatus{State: moduleLoadedUnregistered}, nil
	}
	file, err := open(release, name)
	if errors.Is(err, fs.ErrNotExist) {
		return KernelModuleStatus{State: moduleNotFound}, nil
	}
	if err != nil {
		return KernelModuleStatus{State: ModuleUnknown}, nil
	}
	return KernelModuleStatus{State: moduleUnloaded, CanLoad: canLoad()}, file
}

func procInventory(root fs.FS, path string) ([]byte, bool) {
	data, err := fs.ReadFile(root, path)
	return data, err == nil
}

func guardRegistrations(root fs.FS, ipv6, known bool) GuardFamilies {
	status := GuardFamilies{IPv4: guardFamilyRegistration(root, "ip"), IPv6: moduleNotRequired}
	switch {
	case !known:
		status.IPv6 = ModuleUnknown
	case ipv6:
		status.IPv6 = guardFamilyRegistration(root, "ip6")
	}
	return status
}

func guardFamilyRegistration(root fs.FS, family string) string {
	tables, ok := procInventory(root, "proc/net/"+family+"_tables_names")
	if !ok || !inventoryContains(tables, "filter") {
		return ModuleUnknown
	}
	matches, ok := procInventory(root, "proc/net/"+family+"_tables_matches")
	if !ok {
		return ModuleUnknown
	}
	if inventoryContains(matches, "comment") {
		return moduleRegistered
	}
	return moduleUnregistered
}

func (g GuardFamilies) combined() string {
	if g.IPv4 == ModuleUnknown || g.IPv6 == ModuleUnknown {
		return ModuleUnknown
	}
	if g.IPv4 == moduleUnregistered || g.IPv6 == moduleUnregistered {
		return moduleUnregistered
	}
	return moduleRegistered
}

func ipv6Forwarding(root fs.FS) (enabled, known bool) {
	path := ipv6Conf[1:]
	entries, err := fs.ReadDir(root, path)
	if err != nil {
		return false, errors.Is(err, fs.ErrNotExist)
	}
	known = len(entries) != 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		data, err := fs.ReadFile(root, path+"/"+entry.Name()+"/forwarding")
		switch {
		case err == nil && string(bytes.TrimSpace(data)) == "1":
			return true, true
		case err != nil || string(bytes.TrimSpace(data)) != "0":
			known = false
		}
	}
	return false, known
}

// LoadKernelModule rechecks eligibility and opens only an allowlisted firmware
// file for the running kernel. It never applies firewall or routing changes.
func (f *Firewall) LoadKernelModule(ctx context.Context, feature string) error {
	name := FirmwareModuleName(feature)
	if name == "" {
		return ErrModuleNotLoadable
	}
	release, _ := f.legacyKeenetic(ctx, os.ReadFile, iptablesVersion)
	if release == "" {
		return ErrModuleNotLoadable
	}
	root := os.DirFS("/")
	registration := tproxyRegistration
	if feature == "guard" {
		ipv6, known := ipv6Forwarding(root)
		if !known {
			return fmt.Errorf("%w: IPv6 forwarding state could not be verified", ErrModuleNotLoadable)
		}
		registration = func(root fs.FS) string { return guardRegistrations(root, ipv6, true).combined() }
	}
	return loadKernelModule(ctx, root, release, name, registration, openFirmwareModule, firmwareCanLoad, loadFirmwareModule)
}

func loadKernelModule(ctx context.Context, root fs.FS, release, name string, registration func(fs.FS) string, open func(string, string) (*os.File, error), canLoad func() bool, load func(*os.File) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	status, file := inspectModule(root, release, name, registration(root), open, canLoad)
	if file != nil {
		defer file.Close()
	}
	switch status.State {
	case moduleRegistered:
		return nil
	case moduleLoadedUnregistered:
		return fmt.Errorf("%w: already loaded but not registered", ErrModuleNotLoadable)
	case moduleNotFound:
		return fmt.Errorf("%w: file not found in running firmware", ErrModuleNotLoadable)
	case moduleUnloaded:
		if !status.CanLoad {
			return fmt.Errorf("%w: kernel module loading is not permitted", ErrModuleNotLoadable)
		}
	default:
		return fmt.Errorf("%w: kernel state or firmware file could not be verified", ErrModuleNotLoadable)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := load(file); err != nil {
		return fmt.Errorf("load %s: %w", name, err)
	}
	if registration(root) == moduleRegistered {
		return nil
	}
	return fmt.Errorf("%s loaded but the kernel did not report the required facility", name)
}
