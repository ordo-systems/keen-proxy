package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ordo-systems/keen-proxy/internal/netfilter"
	"golang.org/x/sys/unix"
)

// FirmwareModuleAutoloadAction identifies changes to an explicit boot opt-in.
const FirmwareModuleAutoloadAction = "Firmware module autoload"

// KernelModuleDiagnostics reports firmware capabilities and saved opt-ins without changing routing.
func (d *Daemon) KernelModuleDiagnostics(ctx context.Context) netfilter.KernelModules {
	status := d.moduleDiagnostics(ctx)
	decorateAutoload(d.opt.ConfigPath, "guard", &status.Guard.KernelModuleStatus)
	decorateAutoload(d.opt.ConfigPath, "tproxy", &status.TProxy)
	return status
}

func decorateAutoload(configPath, feature string, status *netfilter.KernelModuleStatus) {
	marker, err := openAutoloadMarker(configPath, feature)
	if err != nil {
		status.CanAutoload = false
		return
	}
	defer unix.Close(marker.dir)
	status.Autoload, err = marker.enabled()
	if status.CanAutoload {
		status.CanAutoload = err == nil && (status.Autoload || marker.checkDirectory() == nil)
	}
}

// SetKernelModuleAutoload changes only the saved opt-in. It never loads or
// unloads a module, applies firewall rules, or persists the main configuration.
func (d *Daemon) SetKernelModuleAutoload(ctx context.Context, feature string, enabled bool) error {
	if netfilter.FirmwareModuleName(feature) == "" {
		return netfilter.ErrModuleNotLoadable
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.applyAdmissionLocked(ctx); err != nil {
		return err
	}
	by, from := applyActor(ctx)
	result := fmt.Sprintf("enabled=%t", enabled)
	err := d.setKernelModuleAutoloadLocked(ctx, feature, enabled)
	if err != nil {
		d.audit(by, FirmwareModuleAutoloadAction, feature, "error", result+": "+err.Error()+from)
	} else {
		d.audit(by, FirmwareModuleAutoloadAction, feature, "ok", result+from)
	}
	return err
}

func (d *Daemon) setKernelModuleAutoloadLocked(ctx context.Context, feature string, enabled bool) error {
	if enabled {
		status := d.moduleDiagnostics(ctx)
		canAutoload := status.TProxy.CanAutoload
		if feature == "guard" {
			canAutoload = status.Guard.CanAutoload
		}
		if err := d.applyAdmissionLocked(ctx); err != nil {
			return err
		}
		if !canAutoload {
			return fmt.Errorf("%w: feature must be registered and present in running firmware", netfilter.ErrModuleNotLoadable)
		}
	}
	marker, err := openAutoloadMarker(d.opt.ConfigPath, feature)
	if err != nil {
		if !enabled && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer unix.Close(marker.dir)
	if !enabled {
		if err := unix.Unlinkat(marker.dir, marker.name, 0); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove autoload marker: %w", err)
		}
		return nil
	}
	if err := marker.checkDirectory(); err != nil {
		return err
	}
	fd, err := unix.Openat(marker.dir, marker.name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if errors.Is(err, os.ErrExist) {
		if present, inspectErr := marker.enabled(); inspectErr != nil || present {
			return inspectErr
		}
	}
	if err != nil {
		return fmt.Errorf("create autoload marker: %w", err)
	}
	return unix.Close(fd)
}

// autoloadMarker pins the configured directory. Marker names are never
// supplied by callers, and the opt-in is represented by a trusted empty file.
type autoloadMarker struct {
	dir  int
	name string
}

func openAutoloadMarker(configPath, feature string) (autoloadMarker, error) {
	if netfilter.FirmwareModuleName(feature) == "" || configPath == "" {
		return autoloadMarker{}, netfilter.ErrModuleNotLoadable
	}
	path := configPath + ".autoload-" + feature
	dir, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return autoloadMarker{}, fmt.Errorf("open autoload marker directory: %w", err)
	}
	return autoloadMarker{dir: dir, name: filepath.Base(path)}, nil
}

func (m autoloadMarker) checkDirectory() error {
	var st unix.Stat_t
	if err := unix.Fstat(m.dir, &st); err != nil {
		return fmt.Errorf("inspect autoload marker directory: %w", err)
	}
	if !trustedAutoloadOwner(st) {
		return errors.New("unsafe autoload marker directory")
	}
	return nil
}

func (m autoloadMarker) enabled() (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(m.dir, m.name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect autoload marker: %w", err)
	}
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG || st.Size != 0 || st.Nlink != 1 || !trustedAutoloadOwner(st) {
		return false, errors.New("unsafe autoload marker")
	}
	if err := m.checkDirectory(); err != nil {
		return false, err
	}
	return true, nil
}

func trustedAutoloadOwner(st unix.Stat_t) bool {
	return (st.Uid == 0 || st.Uid == uint32(os.Geteuid())) && uint32(st.Mode)&0o022 == 0
}

// AutoloadUpdateGuard loads the enrolled guard before the update firewall
// lock is installed. With no opt-in it performs no kernel checks or loads.
func AutoloadUpdateGuard(ctx context.Context, configPath string, firewall *netfilter.Firewall) error {
	_, _, err := loadSavedKernelModule(ctx, configPath, "guard", firewall.AutoloadKernelModule)
	return err
}

func loadSavedKernelModule(ctx context.Context, configPath, feature string, load func(context.Context, string) (bool, error)) (enrolled, verified bool, err error) {
	marker, err := openAutoloadMarker(configPath, feature)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	enabled, err := marker.enabled()
	unix.Close(marker.dir)
	if err != nil || !enabled {
		return false, false, err
	}
	verified, err = load(ctx, feature)
	return true, verified, err
}

func (d *Daemon) autoloadKernelModulesLocked(ctx context.Context, tproxy bool) (tproxyEnrolled bool, tproxyErr error) {
	for _, feature := range [...]string{"guard", "tproxy"} {
		if feature == "tproxy" && !tproxy {
			continue
		}
		enrolled, verified, err := loadSavedKernelModule(ctx, d.opt.ConfigPath, feature, d.moduleAutoload)
		if errors.Is(err, netfilter.ErrModuleAutoloadUnsupported) {
			continue
		}
		if feature == "tproxy" {
			tproxyEnrolled = enrolled
		}
		if err != nil {
			d.log.Warn("firmware module autoload failed", "feature", feature, "err", err)
			d.audit("system", FirmwareModuleLoadAction, feature, "error", "autoload: "+err.Error())
			if enrolled && feature == "tproxy" {
				tproxyErr = err
			}
		} else if verified {
			d.log.Info("firmware module autoload submitted descriptor and verified registration", "feature", feature)
			d.audit("system", FirmwareModuleLoadAction, feature, "ok", "autoload: submitted firmware descriptor; registration verified")
		}
	}
	return tproxyEnrolled, tproxyErr
}
