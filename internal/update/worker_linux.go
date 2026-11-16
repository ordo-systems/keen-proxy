//go:build linux

package update

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/ordo-systems/keen-proxy/tools"
	"golang.org/x/sys/unix"
)

// NewManaged enables updates only for a root-owned managed installation.
// An existing Entware installation is selected before native OpenWrt.
func NewManaged(config string, log *slog.Logger) *Manager {
	exe, err := os.Executable()
	if err != nil || os.Geteuid() != 0 {
		return nil
	}
	return newManagedAt("/opt", "/", exe, config, runtime.GOARCH, log)
}

func newManagedAt(entwarePrefix, nativeRoot, exe, config, goarch string, log *slog.Logger) *Manager {
	if m := newEntware(entwarePrefix, exe, config, goarch, log); m != nil {
		return m
	}
	return newOpenWrt(nativeRoot, exe, config, goarch, log)
}

func newEntware(prefix, exe, config, goarch string, log *slog.Logger) *Manager {
	arch, ok := releaseArch(goarch)
	if !ok || !managedPaths(prefix, exe, config) {
		return nil
	}
	return newManager(filepath.Join(prefix, "share/keenproxy/release"), filepath.Join(prefix, "var/lib/keenproxy/updates"),
		prefix, filepath.Join(prefix, "bin/sh"), arch, "entware", log)
}

func newOpenWrt(root, exe, config, goarch string, log *slog.Logger) *Manager {
	arch, ok := releaseArch(goarch)
	if !ok || !openWrtPaths(root, exe, config) {
		return nil
	}
	return newManager(filepath.Join(root, "usr/share/keenproxy/release"), filepath.Join(root, "usr/share/keenproxy/updates"),
		root, filepath.Join(root, "bin/sh"), arch, "openwrt", log)
}

func releaseArch(goarch string) (string, bool) {
	switch goarch {
	case "amd64", "386", "arm64", "mipsle":
		return goarch, true
	case "arm":
		return "armv5", true
	case "mips":
		return "mipsbe", true
	default:
		return "", false
	}
}

func newManager(metadata, dir, prefix, shell, arch, platform string, log *slog.Logger) *Manager {
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Warn("could not prepare update state", "err", err)
		return nil
	}
	m := &Manager{
		metadata: metadata, dir: dir, arch: arch, platform: platform, log: log,
		prefix: prefix, shell: shell,
		client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
	m.start = m.launch
	return m
}

func managedPaths(prefix, exe, config string) bool {
	if config != filepath.Join(prefix, "etc/keenproxy/config.yaml") {
		return false
	}
	expected, err := filepath.EvalSymlinks(filepath.Join(prefix, "bin/keenproxy"))
	if err != nil || exe != expected {
		return false
	}
	return regularFile(filepath.Join(prefix, "etc/init.d/S99keenproxy"), true)
}

func openWrtPaths(root, exe, config string) bool {
	if config != filepath.Join(root, "etc/keenproxy/config.yaml") {
		return false
	}
	expected, err := filepath.EvalSymlinks(filepath.Join(root, "usr/bin/keenproxy"))
	if err != nil || exe != expected {
		return false
	}
	service := filepath.Join(root, "etc/init.d/keenproxy")
	release := filepath.Join(root, "etc/openwrt_release")
	if !regularFile(service, true) || !hasExactLine(service, "# KeenProxy OpenWrt service") {
		return false
	}
	if !regularFile(release, false) || !openWrtIdentity(release) {
		return false
	}
	return regularFile(filepath.Join(root, "sbin/procd"), true) &&
		regularFile(filepath.Join(root, "etc/rc.common"), true)
}

func regularFile(path string, executable bool) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return !executable || info.Mode().Perm()&0100 != 0
}

func openWrtIdentity(path string) bool {
	return hasExactLine(path, "DISTRIB_ID='OpenWrt'") || hasExactLine(path, `DISTRIB_ID="OpenWrt"`)
}

func hasExactLine(path, want string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	scan := bufio.NewScanner(io.LimitReader(f, 1<<16))
	for scan.Scan() {
		if scan.Text() == want {
			return true
		}
	}
	return false
}

func (m *Manager) lock() (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(m.dir, "job.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return f, nil
}

func (m *Manager) job() *Job {
	// If we can take the lock, no installer can change the state while we read it.
	f, lockErr := m.lock()
	if f != nil {
		defer f.Close()
	}
	b, err := os.ReadFile(filepath.Join(m.dir, "job"))
	if err != nil {
		return nil
	}
	state, target, ok := strings.Cut(strings.TrimSpace(string(b)), " ")
	if !ok || !stable.MatchString(target) {
		return nil
	}
	switch state {
	case "running":
		if !errors.Is(lockErr, ErrBusy) {
			state = "failed"
		}
	case "success", "failed":
	default:
		return nil
	}
	return &Job{State: state, Target: target}
}

// The outer shell retains the lock while its installer child closes descriptor
// three. The new daemon must never inherit the lock from the installer.
const worker = `
umask 077
shell=$1
job=$2
target=$3
shift 3
if "$shell" -s -- "$@" 3>&-; then
    result=success
else
    result=failed
fi
tmp="$job.$$"
printf '%s %s\n' "$result" "$target" > "$tmp" && mv -f "$tmp" "$job"
`

func (m *Manager) launch(current installState, target string) error {
	return m.startWorker(current, target, tools.Bootstrap)
}

func (m *Manager) startWorker(current installState, target string, installer []byte) error {
	lock, err := m.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	f, err := installerInput(m.dir, installer)
	if err != nil {
		return err
	}
	defer f.Close()
	log, err := os.OpenFile(filepath.Join(m.dir, "installer.log"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	args := []string{"-c", worker, "keenproxy-update", m.shell, filepath.Join(m.dir, "job"), target,
		"--version", target, "--expect-current", current.Current}
	if current.Variant == "lite" {
		args = append(args, "--lite")
	}
	cmd := exec.Command(m.shell, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = f, log, log
	cmd.ExtraFiles = []*os.File{lock}
	cmd.Env = workerEnv(os.Environ(), m.platform, m.prefix)

	if err := writePrivate(m.dir, "job", []byte("running "+target+"\n")); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		_ = writePrivate(m.dir, "job", []byte("failed "+target+"\n"))
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func installerInput(dir string, script []byte) (*os.File, error) {
	f, err := os.CreateTemp(dir, ".installer-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(script); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func workerEnv(base []string, platform, prefix string) []string {
	env := make([]string, 0, len(base)+2)
	for _, entry := range base {
		if strings.HasPrefix(entry, "KEENPROXY_PLATFORM=") || strings.HasPrefix(entry, "KEENPROXY_PREFIX=") {
			continue
		}
		env = append(env, entry)
	}
	if platform != "" {
		env = append(env, "KEENPROXY_PLATFORM="+platform)
	}
	return append(env, "KEENPROXY_PREFIX="+prefix)
}
