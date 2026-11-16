//go:build linux

package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEntwareUpdaterRequiresSupportedManagedPaths(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "bin/keenproxy")
	config := filepath.Join(root, "etc/keenproxy/config.yaml")
	service := filepath.Join(root, "etc/init.d/S99keenproxy")
	if err := os.MkdirAll(filepath.Dir(service), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(exe), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, nil, 0700); err != nil {
		t.Fatal(err)
	}
	if NewManaged(config, slog.Default()) != nil {
		t.Fatal("unmanaged binary exposed the Entware updater")
	}
	if newEntware(root, exe, config, "arm64", slog.Default()) != nil {
		t.Fatal("unmanaged installation exposed the updater")
	}
	if err := os.WriteFile(service, nil, 0700); err != nil {
		t.Fatal(err)
	}
	if newEntware(root, exe, config, "amd64", slog.Default()) == nil {
		t.Fatal("amd64 managed installation was rejected")
	}
	if newEntware(root, exe, config, "riscv64", slog.Default()) != nil {
		t.Fatal("unsupported architecture exposed the updater")
	}
	m := newEntware(root, exe, config, "mipsle", slog.Default())
	if m == nil || m.Status().Available {
		t.Fatal("managed updater should wait for a release record")
	}
}

func TestDetachedInstallerKeepsLockAndPublishesResult(t *testing.T) {
	m := &Manager{dir: t.TempDir(), shell: "/bin/sh"}
	m.prefix = m.dir
	gate := filepath.Join(m.dir, "proceed")
	// Ensure an assertion failure cannot strand the fixture process.
	t.Cleanup(func() { _ = os.WriteFile(gate, nil, 0600) })
	script := []byte(`
[ "$*" = '--version v0.4.0 --expect-current v0.3.0 --lite' ] || exit 1
[ ! -e /proc/self/fd/3 ] || exit 1
for try in 1 2 3 4 5 6 7 8 9 10; do
    [ ! -f "$KEENPROXY_PREFIX/proceed" ] || exit 0
    sleep 1
done
exit 1
`)
	current := installState{Current: "v0.3.0", Variant: "lite"}
	if err := m.startWorker(current, "v0.4.0", script); err != nil {
		t.Fatal(err)
	}
	restarted := &Manager{dir: m.dir}
	if job := restarted.job(); job == nil || job.State != "running" {
		t.Fatalf("restarted API lost the active job: %+v", job)
	}
	if err := m.startWorker(current, "v0.4.0", script); !errors.Is(err, ErrBusy) {
		t.Fatalf("second install should be blocked, got %v", err)
	}
	if err := os.WriteFile(gate, nil, 0600); err != nil {
		t.Fatal(err)
	}
	awaitWorkerResult(t, restarted, "success", "v0.4.0")

	if err := m.startWorker(current, "v0.5.0", []byte("exit 1\n")); err != nil {
		t.Fatal(err)
	}
	awaitWorkerResult(t, restarted, "failed", "v0.5.0")
}

func awaitWorkerResult(t *testing.T, m *Manager, want, target string) {
	t.Helper()
	until := time.Now().Add(4 * time.Second)
	for time.Now().Before(until) {
		job := m.job()
		if job != nil && job.State == want && job.Target == target {
			// The status write precedes the outer shell closing its lock.
			if f, err := m.lock(); err == nil {
				f.Close()
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	log, _ := os.ReadFile(filepath.Join(m.dir, "installer.log"))
	t.Fatalf("worker result = %+v, want %s for %s; installer log: %s", m.job(), want, target, log)
}

func TestEntwareWorkerReplacesInheritedNativeEnvironment(t *testing.T) {
	t.Setenv("KEENPROXY_PLATFORM", "openwrt")
	t.Setenv("KEENPROXY_PREFIX", "/")
	root, exe, config := entwareTree(t)
	if err := os.Symlink("/bin/sh", filepath.Join(root, "bin/sh")); err != nil {
		t.Fatal(err)
	}
	m := newEntware(root, exe, config, "arm64", slog.Default())
	if m == nil || m.platform != "entware" || m.prefix != root ||
		m.dir != filepath.Join(root, "var/lib/keenproxy/updates") ||
		m.shell != filepath.Join(root, "bin/sh") {
		t.Fatalf("Entware manager did not keep its own platform and paths: %+v", m)
	}
	// Bake the output path so a wrong inherited prefix cannot write to /.
	seen := filepath.Join(m.dir, "seen-env")
	script := []byte(fmt.Sprintf("printf '%%s %%s\\n' \"$KEENPROXY_PLATFORM\" \"$KEENPROXY_PREFIX\" > '%s'\n", seen))
	if err := m.startWorker(installState{Current: "v0.3.0", Variant: "full"}, "v0.4.0", script); err != nil {
		t.Fatal(err)
	}
	awaitWorkerResult(t, m, "success", "v0.4.0")
	body, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got != "entware "+root+"\n" {
		t.Fatalf("worker environment = %q, want entware prefix %s", got, root)
	}
}

func TestMappedArchitectureSelectsPublishedAsset(t *testing.T) {
	root, exe, config := entwareTree(t)
	m := newEntware(root, exe, config, "arm", slog.Default())
	if m == nil || m.arch != "armv5" {
		t.Fatalf("Go arm was not published as armv5: %+v", m)
	}
	if err := os.MkdirAll(filepath.Dir(m.metadata), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.metadata, []byte("current v0.4.0\nvariant full\n"), 0600); err != nil {
		t.Fatal(err)
	}
	serve := func(names ...string) {
		t.Helper()
		m.checked = time.Time{}
		body := releaseAssetBody("v0.5.0", names...)
		m.client = &http.Client{Transport: releaseTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
	}
	serve("keenproxy-linux-arm", "S99keenproxy", "install.sh", "SHA256SUMS")
	m.Check(context.Background(), true)
	if m.Status().Latest != "" || !m.Status().CheckFailed {
		t.Fatalf("Go arm asset was accepted: %+v", m.Status())
	}
	serve("keenproxy-linux-armv5", "S99keenproxy", "install.sh", "SHA256SUMS")
	m.Check(context.Background(), true)
	if status := m.Status(); status.Latest != "v0.5.0" || status.CheckFailed {
		t.Fatalf("published armv5 release was not advertised: %+v", status)
	}

	nativeRoot, nativeExe, nativeConfig := openWrtTree(t)
	native := newOpenWrt(nativeRoot, nativeExe, nativeConfig, "mips", slog.Default())
	if native == nil || native.arch != "mipsbe" || native.platform != "openwrt" {
		t.Fatalf("Go mips was not published as mipsbe: %+v", native)
	}
	if err := os.WriteFile(native.metadata, []byte("current v0.4.0\nvariant lite\n"), 0600); err != nil {
		t.Fatal(err)
	}
	native.client = &http.Client{Transport: releaseTransport(func(*http.Request) (*http.Response, error) {
		body := releaseAssetBody("v0.5.0", "keenproxy-lite-linux-mips", "SHA256SUMS", "keenproxy.openwrt")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	native.Check(context.Background(), true)
	if native.Status().Latest != "" {
		t.Fatal("Go mips asset was accepted instead of mipsbe")
	}
	native.checked = time.Time{}
	native.client = &http.Client{Transport: releaseTransport(func(*http.Request) (*http.Response, error) {
		body := releaseAssetBody("v0.5.0", "keenproxy-lite-linux-mipsbe", "SHA256SUMS", "keenproxy.openwrt")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	native.Check(context.Background(), true)
	if status := native.Status(); status.Latest != "v0.5.0" || status.CheckFailed {
		t.Fatalf("published mipsbe release was not advertised: %+v", status)
	}
}

func TestOpenWrtUpdaterRequiresOwnedPaths(t *testing.T) {
	root, exe, config := openWrtTree(t)
	m := newOpenWrt(root, exe, config, "amd64", slog.Default())
	if m == nil || m.platform != "openwrt" || m.arch != "amd64" || m.prefix != root ||
		m.dir != filepath.Join(root, "usr/share/keenproxy/updates") ||
		m.metadata != filepath.Join(root, "usr/share/keenproxy/release") ||
		m.shell != filepath.Join(root, "bin/sh") {
		t.Fatalf("owned native installation was not recognized: %+v", m)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/keenproxy/updates")); !os.IsNotExist(err) {
		t.Fatal("native constructor created var/lib updater state")
	}
	for _, arch := range []string{"386", "arm64", "mipsle"} {
		if got := newOpenWrt(root, exe, config, arch, slog.Default()); got == nil || got.arch != arch {
			t.Fatalf("published Go arch %s was rejected: %+v", arch, got)
		}
	}
	if got := newOpenWrt(root, exe, config, "arm", slog.Default()); got == nil || got.arch != "armv5" {
		t.Fatalf("Go arm was not published as armv5: %+v", got)
	}
	if got := newOpenWrt(root, exe, config, "mips", slog.Default()); got == nil || got.arch != "mipsbe" {
		t.Fatalf("Go mips was not published as mipsbe: %+v", got)
	}
	for _, arch := range []string{"armv5", "armv7", "mips64le", "mipsbe", "riscv64"} {
		if newOpenWrt(root, exe, config, arch, slog.Default()) != nil {
			t.Fatalf("unsupported or unmapped architecture %s exposed the native updater", arch)
		}
	}

	reject := func(name string, breakTree func(t *testing.T, root string)) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			root, exe, config := openWrtTree(t)
			breakTree(t, root)
			if newOpenWrt(root, exe, config, "arm64", slog.Default()) != nil {
				t.Fatal("unsafe native installation exposed the updater")
			}
		})
	}
	reject("missing marker", func(t *testing.T, root string) {
		writeTreeFile(t, filepath.Join(root, "etc/init.d/keenproxy"), "#!/bin/sh\n", 0755)
	})
	reject("marker not a whole line", func(t *testing.T, root string) {
		writeTreeFile(t, filepath.Join(root, "etc/init.d/keenproxy"), "# KeenProxy OpenWrt service extra\n", 0755)
	})
	reject("Entware marker", func(t *testing.T, root string) {
		writeTreeFile(t, filepath.Join(root, "etc/init.d/keenproxy"), "# KeenProxy Entware service\n", 0755)
	})
	reject("service symlink", func(t *testing.T, root string) {
		replaceWithSymlink(t, filepath.Join(root, "etc/init.d/keenproxy"), "# KeenProxy OpenWrt service\n", 0755)
	})
	reject("service not executable", func(t *testing.T, root string) {
		if err := os.Chmod(filepath.Join(root, "etc/init.d/keenproxy"), 0644); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("wrong config", func(t *testing.T) {
		root, exe, config := openWrtTree(t)
		if newOpenWrt(root, exe, config+".bak", "arm64", slog.Default()) != nil {
			t.Fatal("unmanaged config exposed the native updater")
		}
	})
	t.Run("wrong executable", func(t *testing.T) {
		root, _, config := openWrtTree(t)
		other := filepath.Join(root, "usr/bin/other")
		writeTreeFile(t, other, "", 0755)
		resolved, err := filepath.EvalSymlinks(other)
		if err != nil {
			t.Fatal(err)
		}
		if newOpenWrt(root, resolved, config, "arm64", slog.Default()) != nil {
			t.Fatal("unmanaged executable exposed the native updater")
		}
	})
	reject("missing openwrt release", func(t *testing.T, root string) {
		if err := os.Remove(filepath.Join(root, "etc/openwrt_release")); err != nil {
			t.Fatal(err)
		}
	})
	reject("openwrt release without id", func(t *testing.T, root string) {
		writeTreeFile(t, filepath.Join(root, "etc/openwrt_release"), "DISTRIB_ID='Keenetic'\n", 0644)
	})
	reject("openwrt release symlink", func(t *testing.T, root string) {
		replaceWithSymlink(t, filepath.Join(root, "etc/openwrt_release"), "DISTRIB_ID='OpenWrt'\n", 0644)
	})
	reject("missing procd", func(t *testing.T, root string) {
		if err := os.Remove(filepath.Join(root, "sbin/procd")); err != nil {
			t.Fatal(err)
		}
	})
	reject("procd not executable", func(t *testing.T, root string) {
		if err := os.Chmod(filepath.Join(root, "sbin/procd"), 0644); err != nil {
			t.Fatal(err)
		}
	})
	reject("procd symlink", func(t *testing.T, root string) {
		replaceWithSymlink(t, filepath.Join(root, "sbin/procd"), "", 0755)
	})
	reject("missing rc.common", func(t *testing.T, root string) {
		if err := os.Remove(filepath.Join(root, "etc/rc.common")); err != nil {
			t.Fatal(err)
		}
	})
	reject("rc.common not executable", func(t *testing.T, root string) {
		if err := os.Chmod(filepath.Join(root, "etc/rc.common"), 0644); err != nil {
			t.Fatal(err)
		}
	})
	reject("rc.common symlink", func(t *testing.T, root string) {
		replaceWithSymlink(t, filepath.Join(root, "etc/rc.common"), "#!/bin/sh\n", 0644)
	})
}

func TestManagedSelectionPrefersExistingEntware(t *testing.T) {
	entware, entwareExe, entwareConfig := entwareTree(t)
	native, nativeExe, nativeConfig := openWrtTree(t)
	got := newManagedAt(entware, native, entwareExe, entwareConfig, "amd64", slog.Default())
	if got == nil || got.platform != "entware" || got.prefix != entware ||
		got.dir != filepath.Join(entware, "var/lib/keenproxy/updates") {
		t.Fatalf("existing Entware installation was not selected: %+v", got)
	}
	got = newManagedAt(entware, native, nativeExe, nativeConfig, "mips", slog.Default())
	if got == nil || got.platform != "openwrt" || got.prefix != native || got.arch != "mipsbe" ||
		got.dir != filepath.Join(native, "usr/share/keenproxy/updates") {
		t.Fatalf("native installation was not selected: %+v", got)
	}
	if newManagedAt(entware, native, entwareExe, nativeConfig, "arm64", slog.Default()) != nil {
		t.Fatal("mixed Entware executable and native config was accepted")
	}
}

func TestNativeUpdaterLifecyclePersistsJobAndPlatform(t *testing.T) {
	root, exe, config := openWrtTree(t)
	if err := os.Symlink("/bin/sh", filepath.Join(root, "bin/sh")); err != nil {
		t.Fatal(err)
	}
	m := newOpenWrt(root, exe, config, "arm64", slog.Default())
	if m == nil {
		t.Fatal("owned native installation was rejected")
	}
	if m.dir != filepath.Join(root, "usr/share/keenproxy/updates") ||
		m.metadata != filepath.Join(root, "usr/share/keenproxy/release") ||
		m.shell != filepath.Join(root, "bin/sh") {
		t.Fatalf("native persistent paths were not used: %+v", m)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/keenproxy/updates")); !os.IsNotExist(err) {
		t.Fatal("native lifecycle used var/lib updater state")
	}
	if err := os.WriteFile(m.metadata, []byte("current v0.3.0\nvariant lite\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.SetPreferences(Preferences{Enabled: true, Time: "04:15"}); err != nil {
		t.Fatal(err)
	}
	prefs, err := os.ReadFile(filepath.Join(m.dir, "preferences.json"))
	if err != nil || !strings.Contains(string(prefs), `"time":"04:15"`) {
		t.Fatalf("scheduler preferences were not persisted under usr/share: %v %s", err, prefs)
	}

	seen := filepath.Join(m.dir, "seen-env")
	argsPath := filepath.Join(m.dir, "seen-args")
	gate := filepath.Join(m.dir, "proceed")
	t.Cleanup(func() { _ = os.WriteFile(gate, nil, 0600) })
	script := []byte(fmt.Sprintf(`
printf '%%s %%s\n' "$KEENPROXY_PLATFORM" "$KEENPROXY_PREFIX" > '%s'
printf '%%s\n' "$*" > '%s'
[ "$*" = '--version v0.4.0 --expect-current v0.3.0 --lite' ] || exit 1
[ ! -e /proc/self/fd/3 ] || exit 1
for try in 1 2 3 4 5 6 7 8 9 10; do
    [ ! -f '%s' ] || exit 0
    sleep 1
done
exit 1
`, seen, argsPath, gate))
	current := installState{Current: "v0.3.0", Variant: "lite"}
	if err := m.startWorker(current, "v0.4.0", script); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "installer.log")); err != nil {
		t.Fatalf("installer log was not created in the persistent updates directory: %v", err)
	}
	deadline := time.Now().Add(4 * time.Second)
	var envBody []byte
	for time.Now().Before(deadline) {
		envBody, err = os.ReadFile(seen)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		log, _ := os.ReadFile(filepath.Join(m.dir, "installer.log"))
		t.Fatalf("worker did not publish its environment: %v; log: %s", err, log)
	}
	if got := string(envBody); got != "openwrt "+root+"\n" {
		t.Fatalf("native worker environment = %q, want openwrt prefix %s", got, root)
	}
	restarted := &Manager{dir: m.dir}
	if job := restarted.job(); job == nil || job.State != "running" || job.Target != "v0.4.0" {
		t.Fatalf("restarted API lost the active native job: %+v", job)
	}
	if err := m.startWorker(current, "v0.4.0", script); !errors.Is(err, ErrBusy) {
		t.Fatalf("second native install should be blocked, got %v", err)
	}
	if err := os.WriteFile(gate, nil, 0600); err != nil {
		t.Fatal(err)
	}
	awaitWorkerResult(t, restarted, "success", "v0.4.0")
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(args) != "--version v0.4.0 --expect-current v0.3.0 --lite\n" {
		t.Fatalf("installer arguments = %q", args)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/keenproxy/updates/job")); !os.IsNotExist(err) {
		t.Fatal("native job state was written under var/lib")
	}
}

func entwareTree(t *testing.T) (root, exe, config string) {
	t.Helper()
	root = t.TempDir()
	exe = filepath.Join(root, "bin/keenproxy")
	config = filepath.Join(root, "etc/keenproxy/config.yaml")
	service := filepath.Join(root, "etc/init.d/S99keenproxy")
	if err := os.MkdirAll(filepath.Dir(exe), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(service), 0755); err != nil {
		t.Fatal(err)
	}
	writeTreeFile(t, exe, "", 0755)
	writeTreeFile(t, service, "", 0755)
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	return root, resolved, config
}

func openWrtTree(t *testing.T) (root, exe, config string) {
	t.Helper()
	root = t.TempDir()
	exe = filepath.Join(root, "usr/bin/keenproxy")
	config = filepath.Join(root, "etc/keenproxy/config.yaml")
	for _, dir := range []string{
		filepath.Dir(exe), filepath.Dir(config), filepath.Join(root, "etc/init.d"),
		filepath.Join(root, "sbin"), filepath.Join(root, "bin"),
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeTreeFile(t, exe, "", 0755)
	writeTreeFile(t, filepath.Join(root, "etc/init.d/keenproxy"), "#!/bin/sh /etc/rc.common\n# KeenProxy OpenWrt service\nUSE_PROCD=1\n", 0755)
	writeTreeFile(t, filepath.Join(root, "etc/openwrt_release"), "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='23.05.5'\n", 0644)
	writeTreeFile(t, filepath.Join(root, "sbin/procd"), "", 0755)
	writeTreeFile(t, filepath.Join(root, "etc/rc.common"), "#!/bin/sh\n", 0755)
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	return root, resolved, config
}

func writeTreeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func replaceWithSymlink(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	other := path + ".foreign"
	writeTreeFile(t, other, body, mode)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
}
