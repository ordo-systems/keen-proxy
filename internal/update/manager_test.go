package update

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type releaseTransport func(*http.Request) (*http.Response, error)

func (f releaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fixtureManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	metadata := filepath.Join(dir, "release")
	if err := os.WriteFile(metadata, []byte("current v0.4.0\nprevious v0.3.0\nvariant full\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return &Manager{metadata: metadata, dir: dir, log: slog.Default(), arch: "arm64"}
}

func TestScheduledInstallRefreshesReleaseAndPersistsAttempt(t *testing.T) {
	m := fixtureManager(t)
	now := time.Date(2026, 11, 7, 4, 30, 0, 0, time.Local)
	var checks, starts int
	m.client = &http.Client{Transport: releaseTransport(func(r *http.Request) (*http.Response, error) {
		checks++
		if r.URL.String() != latestReleaseURL {
			t.Fatalf("unexpected release source: %s", r.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(
			`{"tag_name":"v0.5.0","assets":[{"name":"keenproxy-linux-arm64","state":"uploaded"},` +
				`{"name":"S99keenproxy","state":"uploaded"},{"name":"install.sh","state":"uploaded"},{"name":"SHA256SUMS","state":"uploaded"}]}`))}, nil
	})}
	m.start = func(current installState, target string) error {
		starts++
		if current.Current != "v0.4.0" || target != "v0.5.0" {
			t.Fatalf("unexpected scheduled transition: %+v to %s", current, target)
		}
		return nil
	}
	if p := m.Status().Preferences; p.Enabled || p.Time != defaultTime {
		t.Fatalf("unsafe defaults: %+v", p)
	}
	if err := m.SetPreferences(Preferences{Enabled: true, Time: "4:30"}); !errors.Is(err, ErrPreferences) {
		t.Fatalf("accepted invalid time: %v", err)
	}
	if err := m.SetPreferences(Preferences{Enabled: true, Time: "04:30"}); err != nil {
		t.Fatal(err)
	}
	m.scheduled(context.Background(), now.Add(-time.Minute))
	m.scheduled(context.Background(), now)
	m.scheduled(context.Background(), now.Add(30*time.Second))
	if checks != 1 || starts != 1 {
		t.Fatalf("checks=%d starts=%d, want one each", checks, starts)
	}
	if status := m.Status(); !status.Available || status.Latest != "v0.5.0" || status.CheckFailed {
		t.Fatalf("wrong availability: %+v", status)
	}
	if s, err := m.settings(); err != nil || s.AttemptDate != now.Format(time.DateOnly) {
		t.Fatalf("attempt was not persisted: %+v, %v", s, err)
	}
}

func TestRollbackDisablesAutoInstallOnlyWhenAccepted(t *testing.T) {
	m := fixtureManager(t)
	prefs := Preferences{Enabled: true, Time: "04:30"}
	if err := m.SetPreferences(prefs); err != nil {
		t.Fatal(err)
	}
	if err := m.Start("v0.2.0", true); !errors.Is(err, ErrTarget) {
		t.Fatalf("accepted a stale rollback target: %v", err)
	}
	m.start = func(installState, string) error { return ErrBusy }
	if err := m.Start("v0.3.0", true); !errors.Is(err, ErrBusy) {
		t.Fatalf("expected busy: %v", err)
	}
	if m.Status().Preferences != prefs {
		t.Fatal("failed launch changed preferences")
	}
	m.start = func(current installState, target string) error {
		if current.Current != "v0.4.0" || target != "v0.3.0" {
			t.Fatalf("unexpected rollback: %+v to %s", current, target)
		}
		return nil
	}
	if err := m.Start("v0.3.0", true); err != nil {
		t.Fatal(err)
	}
	if m.Status().Preferences.Enabled {
		t.Fatal("rollback left automatic installation enabled")
	}
}

func TestSchedulerStopsWhenServiceStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := &Manager{metadata: filepath.Join(t.TempDir(), "missing")}
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("update scheduler outlived its service")
	}
}

func TestReleaseCheckRejectsMalformedAndIncompleteResponses(t *testing.T) {
	for _, body := range []string{"{", `{"tag_name":"v0.5.0","assets":[]}`, `{"tag_name":"v0.5.0","draft":true}`} {
		if _, err := decodeRelease(strings.NewReader(body), "full", "arm64", "entware"); err == nil {
			t.Errorf("accepted unavailable release response %q", body)
		}
	}
}

func TestReleaseMustBeStableAndComplete(t *testing.T) {
	assets := []string{"keenproxy-linux-arm64", "install.sh", "S99keenproxy", "SHA256SUMS"}
	if !releaseReady("v0.4.0", assets, "full", "arm64", "entware") {
		t.Fatal("complete stable release was rejected")
	}
	if releaseReady("v0.4.0-rc.1", assets, "full", "arm64", "entware") ||
		releaseReady("v0.4.0", assets[:3], "full", "arm64", "entware") ||
		releaseReady("v0.4.0", assets, "lite", "arm64", "entware") ||
		releaseReady("v0.4.0", assets, "full", "arm64", "openwrt") {
		t.Fatal("pre-release, incomplete release, wrong variant, or native-incomplete release accepted")
	}
	if !newer("v0.10.0", "v0.9.9") || newer("v0.3.0", "v0.3.0") || newer("v0.3.0", "v0.4.0") {
		t.Fatal("release ordering is incorrect")
	}
	if newer("v0.5.0-rc.1", "v0.4.0") || newer("v0.5.0", "v0.4.0-rc.1") {
		t.Fatal("an unstable version entered the update comparison")
	}
}

func TestScheduleUsesLocalMinuteAndOnlyOneAttempt(t *testing.T) {
	now := time.Date(2026, 11, 7, 4, 30, 12, 0, time.FixedZone("router", 3*3600))
	prefs := Preferences{Enabled: true, Time: "04:30"}
	if !due(prefs, "", now) || due(prefs, "2026-11-07", now) || due(prefs, "", now.Add(time.Minute)) ||
		due(Preferences{Time: "04:30"}, "", now) {
		t.Fatal("schedule ignored the local minute, previous attempt, or disabled setting")
	}
}

func TestParseInstallMetadata(t *testing.T) {
	state := readInstall(strings.NewReader("current v0.4.0\nprevious v0.3.0\nvariant lite\n"))
	if state.Current != "v0.4.0" || state.Previous != "v0.3.0" || state.Variant != "lite" {
		t.Fatalf("unexpected install state: %+v", state)
	}
	if state := readInstall(strings.NewReader("current ../../unsafe\nvariant full\n")); state.Current != "" {
		t.Fatal("accepted invalid installed tag")
	}
}

func TestNativeReleaseDecodeRequiresOpenWrtAsset(t *testing.T) {
	for _, arch := range []string{"amd64", "386", "armv5", "arm64", "mipsle", "mipsbe"} {
		entware := []string{"keenproxy-linux-" + arch, "install.sh", "S99keenproxy", "SHA256SUMS"}
		if !releaseReady("v0.4.0", entware, "full", arch, "entware") {
			t.Fatalf("complete Entware %s release was rejected", arch)
		}
		if releaseReady("v0.4.0", entware, "full", arch, "openwrt") {
			t.Fatalf("native %s release without keenproxy.openwrt was accepted", arch)
		}
		native := []string{"keenproxy-linux-" + arch, "SHA256SUMS", "keenproxy.openwrt"}
		if !releaseReady("v0.4.0", native, "full", arch, "openwrt") {
			t.Fatalf("complete native %s release was rejected", arch)
		}
		if releaseReady("v0.4.0", native, "full", arch, "entware") {
			t.Fatalf("Entware accepted a %s release without S99keenproxy and install.sh", arch)
		}
		lite := []string{"keenproxy-lite-linux-" + arch, "SHA256SUMS", "keenproxy.openwrt"}
		if !releaseReady("v0.4.0", lite, "lite", arch, "openwrt") || releaseReady("v0.4.0", lite, "full", arch, "openwrt") {
			t.Fatalf("native lite asset selection failed for %s", arch)
		}
	}
	if releaseReady("v0.4.0", []string{"keenproxy-linux-arm", "SHA256SUMS", "keenproxy.openwrt"}, "full", "armv5", "openwrt") ||
		releaseReady("v0.4.0", []string{"keenproxy-linux-mips", "SHA256SUMS", "keenproxy.openwrt"}, "full", "mipsbe", "openwrt") ||
		releaseReady("v0.4.0", []string{"keenproxy-linux-amd64", "SHA256SUMS", "keenproxy.openwrt", "trusttunnel"}, "full", "amd64", "debian") {
		t.Fatal("unmapped suffix, helper asset, or unknown platform was treated as a complete release")
	}

	entwareBody := releaseAssetBody("v0.5.0", "keenproxy-linux-amd64", "S99keenproxy", "install.sh", "SHA256SUMS")
	if tag, err := decodeRelease(strings.NewReader(entwareBody), "full", "amd64", "entware"); err != nil || tag != "v0.5.0" {
		t.Fatalf("Entware release rejected: %v %s", err, tag)
	}
	if _, err := decodeRelease(strings.NewReader(entwareBody), "full", "amd64", "openwrt"); err == nil {
		t.Fatal("decoded a native release without keenproxy.openwrt")
	}
	pending := `{"tag_name":"v0.5.0","assets":[{"name":"keenproxy-linux-amd64","state":"uploaded"},{"name":"SHA256SUMS","state":"uploaded"},{"name":"keenproxy.openwrt","state":"starter"}]}`
	if _, err := decodeRelease(strings.NewReader(pending), "full", "amd64", "openwrt"); err == nil {
		t.Fatal("pending keenproxy.openwrt asset was treated as uploaded")
	}
	nativeBody := releaseAssetBody("v0.5.0", "keenproxy-lite-linux-mipsbe", "SHA256SUMS", "keenproxy.openwrt")
	if tag, err := decodeRelease(strings.NewReader(nativeBody), "lite", "mipsbe", "openwrt"); err != nil || tag != "v0.5.0" {
		t.Fatalf("complete native release rejected: %v %s", err, tag)
	}
	if _, err := decodeRelease(strings.NewReader(nativeBody), "lite", "mipsbe", "entware"); err == nil {
		t.Fatal("Entware accepted a release without S99keenproxy and install.sh")
	}
}

func TestEntwareStatusStillAdvertisesRecordedRollback(t *testing.T) {
	m := fixtureManager(t)
	m.platform = "entware"
	if m.Status().Previous != "v0.3.0" {
		t.Fatal("Entware hid a recorded rollback")
	}
}

func TestNativeRollbackNotAdvertisedWithoutProcdAsset(t *testing.T) {
	const previousURL = "https://api.github.com/repos/ordo-systems/keen-proxy/releases/tags/v0.3.0"
	latest := releaseAssetBody("v0.5.0", "keenproxy-linux-arm64", "SHA256SUMS", "keenproxy.openwrt")
	check := func(t *testing.T, previous string, previousStatus int) Status {
		t.Helper()
		m := fixtureManager(t)
		m.platform = "openwrt"
		if m.Status().Previous != "" {
			t.Fatal("native rollback advertised before the previous release was checked")
		}
		m.client = &http.Client{Transport: releaseTransport(func(r *http.Request) (*http.Response, error) {
			switch r.URL.String() {
			case latestReleaseURL:
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(latest))}, nil
			case previousURL:
				return &http.Response{StatusCode: previousStatus, Body: io.NopCloser(strings.NewReader(previous))}, nil
			default:
				t.Errorf("unexpected release source: %s", r.URL)
				return nil, errors.New("unexpected release source")
			}
		})}
		m.Check(context.Background(), true)
		return m.Status()
	}

	missing := releaseAssetBody("v0.3.0", "keenproxy-linux-arm64", "install.sh", "S99keenproxy", "SHA256SUMS")
	if status := check(t, missing, http.StatusOK); status.Latest != "v0.5.0" || status.Previous != "" || status.CheckFailed {
		t.Fatalf("incomplete native rollback advertised: %+v", status)
	}
	if status := check(t, "", http.StatusNotFound); status.Latest != "v0.5.0" || status.Previous != "" || status.CheckFailed {
		t.Fatalf("missing previous release affected latest or was advertised: %+v", status)
	}
	ready := releaseAssetBody("v0.3.0", "keenproxy-linux-arm64", "SHA256SUMS", "keenproxy.openwrt")
	if status := check(t, ready, http.StatusOK); status.Latest != "v0.5.0" || status.Previous != "v0.3.0" || status.CheckFailed {
		t.Fatalf("complete native rollback was hidden: %+v", status)
	}
}

func releaseAssetBody(tag string, names ...string) string {
	var b strings.Builder
	b.WriteString(`{"tag_name":"`)
	b.WriteString(tag)
	b.WriteString(`","assets":[`)
	for i, name := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"name":"`)
		b.WriteString(name)
		b.WriteString(`","state":"uploaded"}`)
	}
	b.WriteString(`]}`)
	return b.String()
}
