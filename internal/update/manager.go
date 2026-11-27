package update

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultTime   = "04:00"
	checkInterval = 6 * time.Hour
	checkCooldown = 30 * time.Second
	busyRetry     = 10 * time.Second
)

var (
	ErrUnavailable = errors.New("updates require a managed installation")
	ErrPreferences = errors.New("expected a router-local time in HH:MM format")
	ErrTarget      = errors.New("the requested release is no longer available")
	ErrBusy        = errors.New("update operation is busy; try again")
)

// Preferences schedules optional daily installation in the router's local time.
type Preferences struct {
	Enabled bool   `json:"enabled"`
	Time    string `json:"time"`
}

type schedule struct {
	Preferences
	AttemptDate string `json:"attempt_date,omitempty"`
}

type releaseIdentity struct{ tag, variant string }

type installState struct {
	Current, Variant string
	Previous         releaseIdentity
}

// Job is persisted across service restarts by the detached installer.
type Job struct {
	State  string `json:"state"`
	Target string `json:"target"`
}

// Status exposes release information and progress without leaking installer logs.
type Status struct {
	Available   bool        `json:"available"`
	Current     string      `json:"current,omitempty"`
	Previous    string      `json:"previous,omitempty"`
	Latest      string      `json:"latest,omitempty"`
	CheckedAt   *time.Time  `json:"checked_at,omitempty"`
	CheckFailed bool        `json:"check_failed,omitempty"`
	Preferences Preferences `json:"prefs"`
	Job         *Job        `json:"job,omitempty"`
	RouterTime  string      `json:"router_time,omitempty"`
}

// Manager coordinates release checks and owns the updater's separate preferences.
type Manager struct {
	mu                  sync.Mutex
	metadata, dir, arch string
	platform            string
	prefix, shell       string
	client              *http.Client
	log                 *slog.Logger
	start               func(installState, releaseIdentity) error
	latest, variant     string
	rollbackReady       releaseIdentity
	checked             time.Time
	checkFailed         bool
}

func (m *Manager) installed() installState {
	if m == nil {
		return installState{}
	}
	f, err := os.Open(m.metadata)
	if err != nil {
		return installState{}
	}
	defer f.Close()
	return readInstall(f)
}

func readInstall(r io.Reader) installState {
	fields := make(map[string]string)
	scan := bufio.NewScanner(io.LimitReader(r, 512))
	for scan.Scan() {
		if key, value, ok := strings.Cut(scan.Text(), " "); ok {
			fields[key] = value
		}
	}
	s := installState{Current: fields["current"], Variant: fields["variant"]}
	if !stable.MatchString(s.Current) || (s.Variant != "full" && s.Variant != "lite") || scan.Err() != nil {
		return installState{}
	}
	previousVariant, ok := fields["previous_variant"]
	if !ok {
		previousVariant = s.Variant
	}
	previousTag := fields["previous"]
	if stable.MatchString(previousTag) && previousTag != s.Current && (previousVariant == "full" || previousVariant == "lite") {
		s.Previous = releaseIdentity{tag: previousTag, variant: previousVariant}
	}
	return s
}

func (m *Manager) settings() (schedule, error) {
	s := schedule{Preferences: Preferences{Time: defaultTime}}
	b, err := os.ReadFile(filepath.Join(m.dir, "preferences.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(b, &s); err == nil && !validTime(s.Time) {
		err = ErrPreferences
	}
	return s, err
}

func validTime(value string) bool {
	t, err := time.Parse("15:04", value)
	return err == nil && t.Format("15:04") == value
}

func (m *Manager) save(s schedule) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writePrivate(m.dir, "preferences.json", b)
}

// Status reads persistent job state so a reconnected UI sees the same operation.
func (m *Manager) Status() Status {
	current := m.installed()
	s := Status{Preferences: Preferences{Time: defaultTime}}
	if current.Current == "" {
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s.Available = true
	s.Current, s.Previous = current.Current, m.rollbackCandidate(current).tag
	if prefs, err := m.settings(); err == nil {
		s.Preferences = prefs.Preferences
	}
	s.RouterTime = time.Now().Format(time.RFC3339)
	if !m.checked.IsZero() && m.variant == current.Variant {
		checked := m.checked
		s.CheckedAt, s.CheckFailed = &checked, m.checkFailed
		s.Latest = m.candidate(current)
	}
	s.Job = m.job()
	return s
}

// Check refreshes the cache at most once per interval, including failed checks.
func (m *Manager) Check(ctx context.Context, manual bool) {
	current := m.installed()
	if current.Current == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	interval := checkInterval
	if manual {
		interval = checkCooldown
	}
	if m.variant == current.Variant && time.Since(m.checked) < interval {
		return
	}
	latest, err := fetchLatest(ctx, m.client, current.Variant, m.arch, m.platform)
	m.latest, m.variant, m.checked, m.checkFailed = latest, current.Variant, time.Now(), err != nil
	if err != nil {
		m.log.Debug("release check failed", "err", err)
	}
	m.confirmRollback(ctx, current)
}

func (m *Manager) confirmRollback(ctx context.Context, current installState) {
	m.rollbackReady = releaseIdentity{}
	previous := current.Previous
	if m.platform != "openwrt" || previous.tag == "" {
		return
	}
	tag, err := fetchTagged(ctx, m.client, previous.tag, previous.variant, m.arch, m.platform)
	if err != nil {
		m.log.Debug("previous release is not a native rollback target", "err", err)
		return
	}
	if tag == previous.tag {
		m.rollbackReady = previous
	}
}

// SetPreferences writes scheduler settings independently of the routing draft.
func (m *Manager) SetPreferences(p Preferences) error {
	if m.installed().Current == "" {
		return ErrUnavailable
	}
	if !validTime(p.Time) {
		return ErrPreferences
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.settings()
	if err != nil {
		return err
	}
	s.Preferences = p
	return m.save(s)
}

// Start accepts only the checked latest version or an eligible rollback version.
func (m *Manager) Start(target string, rollback bool) error {
	current := m.installed()
	if current.Current == "" {
		return ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var expected releaseIdentity
	if rollback {
		expected = m.rollbackCandidate(current)
	} else {
		expected = releaseIdentity{tag: m.candidate(current), variant: current.Variant}
	}
	if expected.tag == "" || expected.tag != target {
		return ErrTarget
	}
	if rollback {
		return m.startRollback(current, expected)
	}
	return m.start(current, expected)
}

func (m *Manager) candidate(current installState) string {
	if m.variant == current.Variant && newer(m.latest, current.Current) {
		return m.latest
	}
	return ""
}

func (m *Manager) rollbackCandidate(current installState) releaseIdentity {
	if m.platform == "openwrt" && (m.rollbackReady != current.Previous || m.variant != current.Variant) {
		return releaseIdentity{}
	}
	return current.Previous
}

func (m *Manager) startRollback(current installState, target releaseIdentity) error {
	s, err := m.settings()
	if err != nil {
		return err
	}
	before := s
	s.Enabled = false
	if err := m.save(s); err != nil {
		return err
	}
	if err := m.start(current, target); err != nil {
		return errors.Join(err, m.save(before))
	}
	return nil
}

func due(p Preferences, attempted string, now time.Time) bool {
	return p.Enabled && attempted != now.Format(time.DateOnly) && p.Time == now.Format("15:04")
}

// scheduled reports whether lock contention warrants another try in this minute.
func (m *Manager) scheduled(ctx context.Context, now func() time.Time) bool {
	s, err := m.settings()
	if err != nil || !due(s.Preferences, s.AttemptDate, now()) {
		return false
	}
	m.Check(ctx, true)
	if ctx.Err() != nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err = m.settings()
	current := m.installed()
	target := m.candidate(current)
	currentTime := now()
	if err != nil || !due(s.Preferences, s.AttemptDate, currentTime) || target == "" {
		return false
	}
	before := s
	s.AttemptDate = currentTime.Format(time.DateOnly)
	if err = m.save(s); err == nil {
		err = m.start(current, releaseIdentity{tag: target, variant: current.Variant})
		if errors.Is(err, ErrBusy) {
			restoreErr := m.save(before)
			if restoreErr == nil {
				return true
			}
			err = errors.Join(err, restoreErr)
		}
	}
	if err != nil {
		m.log.Warn("scheduled update failed to start", "err", err)
	}
	return false
}

// Run checks for releases at startup and ticks on the router clock.
func (m *Manager) Run(ctx context.Context) {
	if m == nil {
		return
	}
	for {
		now := time.Now()
		// Measure the next tick before a network check can cross a minute boundary.
		next := now.Truncate(time.Minute).Add(time.Minute)
		if m.scheduled(ctx, time.Now) {
			if retry := now.Add(busyRetry); retry.Before(next) {
				next = retry
			}
		}
		m.Check(ctx, false)
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// writePrivate atomically publishes a state file within the private updater directory.
func writePrivate(dir, name string, b []byte) error {
	f, err := os.CreateTemp(dir, ".state-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(b)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, name))
}
