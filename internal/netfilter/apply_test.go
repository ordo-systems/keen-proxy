package netfilter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// fakeRunner records calls and fails -C checks for jumps listed in missing.
type fakeRunner struct {
	calls   []string
	missing map[string]bool // "table/from/to"
	deleted map[string]int
}

func (r *fakeRunner) Run(_ context.Context, stdin, name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	if stdin != "" {
		call += " <stdin>"
	}
	r.calls = append(r.calls, call)
	if len(args) >= 6 && args[0] == "-w" && args[1] == "-t" {
		key := args[2] + "/" + args[4]
		if len(args) >= 7 {
			key += "/" + args[len(args)-1]
		}
		switch args[3] {
		case "-C":
			if r.missing[key] {
				return errors.New("rule missing")
			}
		case "-D":
			if r.deleted[key] >= 2 { // the chain contained two duplicate jumps
				return errors.New("rule missing")
			}
			r.deleted[key]++
		}
	}
	return nil
}

func TestApplyInsertsOnlyMissingJumps(t *testing.T) {
	r := &fakeRunner{missing: map[string]bool{"nat/PREROUTING/KEENPROXY_DNS": true}}
	f := &Firewall{Run: r, IPTables: "iptables", Restore: "iptables-restore"}
	if err := f.Apply(context.Background(), testPlan(model.InterceptRedirect)); err != nil {
		t.Fatal(err)
	}
	if r.calls[0] != "iptables-restore -w --noflush <stdin>" {
		t.Errorf("restore must run first, got %q", r.calls[0])
	}
	var inserts []string
	for _, c := range r.calls {
		if strings.Contains(c, " -I ") {
			inserts = append(inserts, c)
		}
	}
	if len(inserts) != 1 || inserts[0] != "iptables -w -t nat -I PREROUTING 1 -j KEENPROXY_DNS" {
		t.Errorf("expected insertion of only the DNS jump, got %v", inserts)
	}
}

func TestApplyLegacyRestoreCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, restoreWithWait, restoreWithoutWait, wantError string
	}{
		{
			name:               "legacy option parser",
			restoreWithWait:    `printf "%s: invalid option -- 'w'\nUsage: iptables-restore\n" "$0" >&2; exit 1`,
			restoreWithoutWait: `cat > "$RESTORE_INPUT"`,
		},
		{
			name:               "musl option parser",
			restoreWithWait:    `printf "%s: unrecognized option: w\n" "$0" >&2; exit 1`,
			restoreWithoutWait: `cat > "$RESTORE_INPUT"`,
		},
		{
			name:               "another unrecognized option is not retried",
			restoreWithWait:    `printf "%s: unrecognized option: noflush\n" "$0" >&2; exit 1`,
			restoreWithoutWait: `cat > "$RESTORE_INPUT"`,
			wantError:          "unrecognized option: noflush",
		},
		{
			name:               "rule error is not an option rejection",
			restoreWithWait:    `printf "iptables-restore: line 7 failed\nrule text: invalid option -- 'w'\n" >&2; exit 1`,
			restoreWithoutWait: `cat > "$RESTORE_INPUT"`,
			wantError:          "line 7 failed",
		},
		{
			name:               "legacy restore still reports rule errors",
			restoreWithWait:    `printf "%s: invalid option -- 'w'\n" "$0" >&2; exit 1`,
			restoreWithoutWait: `printf "iptables-restore: line 7 failed\n" >&2; exit 1`,
			wantError:          "line 7 failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "rules")
			t.Setenv("RESTORE_INPUT", input)
			restore := filepath.Join(dir, "iptables-restore")
			script := `#!/bin/sh
case "$*" in
  '-w --noflush') ` + tc.restoreWithWait + ` ;;
  '--noflush') ` + tc.restoreWithoutWait + ` ;;
  *) exit 99 ;;
esac
`
			if err := os.WriteFile(restore, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			iptables := filepath.Join(dir, "iptables")
			if err := os.WriteFile(iptables, []byte("#!/bin/sh\n[ \"$1\" = -w ] && [ \"$4\" = -C ]\n"), 0700); err != nil {
				t.Fatal(err)
			}
			f := &Firewall{Run: ExecRunner{}, IPTables: iptables, Restore: restore}
			p := testPlan(model.InterceptTProxy)
			err := f.Apply(t.Context(), p)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("Apply error = %v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(input)
			if err != nil || string(got) != p.Render() {
				t.Fatalf("legacy restore did not receive the full firewall plan: %v", err)
			}
		})
	}
}

func TestRemoveDeletesJumpsBeforeChains(t *testing.T) {
	r := &fakeRunner{deleted: map[string]int{}}
	f := &Firewall{Run: r, IPTables: "iptables", Restore: "iptables-restore"}
	if err := f.Remove(context.Background(), testPlan(model.InterceptTProxy)); err != nil {
		t.Fatal(err)
	}
	firstFlush := -1
	lastDelete := -1
	for i, c := range r.calls {
		if strings.Contains(c, " -D ") {
			lastDelete = i
		}
		if strings.Contains(c, " -F ") && firstFlush < 0 {
			firstFlush = i
		}
	}
	if lastDelete < 0 || firstFlush < lastDelete {
		t.Errorf("jumps must be removed before flushing chains: %v", r.calls)
	}
	if r.deleted["nat/PREROUTING/KEENPROXY_DNS"] != 2 {
		t.Errorf("all duplicate jumps must be removed: %v", r.deleted)
	}
}

func TestDetachLegacyMissingChain(t *testing.T) {
	iptables := filepath.Join(t.TempDir(), "iptables")
	script := "#!/bin/sh\nprintf \"iptables v1.8.9 (legacy): Couldn't load target \\140%s':No such file or directory\\n\" \"$7\" >&2\nexit 2\n"
	if err := os.WriteFile(iptables, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	f := &Firewall{Run: ExecRunner{}, IPTables: iptables}
	if err := f.Detach(t.Context(), testPlan(model.InterceptTProxy)); err != nil {
		t.Fatalf("absent owned chains should already be detached: %v", err)
	}
}
