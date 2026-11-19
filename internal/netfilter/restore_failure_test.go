package netfilter

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestApplyReportsLegacyRestoreFailureLocation(t *testing.T) {
	for _, tc := range []struct {
		name, pattern, stderr, operation, chain, target string
	}{
		{"rule", `/-j TPROXY/`, `"iptables-restore: line " NR " failed"`, "append_rule", ChainUDP, "TPROXY"},
		{"commit", `/^COMMIT$/ && table == "*mangle"`, `"iptables-restore: line " NR " failed"`, "commit", "", ""},
		{"legacy parameter error", `/-j TPROXY/`, `"Error occurred at line: " NR`, "append_rule", ChainUDP, "TPROXY"},
		{"nft rule error", `/-j TPROXY/`, `"iptables-restore: line " NR ": RULE_APPEND failed (Invalid argument): rule in chain KEENPROXY_UDP"`, "append_rule", ChainUDP, "TPROXY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := filepath.Join(t.TempDir(), "iptables-restore")
			script := `#!/bin/sh
case "$*" in
  '-w --noflush') printf "%s: invalid option -- 'w'\n" "$0" >&2; exit 1 ;;
  '--noflush') awk '/^\*/ { table = $0 } ` + tc.pattern + ` { print ` + tc.stderr + `; exit }' >&2; exit 1 ;;
  *) exit 99 ;;
esac
`
			if err := os.WriteFile(restore, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			f := &Firewall{Run: ExecRunner{}, Restore: restore}
			err := f.Apply(t.Context(), testPlan(model.InterceptTProxy))
			var failure *RestoreFailure
			if !errors.As(err, &failure) || failure.Wait || failure.ExitCode != 1 || failure.Line <= 0 ||
				failure.Table != "mangle" || failure.Operation != tc.operation || failure.Chain != tc.chain || failure.Target != tc.target {
				t.Fatalf("restore failure = %+v, error = %v", failure, err)
			}
		})
	}
}
