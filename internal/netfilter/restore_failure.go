package netfilter

import (
	"errors"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// RestoreFailure describes the final restore invocation without retaining its input.
// Err preserves the original command failure for local diagnostics.
type RestoreFailure struct {
	Err                             error
	Wait                            bool
	ExitCode, Line                  int
	Table, Operation, Chain, Target string
}

func (f *RestoreFailure) Error() string { return f.Err.Error() }
func (f *RestoreFailure) Unwrap() error { return f.Err }

// Legacy restore and the nft backend report input locations differently.
var restoreLineFailure = regexp.MustCompile(`(?m)^(?:[^\r\n]*: )?(?:line ([0-9]+) failed|Error occurred at line: ([0-9]+)|line ([0-9]+): [A-Z_]+ failed[^\r\n]*)\r?$`)

func describeRestoreFailure(err error, rules string, wait bool) *RestoreFailure {
	f := &RestoreFailure{Err: err, Wait: wait, ExitCode: -1}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return f
	}
	if exit.ProcessState != nil {
		f.ExitCode = exit.ExitCode()
	}
	match := restoreLineFailure.FindSubmatch(exit.Stderr)
	if match == nil {
		return f
	}
	var number []byte
	for _, group := range match[1:] {
		if len(group) > 0 {
			number = group
			break
		}
	}
	n, err := strconv.Atoi(string(number))
	if err != nil || n <= 0 {
		return f
	}
	f.Line = n
	var table string
	for line := range strings.SplitSeq(rules, "\n") {
		if name, ok := strings.CutPrefix(line, "*"); ok {
			table = name
		}
		n--
		if n == 0 && line != "" {
			// Journal entries outlive this invocation; retain only the labels.
			f.Table = strings.Clone(table)
			switch fields := strings.Fields(line); {
			case strings.HasPrefix(line, "*"):
				f.Operation = "table"
			case line == "COMMIT":
				f.Operation = "commit"
			case strings.HasPrefix(line, ":"):
				f.Operation, f.Chain = "declare_chain", strings.Clone(fields[0][1:])
			case len(fields) >= 2 && fields[0] == "-A":
				f.Operation, f.Chain = "append_rule", strings.Clone(fields[1])
				if _, tail, ok := strings.Cut(line, " -j "); ok {
					target, _, _ := strings.Cut(tail, " ")
					f.Target = strings.Clone(target)
				}
			}
			break
		}
		if line == "COMMIT" {
			table = ""
		}
	}
	return f
}
