package api

import (
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

// supportFirewall retains only known probe metadata. Historical journal
// payloads are untrusted, even when they claim to originate from the watchdog.
func supportFirewall(e journal.Entry) *journal.FirewallEvent {
	if e.Firewall == nil || e.Actor != "watchdog" || e.Target != "firewall" {
		return nil
	}
	outcome := known(e.Firewall.Outcome, "restored", "apply_failed", "verify_failed")
	if outcome == "" {
		return nil
	}
	return &journal.FirewallEvent{
		Trigger:    known(e.Firewall.Trigger, "netfilter_hook", "watchdog"),
		DurationMS: supportFirewallDuration(e.Firewall.DurationMS),
		Outcome:    outcome,
		Before:     supportFirewallCheck(e.Firewall.Before),
		After:      supportFirewallCheck(e.Firewall.After),
		ApplyError: failureClass(e.Firewall.ApplyError),
		Restore:    supportRestoreDiagnostic(e.Firewall.Restore),
	}
}

func supportFirewallApply(e journal.Entry) *journal.FirewallApplyDiagnostic {
	if e.FirewallApply == nil || e.Action != "Configuration apply failed" || e.Target != "config" || e.Result != "error" {
		return nil
	}
	restore := supportRestoreDiagnostic(e.FirewallApply.Restore)
	rollback := supportRestoreDiagnostic(e.FirewallApply.RollbackRestore)
	if restore == nil && rollback == nil {
		return nil
	}
	return &journal.FirewallApplyDiagnostic{Restore: restore, RollbackRestore: rollback}
}

func supportRestoreDiagnostic(f *journal.RestoreDiagnostic) *journal.RestoreDiagnostic {
	if f == nil {
		return nil
	}
	safe := &journal.RestoreDiagnostic{Wait: f.Wait, ExitCode: f.ExitCode}
	if safe.ExitCode < 0 || safe.ExitCode > 255 {
		safe.ExitCode = -1
	}
	if f.Line > 0 {
		safe.Line = f.Line
		safe.Table = known(f.Table, "nat", "mangle", "filter")
		safe.Operation = known(f.Operation, "table", "declare_chain", "append_rule", "commit")
		safe.Chain = known(f.Chain, netfilter.ChainDNS, netfilter.ChainDNSGuard, netfilter.ChainTCP, netfilter.ChainUDP, netfilter.ChainQUIC)
		safe.Target = known(f.Target, "RETURN", "REDIRECT", "TPROXY", "REJECT")
	}
	return safe
}

func supportFirewallDuration(ms *int64) *int64 {
	if ms == nil || *ms < 0 {
		return nil
	}
	return ms
}

func supportFirewallCheck(check *journal.FirewallCheck) *journal.FirewallCheck {
	if check == nil {
		return nil
	}
	// Match a whole owned jump, rather than allowing arbitrary chain names.
	for _, jump := range (netfilter.Plan{Mode: model.InterceptTProxy}).Jumps() {
		if check.Table == jump.Table && check.Chain == jump.From && check.Target == jump.To {
			exitCode := check.ExitCode
			if exitCode < 0 || exitCode > 255 {
				exitCode = -1
			}
			return &journal.FirewallCheck{
				Table: jump.Table, Chain: jump.From, Target: jump.To, ExitCode: exitCode,
				Reason: known(check.Reason, "execution_failed", "command_failed", "check_failed", "timeout", "canceled"),
				Error:  failureClass(check.Error),
			}
		}
	}
	return nil
}
