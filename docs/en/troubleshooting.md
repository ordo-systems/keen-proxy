# Troubleshooting

## The demo says a tunnel works. Is it real?

No. Every address, counter, DNS result, and connectivity check in the browser demo is simulated. It does not contact the listed VPN servers, resolve your domains, download lists, or configure a router. Reload the page to reset configuration changes.

## I edited a profile, but traffic did not change

Look for pending changes and choose **Apply**. All screens share a draft. Confirm that the selected network/client uses the intended routing mode, then inspect the route journal and test the applied connection.

## I cannot retrieve the panel token

`keenproxy --key` loads and validates the entire configuration before reading `api.token_file`. A configuration error after a manual edit therefore blocks the command even when the existing token file is intact. Fix or restore the configuration; do not delete or rotate the token to work around the error.

In the router's Entware root shell, you can read the existing token file directly:

```sh
cat /opt/etc/keenproxy/token
```

Use your configured `api.token_file` path if it differs from the default. Keep the output private: it is a login credential, not a diagnostic attachment.

## HTTP passes but the application fails

Run HTTPS and transfer checks separately. Inspect certificate/time errors, profile details, system logs, and fallback behavior. A process being alive or one HTTP response succeeding is weaker evidence than a successful application transfer.

## A domain has no current IPs

Check whether the group is enabled and applied. Review its DNS route, resolver availability, expiration and error details. Manual preview observations are separate from applying the configuration. Demo `.invalid` names intentionally return synthetic errors.

## Why does the watchdog restore interception rules?

Older Keenetic Entware builds (such as `iptables 1.4.21-6`) can accept `-w` in `iptables` but reject it in `iptables-restore`. KeenProxy retries once without `-w` only for the known glibc (`invalid option -- 'w'`) or musl (`unrecognized option: w`) diagnostic. It keeps `--noflush` to preserve unrelated firewall rules. Other restore errors are reported as-is. This does not bypass missing Netfilter or TPROXY support.

The watchdog checks the required firewall entry jumps every 30 seconds by default. A failed check triggers a repair attempt. The audit event records the first failed table, built-in chain, target, exit code and command error. Exit code 1 is reported as a failed check, because the code alone cannot establish why the command failed. A value of -1 means no normal process exit code was available.

On a managed Linux installation, KeenProxy also enables an optional NDM callback when `/var/run/ndm.core.socket` and `/opt/etc/ndm` are present. This covers compatible Keenetic/Netcraze firmware without assuming every router supports NDM. The daemon owns `/opt/etc/ndm/netfilter.d/99-keenproxy.sh` and a private runtime event file. IPv4 `nat`, `filter` and `mangle` callbacks request a serialized check of the current rules without restarting the engine. Repeated notifications coalesce. The 30-second watchdog remains active on every platform, including when callback setup fails.

A clean exit removes the managed hook. Uninstall also cleans up the managed hook after the service has stopped, including leftovers from an interrupted shutdown. Foreign hook files are preserved. A callback queued after shutdown or binary rollback exits harmlessly when the event file is absent. The system journal records `netfilter event hook enabled` at startup. Each repair attempt appears once in the audit journal with its check trigger: **Netfilter hook** or **Watchdog timer**. The panel shows a short result and rule identity; expand the entry for exit codes and the original command errors. Historical entries without trigger metadata show **Not recorded**. Check-and-recovery time measures the work from the first check through verification, not outage duration. Successful recovery and routine event checks are not repeated in the system journal; hook setup/watcher errors and failed recovery remain there. Firmware callback queues and rule application still take time: event recovery does not guarantee zero packet loss. See the [NDM hook contract](https://support.keenetic.ua/titan/kn-1811/en/42407-opkg-component-description.html).

After applying the rules, the watchdog checks the entry jumps again. If verification fails, it waits briefly and retries the repair once to allow for firmware replacing several tables in succession. The counter increases only after verified recovery, including retries of failed rule updates; it does not count firmware rebuilds specifically. A failure records the initial check, the final attempt's outcome, and its verification result if verification ran. If both a configuration apply and its rollback fail while installing firewall rules, the watchdog can retry the pending plan once its engine, DNS listener, and policy routing are ready. Failed rule updates after device address changes are also retried, even when the old entry jumps still exist. If rollback fails earlier while preparing dependencies, firewall recovery cannot safely restore the configuration: resolve the reported engine, DNS, or routing error, then apply the configuration again or restart the service. A successful check establishes entry-jump presence at that moment. It does not validate every rule inside the chains, TPROXY policy routes, or end-to-end connectivity.

For repeated recoveries, record the times of the triggering actions and export the diagnostics ZIP together with the router system log. The ZIP retains structured firewall evidence under the audit entry's `firewall` field, including the optional `trigger` (`netfilter_hook` or `watchdog`) and nonnegative `duration_ms`, any failed `before` and `after` checks, and `outcome` (`restored`, `apply_failed`, or `verify_failed`). Raw command errors remain in the local journals. The ZIP keeps only known rule identities, exit codes, reasons and coarse error categories. Older entries have no `firewall` field.

## Apply fails in TPROXY mode on Keenetic { #keenetic-tproxy-apply }

The error `iptables-restore: line N failed` does not necessarily mean TPROXY is missing. Start with the exact Apply error and the [`firewall_apply.restore` entry in the diagnostic ZIP](#download-the-diagnostic-zip). If the reported operation is `commit`, it identifies the table whose commit failed, not a specific rule.

In the KeeneticOS component list, check **Open Package support (OPKG)** and **Kernel modules for Netfilter**. Entware supplies the `iptables` commands separately. Even with Netfilter and Xtables-addons installed, the TPROXY module may be present on disk but not loaded.

**Check what is available.** Run these commands over the router's Entware SSH session. They do not apply firewall rules or explicitly load a module:

```sh
uname -rm
/opt/bin/opkg list-installed | grep '^iptables '
grep -x TPROXY /proc/net/ip_tables_targets
grep '^xt_TPROXY ' /proc/modules
ls -l "/lib/modules/$(uname -r)/xt_TPROXY.ko"
/opt/sbin/iptables -t mangle -j TPROXY --help
/opt/sbin/iptables -w -t mangle -S >/dev/null
echo "mangle read exit=$?"
```

If the help lists `--on-port`, `--on-ip`, and `--tproxy-mark`, the Entware command recognizes the extension. A successful `mangle` read only confirms that the table is accessible. Neither proves that the kernel will accept a TPROXY rule. `TPROXY` in `/proc/net/ip_tables_targets` confirms that the target is registered; absence from `/proc/modules` alone does not rule out built-in support.

**If the target is missing but the firmware module exists**, the router owner can try loading it temporarily. Keep local recovery access and do this when it is safe to retest Apply. Use only the module shipped with the running firmware; do not download a `.ko` from another router or distribution.

```sh
insmod "/lib/modules/$(uname -r)/xt_TPROXY.ko"
echo "insmod exit=$?"
grep -x TPROXY /proc/net/ip_tables_targets
```

In [issue #39](https://github.com/ordo-systems/keen-proxy/issues/39), the target appeared after this step. If it appears on your router, retry **Apply** in TPROXY mode. After a successful Apply, check that `/opt/sbin/iptables -w -t mangle -S KEENPROXY_UDP` shows a `-j TPROXY` rule for participating clients, then test UDP traffic from one of those clients. Manual module loading does not persist across reboot. If loading fails, capture its error and relevant lines from `dmesg | tail -30`. If Apply still fails, include the full Apply error and the reviewed diagnostic ZIP in your report. If you do not need transparent UDP interception, use the compatible (`redirect`) mode while investigating. Redact private addresses and kernel pointers before sharing command output.

## Download the diagnostic ZIP

1. Reproduce the problem and note the approximate time and time zone. Open **Diagnostics** in the web panel on your router.
2. Find **Diagnostics archive** near the top of the page, below **Build details** when shown. Choose **Download ZIP**. Open the downloaded `keenproxy-diagnostics.zip` and review its contents before sharing.

| File | What it contains |
| --- | --- |
| `README.txt` | Archive format and a summary of the privacy rules |
| `config.json` | A sanitized summary of applied settings, including routing, connections, and DNS policies |
| `status.json` | Runtime state at export time, including build identity, interception, connection health, and active fallbacks |
| `journals/routes.jsonl`, `journals/audit.jsonl`, `journals/system.jsonl` | All readable records still retained by KeenProxy, with one event per line |

The ZIP includes records still in memory and on disk, regardless of the filters, grouping, or time range selected in **Logs**. Older records may have rotated out. Draft changes are outside the archive.

When `iptables-restore` fails during Apply, look for **Configuration apply failed** in `journals/audit.jsonl`. `firewall_apply.restore` describes the failed attempt; `rollback_restore` describes a separate restore failure during rollback, if any. The ZIP records the exit code, whether `-w` was used, and, when reported, the input line number and known table, operation, chain, and jump target. A `commit` failure identifies a table, not a particular rule. Watchdog failures use `firewall.restore`. Raw errors remain in the local journal; the ZIP does not include rule arguments or raw stderr.

The export omits credentials, raw connection profiles, and free-form log messages. Names and addresses are removed or replaced with aliases that are consistent within one ZIP. Event times, ports, protocols, policies, and counts can still identify activity. Review the files before attaching them to an issue or sharing them privately.

For one journal as plain text on the router, open **Logs**, select **Routing**, **Audit**, or **System**, then choose **Download log** and a time range. The text export masks known secrets but can include readable domains, addresses, and log details. Use the ZIP for a support report covering all three journals.

**Download report** on the Diagnostics screen saves `keenproxy-diagnostics.json` with a status summary and results from any checks you ran for the selected connection. In the browser demo this report contains synthetic data, and ZIP download is available only in the router panel. For a restorable configuration, use **Settings → YAML configuration** and store the export privately.

## What should a bug report include?

Include the expected and actual behavior, the running release and build details, router model and firmware, steps to reproduce, and the approximate time of the incident. Use a minimal synthetic configuration or attach a reviewed [diagnostic ZIP](#download-the-diagnostic-zip). Read [CONTRIBUTING](https://github.com/ordo-systems/keen-proxy/blob/main/CONTRIBUTING.md) and [SECURITY](https://github.com/ordo-systems/keen-proxy/blob/main/SECURITY.md).
