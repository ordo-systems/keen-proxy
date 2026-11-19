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

In **Settings → Network → Interception mode**, KeenProxy reports whether TPROXY passed the preliminary check, was found unavailable, or could not be verified. Select **Check again** after correcting the reported problem. An unknown result does not block Apply. On OpenWrt with `iptables-nft`, the absence of a target from the legacy iptables list does not prove that TPROXY is unavailable.

If the saved TPROXY mode is found unavailable at startup, the panel stays accessible without starting interception. KeenProxy neither loads the module explicitly nor switches to compatible mode automatically. To recover, correct the reported problem, select **Check again**, then **Apply again**. This retry uses the saved settings without rewriting the configuration or its backup. To change modes instead, select **Compatible** and apply the draft. A successful preliminary check is not a traffic test.

In the KeeneticOS component list, check **Open Package support (OPKG)** and **Kernel modules for Netfilter**. Entware supplies the `iptables` commands separately. Even with Netfilter and Xtables-addons installed, the TPROXY module may be present on disk but not loaded.

**Kernel and iptables checks.** Save as `test1.sh` and run `sh test1.sh` in an Entware SSH session. This does not apply rules or explicitly load modules.

```sh
#!/bin/sh
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
section() { printf '\n=== %s ===\n' "$1"; }
iptables=/opt/sbin/iptables
restore=/opt/sbin/iptables-restore

section 'Kernel and Entware'
uname -rm
if command -v opkg >/dev/null 2>&1; then
    opkg list-installed | grep -E '^(iptables|xtables)([[:space:]]|-)'
else
    echo 'opkg not found'
fi

section 'iptables and iptables-restore'
ls -l "$iptables" "$restore"
"$iptables" -w --version 2>&1
printf 'iptables version exit=%s\n' "$?"
"$restore" --help </dev/null 2>&1

section 'Kernel targets and modules (before iptables probes)'
if [ -r /proc/net/ip_tables_targets ]; then
    if grep -qx TPROXY /proc/net/ip_tables_targets; then
        echo 'TPROXY target: registered'
    else
        echo 'TPROXY target: not listed or unreadable'
    fi
else
    echo '/proc/net/ip_tables_targets unavailable'
fi
if [ -r /proc/modules ]; then
    awk '
        $1 ~ /^(xt_TPROXY|xt_socket|iptable_mangle)$/ {
            printf "%s: loaded (size=%s, refs=%s)\n", $1, $2, $3
            found = 1
        }
        END { if (!found) print "No matching loadable modules listed" }
    ' /proc/modules
else
    echo '/proc/modules unavailable'
fi

section 'TPROXY userspace extension'
help=$("$iptables" -t mangle -j TPROXY --help 2>&1)
if ! printf '%s\n' "$help" |
    grep -Ei 'TPROXY target options|--on-port|--on-ip|--tproxy-mark|error|failed|not found'; then
    printf '%s\n' "$help" | tail -10
fi

section 'IPv4 mangle and KeenProxy rules'
"$iptables" -w -t mangle -S >/dev/null
printf 'mangle read exit=%s\n' "$?"
if rules=$("$iptables" -w -t mangle -S KEENPROXY_UDP 2>&1); then
    printf '%s\n' "$rules" | awk '
        / -j TPROXY( |$)/ { count++ }
        END { printf "KEENPROXY_UDP: %d TPROXY rule(s)\n", count }
    '
else
    printf 'KEENPROXY_UDP unavailable: %s\n' "$rules"
fi

section 'Recent kernel messages'
if messages=$(dmesg 2>&1); then
    matches=$(printf '%s\n' "$messages" |
        grep -Ei 'tproxy|x_tables|ip_tables|unknown symbol|invalid module' |
        tail -30)
    printf '%s\n' "${matches:-No matching kernel messages}"
else
    printf 'dmesg unavailable: %s\n' "$messages"
fi
```

**Module files and tools.** Save as `test2.sh` and run `sh test2.sh` to check the running firmware without loading anything. An unavailable `/proc/config.gz` does not prevent the other checks.

```sh
#!/bin/sh
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
section() { printf '\n=== %s ===\n' "$1"; }
release=$(uname -r)
module="/lib/modules/$release/xt_TPROXY.ko"

section 'Module for the running kernel'
printf 'Kernel release: %s\n' "$release"
if [ -f "$module" ]; then
    ls -l "$module"
else
    printf 'Not found at the expected path: %s\n' "$module"
fi

section 'Other TPROXY module files'
for dir in /lib/modules /opt/lib/modules; do
    printf '%s:\n' "$dir"
    if [ -d "$dir" ]; then
        matches=$(find "$dir" -type f -iname '*tproxy*.ko*' -print)
        printf '%s\n' "${matches:-  No matching files}"
    else
        echo '  Directory unavailable'
    fi
done

section 'Module tools (not executed)'
for tool in modprobe insmod modinfo; do
    if path=$(command -v "$tool"); then
        printf '%s: %s\n' "$tool" "$path"
    else
        printf '%s: not found\n' "$tool"
    fi
done

section 'Kernel build options'
if [ -r /proc/config.gz ] && command -v zcat >/dev/null 2>&1; then
    zcat /proc/config.gz |
        grep -E '^(# )?CONFIG_(NETFILTER_XT_TARGET_TPROXY|NF_TPROXY_IPV4)(=| is not set)' ||
        echo 'No matching options found or kernel config could not be read'
else
    echo '/proc/config.gz or zcat unavailable'
fi
```

If the help lists `--on-port`, `--on-ip`, and `--tproxy-mark`, the Entware command recognizes the extension. A successful `mangle` read only confirms that the table is accessible. Neither proves that the kernel will accept a TPROXY rule. `TPROXY` in `/proc/net/ip_tables_targets` confirms that the target is registered; absence from `/proc/modules` alone does not rule out built-in support.

**If the target is missing but the firmware module exists**, the router owner can try loading it temporarily. Keep local recovery access and do this when it is safe to retest Apply. Use only the module shipped with the running firmware; do not download a `.ko` from another router or distribution.

Save the optional loader as `load-tproxy.sh` and run it separately with `sh load-tproxy.sh`. It skips `insmod` if the target is already registered, the module is already loaded, or either kernel check fails.

```sh
#!/bin/sh
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin

targets=/proc/net/ip_tables_targets
modules=/proc/modules
module="/lib/modules/$(uname -r)/xt_TPROXY.ko"

if grep -xq TPROXY "$targets"; then
    echo 'TPROXY target already registered; skipping insmod'
    exit 0
elif [ "$?" -ne 1 ]; then
    echo 'Cannot check kernel targets; skipping insmod' >&2
    exit 1
fi
if grep -q '^xt_TPROXY ' "$modules"; then
    echo 'xt_TPROXY already loaded but target not listed; skipping insmod' >&2
    exit 1
elif [ "$?" -ne 1 ]; then
    echo 'Cannot check loaded modules; skipping insmod' >&2
    exit 1
fi
if [ ! -f "$module" ]; then
    printf 'Firmware module not found: %s\n' "$module" >&2
    exit 1
fi
insmod "$module" || exit "$?"
grep -x TPROXY "$targets"
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
