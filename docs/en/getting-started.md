# Getting started

## Experimental OpenWrt support

KeenProxy requires **at least 256 MiB of total RAM** on OpenWrt and Keenetic/Netcraze routers, plus enough storage for the binary and its data. Releases provide full and lite Linux binaries for x86-64 (`amd64`, baseline v1), 32-bit x86 (`386`, requires SSE2), ARM32 (ARMv5 or later, soft float, suffix `armv5`), ARM64 (`arm64`), little-endian MIPS (`mipsle`, soft float), and big-endian MIPS (`mipsbe`, soft float).

Native OpenWrt installation and panel updates use the system shell and procd, without Entware. Both native OpenWrt and Entware support the six release architectures listed above. The interception runtime still requires compatible `iptables`, `iptables-restore`, and kernel support. Verify interception with a test client on your firmware, especially on systems using firewall4. This does not add a native nftables backend. [OpenWrt netfilter documentation](https://openwrt.org/docs/guide-user/firewall/netfilter_iptables/netfilter_management)

The optional NDM netfilter hook is specific to compatible Keenetic/Netcraze firmware. On OpenWrt without NDM it stays disabled and creates no NDM hook or event files; the regular watchdog continues checking every 30 seconds by default. No OpenWrt hotplug or firewall4 integration is installed. See [firewall recovery](network-flow.md#how-firewall-rules-recover-after-a-firmware-change).

### Native OpenWrt installation

Keep SSH/LAN recovery access, back up the configuration, and stop competing DNS/traffic interceptors. The service starts LAN DNS interception on its first start. Ensure enough persistent overlay storage for the binary, a staged replacement, and a rollback copy; `/tmp` free space alone is not sufficient.

Install `curl`, CA certificates, and compatible iptables tools using the package manager for your firmware (`opkg` or `apk`). Package names vary by release; common choices include `curl`, `ca-bundle`, and `iptables-nft`. REDIRECT needs NAT support; UDP TPROXY additionally needs matching TPROXY/mangle modules. Installing a package does not prove its compatibility with your firmware.

Check the native environment before installation:

```sh
uname -m
df -h /overlay /usr
free
test -x /sbin/procd && test -f /etc/openwrt_release
test -x /usr/sbin/iptables-restore
/usr/sbin/iptables -t nat -S
```

Then run as root:

```sh
curl -fsSL https://raw.githubusercontent.com/ordo-systems/keen-proxy/main/tools/bootstrap.sh | KEENPROXY_PLATFORM=openwrt /bin/sh
```

The bootstrap installs `/usr/bin/keenproxy`, enables `/etc/init.d/keenproxy` for boot through procd, and starts the service. It verifies checksums and validates the configuration before replacing a running version. A failed startup triggers restoration of the previous files and service. Full and lite builds both embed TrustTunnel; no external helper is needed.

The clean configuration is `/etc/keenproxy/config.yaml`, with `api.token_file: /etc/keenproxy/token` and `lan.interface: br-lan`. Change the bridge name if your firmware differs. Existing configurations and tokens are preserved. The CLI retains Entware defaults, so pass the native configuration explicitly:

```sh
keenproxy --url -config /etc/keenproxy/config.yaml
keenproxy --key -config /etc/keenproxy/config.yaml
/etc/init.d/keenproxy status
```

Use the same bootstrap command to update. Append `-s -- --version vX.Y.Z --lite` to `/bin/sh` to choose a release/variant; append `-s -- --uninstall` to stop and disable the native service and remove its binary/init script while retaining settings. Panel updates and scheduling work as described below.

Native release transactions require the checksummed `keenproxy.openwrt` asset. Older releases without it are not valid native installation or rollback targets; rejection leaves the running version unchanged. Release records and update preferences live persistently under `/usr/share/keenproxy/`; rule sets, logs, and derived state under `/var/lib/keenproxy/` are normally volatile on OpenWrt.

Automatic detection preserves an existing managed Entware installation rather than migrating it on an OpenWrt host. `KEENPROXY_PLATFORM=openwrt` explicitly selects native installation; do not run native and Entware instances simultaneously. The remaining router-preparation and Entware shell commands below describe the Entware path only.

## Prepare the router

### Hardware and firmware

- **CPU.** The installer supports the six release architectures listed above. Use a matching Linux userspace; 32-bit x86 requires SSE2. For MIPS, confirm the byte order with the package architecture or the model guide.
- **Firmware.** Use a Keenetic or Netcraze model with Open Package support (OPKG), an Entware shell, and compatible `iptables` tools. TCP interception uses REDIRECT. UDP interception in `tproxy` mode also requires kernel TPROXY support and policy routing.
- **Storage.** Use an external USB drive for Entware and KeenProxy. Compare the release binary size with the free space on `/opt` and leave room for Entware, the configuration, rule sets and filter data, and a rollback copy. The lite binary is smaller and supports fewer protocols.
- **RAM.** At least **256 MiB of total router RAM**, including for lite builds. This is the supported hardware floor, not a guarantee that every workload fits. Check available memory with your usual router services running; reserve headroom for firmware, the engine, connections, and enabled lists. Monitor memory during the first test with your own configuration. The default 768 MiB Go memory recommendation is not a physical-memory requirement or a hard RSS limit.

**Recommended firmware component.** Enable **Kernel modules for Netfilter** alongside OPKG if your model offers it. It supplies kernel support for packet filtering used by `iptables`; the Entware commands are a separate prerequisite. Check the component list for your exact model. [KeeneticOS component reference](https://support.keenetic.com/hopper/kn-3810/en/16327-os-component-description.html)

If Apply fails with UDP interception enabled, see [TPROXY troubleshooting on Keenetic](troubleshooting.md#keenetic-tproxy-apply).

### Choose where to install Entware

| Method | How it works |
| --- | --- |
| **USB drive (recommended)** | A standard USB flash drive that your router recognizes is sufficient if it has enough space. Prepare an ext4 partition as described below, enable OPKG, then place the installer archive for your model in the partition's `install` folder. Select that partition in OPKG Package Manager. [Keenetic USB guide](https://support.keenetic.com/hopper-se/kn-3812/en/20980-installing-the-entware-repository-on-a-usb-drive.html) |
| **Internal storage (not recommended)** | Available on selected models and firmware versions. The built-in partition can leave little room for updates, filter lists, and a rollback copy. If you use it, check free space on `/opt` before installing KeenProxy. The vendor guide covers setup from OPKG Package Manager, the CLI, and an installer archive. [Keenetic internal storage guide](https://support.keenetic.com/titan/kn-1811/en/18482-installing-opkg-entware-in-the-router-s-internal-memory.html) |

**Prepare the USB drive on the router.** On supported models running KeeneticOS or NetcrazeOS 5.1 or later, enable the **Ext filesystem** component and the **EXT4 filesystem utilities** in the firmware component settings. Connect the drive and open **Management → Storage & Devices**. Choose **Format** for the partition you want to use, then select **EXT4**. Formatting erases the selected partition, so back up its files first. If the router does not offer this feature, format the drive as ext4 on a computer. [Keenetic formatting guide](https://support.keenetic.com/hero/kn-1013/en/100924-formatting-and-checking-a-file-system-on-a-usb-drive.html)

The linked manuals use specific models as examples. Use the components and installer archive listed for your own model.

### Verify the environment

After Entware setup, connect to the Entware shell from the LAN and change its initial password. Back up the router settings and keep local access for recovery. Run these read-only checks before copying KeenProxy:

```sh
uname -m
opkg print-architecture
df -h /opt
free
command -v iptables
command -v iptables-restore
iptables -t nat -S
```

Confirm the architecture, free disk space, available memory, and firewall tools. Start with an example configuration and replace its placeholder connection details privately.

The last command lists IPv4 NAT rules without editing them. For `tproxy` mode, also check that `iptables -t mangle -S` succeeds. Table access is a preliminary check. Verify REDIRECT or TPROXY with traffic from a test client before relying on interception.

## Install or update from GitHub

Install `curl` and the CA certificates in the Entware root shell if needed.

```sh
opkg update && opkg install curl ca-bundle ca-certificates
```

Stop competing traffic or DNS interception services before installation. KeenProxy begins intercepting LAN DNS when the daemon starts, including with the starter configuration. Run the bootstrap from `main`:

```sh
curl -fsSL https://raw.githubusercontent.com/ordo-systems/keen-proxy/main/tools/bootstrap.sh | /opt/bin/sh
```

The installer reads `version.txt` from `main`, detects the CPU, and verifies the release files against `SHA256SUMS`. It installs missing Entware `iptables` tools, creates a starter configuration if needed, and registers and starts `S99keenproxy` through the Entware init mechanism. TrustTunnel runs inside sing-box-lx; no separate client is installed. After installation and command-line updates, it prints the panel URL when the installed binary can determine it. Display the current token with `keenproxy --key` in the router's Entware shell; the installer never prints it automatically. See [panel access](user-guide.md#access-the-panel).

On a clean install, the bootstrap creates `/opt/etc/keenproxy/config.yaml` with `schema_version: 1` and KeenProxy fills in defaults when it loads the file. The daemon generates the login token on first startup if the token file is missing. `keenproxy --key` reads the existing configured `api.token_file` without generating a replacement. The default path is `/opt/etc/keenproxy/token`. On older releases without the flag, read that file (or your custom token path) directly. `keenproxy --url` displays the configured access URL again; if an older binary or unavailable LAN address prevents discovery, the installer reports that limitation without rolling back a successful installation.

Run the same command to update. Your configuration and token are preserved. The installer stages and validates the candidate before stopping the managed service. If the new service fails its startup check, it attempts to restore the previous files and restart the previous service. A manually started instance must be stopped before the installer can take over.

To choose a release, replace `vX.Y.Z` with a published tag. The optional `--lite` flag selects the smaller build without QUIC/HTTP/3. `--without-trusttunnel` remains accepted for existing updaters and scripts, but no longer changes the payload: TrustTunnel is embedded. `--trusttunnel-only` is no longer accepted.

```sh
curl -fsSL https://raw.githubusercontent.com/ordo-systems/keen-proxy/main/tools/bootstrap.sh | /opt/bin/sh -s -- --version vX.Y.Z
```

The tag must have installer assets and checksums attached. If publication is still in progress, wait for the assets and rerun the command. Service commands are `status`, `start`, `stop`, and `restart` on `/opt/etc/init.d/S99keenproxy`. See the root README for manual installation. [Installation reference](https://github.com/ordo-systems/keen-proxy#configuration-and-router-installation)

## Update from the panel

On a managed Entware or native OpenWrt installation, **Settings → Updates** shows the installed version, the latest available stable release, and the previous installed version when recorded. Upgrade once with the command-line bootstrap if the current build predates panel updates. To make that older release a rollback target, first rerun the current bootstrap with the exact tag and build variant already installed, then upgrade. Native OpenWrt additionally requires that target release's procd asset. Update actions and schedule changes require the panel token, including on trusted networks.

Automatic installation is off by default. The panel still checks for releases. Enable automatic installation and save a time to install available releases during that minute in the router's local time, once per day while the service is running. Installation briefly restarts KeenProxy.

**Roll back** reinstalls the previous published version and switches off automatic installation. It needs access to GitHub and keeps the existing configuration and token. The installer rejects an incompatible configuration before restarting the service. Rolling back to a version released before panel updates also restores that version's earlier panel. Use the command-line installer to upgrade again.

## First configuration

Follow the [user guide](user-guide.md): inspect a connection, add a domain group, choose a network/client policy, Apply, then verify using **Diagnostics** and **Logs**. Start with a small set of domains and one test device.

## Updates and recovery

Back up the current configuration and keep the old binary before updating. Read release compatibility and migration notes. Settings can preview a previous configuration into the shared draft; applying it still requires **Apply**. Do not assume a successful HTTP probe establishes that all HTTPS traffic works.

## Uninstall

Run from the Entware root shell:

```sh
curl -fsSL https://raw.githubusercontent.com/ordo-systems/keen-proxy/main/tools/bootstrap.sh | /opt/bin/sh -s -- --uninstall
```

The command stops the managed service and removes `/opt/bin/keenproxy` and `/opt/etc/init.d/S99keenproxy`. It preserves `/opt/etc/keenproxy/` (including configuration and token), `/opt/var/lib/keenproxy/` (logs and derived state), and any previously installed external TrustTunnel client. KeenProxy no longer uses that executable. Run the regular installer again to reuse your settings.
