# User guide

These screenshots show the same Vue screens shipped by KeenProxy, running in the independent browser demo. Addresses, counters, profiles, and results are synthetic. The guide covers the implemented interface, rather than promising every feature shown in historical mockups.

## Access the panel

After a successful installation or command-line update, the installer prints the panel URL. Open it from your LAN. To display the current login token, run this command in the router's Entware shell:

```sh
keenproxy --key
```

Paste the token into the sign-in form. Treat it as a password: do not include it in screenshots, support reports or shared terminal output. The installer does not print the token automatically.

You can display the URL again with `keenproxy --url`. Both commands read the existing configuration without starting the daemon or changing its settings. `--key` reads the configured `api.token_file`; it does not create or rotate a missing token. For a non-default configuration:

```sh
keenproxy --key --config /path/to/config.yaml
keenproxy --url --config /path/to/config.yaml
```

The URL follows `api.listen`; wildcard listeners use an address from the configured LAN interface. If that interface has no usable address, no address is guessed. A loopback listener remains accessible only from the router or through a suitable SSH tunnel. See [installation and updates](getting-started.md#install-or-update-from-github).

## 1. Read the overview

Open **Overview** to see connection health, recent traffic, and the router's CPU and memory usage. The first resource row covers the whole router. The **KeenProxy** row shows its share of total router CPU time and its resident memory (RSS). This includes embedded sing-box. An external TrustTunnel client is measured by the router totals. When a new release is available, follow its notice to **Settings**. Traffic graphs describe observed activity and cannot establish whether traffic leaks.

![Overview with synthetic traffic and connection cards](../assets/screenshots/en-overview.png)

## 2. Configure a connection

Open **Connections**. Select a profile to inspect its settings and status. Choose **Add** to use the wizard: import a supported connection link/file or enter a supported protocol manually. Use a descriptive name and inspect the proposed protocol and endpoint before accepting.

The file picker accepts `.conf`, `.txt`, `.json`, and `.vpn` up to 2 MiB. For a sing-box file with multiple profiles, choose the outbound or endpoint to import. Router DNS and routes stay under KeenProxy control. In **Failover**, choose the immediate backup and review the inherited chain. Connection parameters stay hidden until you reveal them. See [how failover works](routing.md#fallback-chains).

Changes enter the shared draft. Real credentials belong only in your local management session. In the browser demo, use synthetic values.

Use the connection's **Enabled** switch to pause it without deleting its profile, credentials, or routing references. The switch changes the draft only; the running connection changes after **Apply**, and **Discard** restores the saved state. A disabled connection stays visible and editable, but its tunnel/client and availability checks do not run.

Groups, devices, networks, and DNS settings keep their references to a disabled connection. Traffic follows its configured enabled fallback chain; with no enabled fallback it is blocked, not silently routed directly or passed to the next rule. An explicitly configured **Direct** fallback remains intentional. DNS keeps its separate strict/direct failure policy: disabling a connection must not create a direct DNS path in strict mode.

Raw sing-box profiles keep their `detour` and selector references to the configured connection ID. When that connection is disabled, its runtime relay uses the same enabled fallback chain, or blocks if none is available; the saved raw profile is not rewritten.

![Connection profiles and routing targets](../assets/screenshots/en-connections.png)

![Connection creation wizard](../assets/screenshots/en-wizard.png)

### AmneziaWG profiles (experimental lx build)

Import a single-peer AmneziaWG `.conf` file or paste its contents in the connection wizard. AWG fields select **AmneziaWG** automatically; you can also select the AmneziaWG protocol explicitly. The original profile stays in the shared draft and can be edited before **Apply**. Keep it private: it contains the tunnel's private key and may contain a preshared key.

This build embeds [sing-box-lx 1.14.4-lx.35](https://github.com/Leadaxe/sing-box-lx/releases/tag/v1.14.4-lx.35). It supports AWG 2/3 client parameters and application TCP/UDP through a userspace WireGuard endpoint; the outer tunnel uses UDP. No kernel AWG module or additional daemon is required. Unsupported fields, executable hooks and multiple peers are rejected instead of being silently discarded.

For a standalone Amnezia `vpn://` client export, choose **AmneziaWG → Paste .conf / vpn://**, paste the complete link, enter a name and ID, and validate. You can also upload a text or `.vpn` file containing the link. Decoding happens locally in KeenProxy's backend, without contacting Amnezia or registering a device. If the export contains several AWG profiles, select one explicitly and validate again before saving it to the draft. Only the selected AWG client configuration is retained; SSH credentials, source-envelope metadata, DNS policy and other protocols are not imported. The static browser-only demo cannot decode these exports.

Compressed and uncompressed standalone exports with supported format versions (missing, 0 or 1) are accepted. The encoded URI is limited to 2 MiB and decoded JSON to 1 MiB. An export may contain at most 32 AWG candidates, with at most 1 MiB of native profile text in total; an over-limit export is rejected as a whole, without partial import. Damaged exports, unsupported protocol options, service/subscription keys and administrator-only exports without client keys are rejected. A `vpn://` link is not necessarily a ready-to-use tunnel: obtain a **client connection export**, not a subscription activation key.

To bound router memory use, junk bursts are limited to 256 packets and 1 MiB of worst-case payload per handshake. The same budget applies to native AWG profiles and core-decoded raw WireGuard endpoints.

The profile's `DNS` setting does not replace KeenProxy DNS settings. Existing routing rules and failover still select the connection; `AllowedIPs` does not install system routes. Application UDP requires **TPROXY** interception. The existing participant **UDP/443 rejection remains enabled**, so importing AWG does not enable client QUIC traffic. Amnezia subscription activation, server provisioning and service API integration are not supported.

For YAML configuration, store the profile as a block scalar:

```yaml
connections:
  - id: awg
    name: AmneziaWG
    type: amneziawg
    amneziawg: |
      [Interface]
      PrivateKey = <client-private-key-base64>
      Address = 10.77.0.2/32
      Jc = 3
      Jmin = 40
      Jmax = 80
      S1 = 20
      S2 = 30
      H1 = 1001
      H2 = 1002
      H3 = 1003
      H4 = 1004
      [Peer]
      PublicKey = <server-public-key-base64>
      Endpoint = vpn.example.com:51820
      AllowedIPs = 0.0.0.0/0
```

Replace the placeholders and obfuscation values with those exported by your server. Before rolling back to an official-sing-box build, remove or replace AmneziaWG connections in the draft and Apply: the older engine cannot use this profile type.


## 3. Add a routing group

Open **Rules → Whitelist**. Create a group, name it, select its target connection (or **Direct**/**Block**), and add domains or addresses. For example, direct `work.example.com` to the Netherlands profile. Review imported entries before confirming; country selectors express broader policies.

To move several domain or country groups together, select their checkboxes, choose a target in **Change route**, and review the preview. Groups hidden by a filter can still be selected. Choose **Save to draft**, then **Apply** when ready.

Expand an entry to see its current DNS observations and expiration. A resolved address alone does not prove that application traffic followed the intended tunnel.

Use the on/off switches to pause an entire group or an individual domain/IP rule without removing its value. Country/category groups also have group and per-selector switches. Disabled items remain visible; the active/total counts distinguish saved rules from effective rules. Turning a group off preserves its children's individual states, so turning it on again does not re-enable rules you had paused separately.

An off group or rule is skipped, not blocked: the remaining rules and device policy determine the route. In particular, disabling a block rule stops that rule from blocking. Off domain rules do not contribute active DNS rule sets or initiate background resolution. A country/category group with no active selectors is inactive even in **All except** mode; it never becomes a match-all rule. Review the shared draft and **Apply** to change live behavior.

In YAML, connection and group switches use `disabled: true`. Per-rule states are retained in `disabled_entries`, `disabled_countries`, and `disabled_categories`; the original entries/selectors remain present. Missing fields preserve the previous enabled behavior. Older releases reject unknown activation fields: prepare and validate a compatible configuration before downgrading. Removing the fields re-enables the corresponding items, so review the resulting routes first.

![Domain groups, targets, and address observations](../assets/screenshots/en-rules.png)

See [Country rules](routing.md#country-rules) for an illustrated setup, country exclusions, and rule precedence.

## 4. Try a preset

Open **Rules → Presets**, select a target, then preview a collection. Inspect the added/removed entries and accept it into the draft. Presets can be enabled, disabled, or removed. The static demo includes one original example collection; it does not redistribute the full community catalog.

The catalog shows domain lists without resolving them. KeenProxy resolves IPs for enabled presets after **Apply**. Enable **Update with new app versions** to adopt changes to the bundled preset after upgrading KeenProxy. To block ads or other domains through DNS, see [DNS filters](routing.md#dns-filters).

Updating a preset preserves per-entry off states separately from deletions, including entries that disappear from one preset revision and return later. Disabling a rule does not remove it from the preset or discard your saved value.

## 5. Choose devices and networks

Open **Connections → Clients**. Network defaults apply to matching subnets; per-device entries let you select a policy for individual clients. **Split** uses selective rules, **Full** selects a default connection, and **Off** bypasses KeenProxy interception for that policy. Review both the device and network settings before Apply. When available, the device row also shows a discovered hostname and its DHCP/DNS source. A manually assigned name takes priority; searching matches either name. Discovery refreshes in the background and does not write names to configuration.

![Networks and individual client policies](../assets/screenshots/en-clients.png)

## 6. Review and Apply

The change bar appears whenever the draft differs from the saved configuration. Review changes across screens, then choose **Apply** once. Wait for success. If validation/application fails, read the error and correct the draft. **Discard** restores the last saved snapshot.

![A pending change with shared Apply and Discard controls](../assets/screenshots/en-apply.png)

## 7. Verify the result

Open **Diagnostics** to see core uptime, applied configuration, interception, DNS settings, GeoIP, and the firewall restoration counter. Select an applied connection and choose **Run checks** to test HTTP, HTTPS with certificate verification, and a 64 KiB transfer separately. A new or edited profile must be applied first. The results leave the active failover selection unchanged. The DNS row describes the configured path. Use [a test from the affected device](network-flow.md#how-to-trace-one-request) to verify the actual path. The browser demo labels its check results as simulated and hides the ZIP download button.

![Separate HTTP, HTTPS, and transfer diagnostics](../assets/screenshots/en-diagnostics.png)

### Export journals and diagnostics { #export-journals }

On the router, open **Diagnostics → Diagnostics archive → Download ZIP**. See [what each download contains and what to review before sharing](troubleshooting.md#download-the-diagnostic-zip).

Watchdog recovery events include the failed firewall check and the verification result. The ZIP retains safe structured evidence. See [watchdog diagnostics](troubleshooting.md#why-does-the-watchdog-restore-interception-rules).

### Inspect one routing decision

Open **Logs** and switch between **Routing**, **Audit**, and **System**. In **Routing**, **Group repeats** combines matching loaded records in 30-second windows. Expand a group to see its members or clear the checkbox for individual entries. Search and filters narrow the view. A routing record explains which outbound was selected. Check the application separately to confirm that the connection and transfer succeeded. New routing records in the browser demo are generated locally by the simulation.

![Routing journal with synthetic records](../assets/screenshots/en-journal.png)

## 8. Find settings and manage backups

Open **Settings** with the gear icon. On narrow screens, choose a section from the dropdown. **DNS** opens by default. Use **YAML configuration** to manage backups. Use **Network and interception** for REDIRECT/TPROXY and interfaces, **Panel access** for the listener, token path, and trusted networks, and **Country databases** for GeoIP status. Use **Language and theme** for browser preferences. Routing and access changes use the shared **Apply** action. Changing the panel listener or token file also requires a service restart. **Updates** has its own controls.

Open **Settings → DNS** to choose the primary and secondary DNS servers. Choose a provider and protocol from the list or select **Custom DNS server** and enter an IP address or a DoH, DoT, or UDP URL. The provider list includes Cloudflare, Google Public DNS, Quad9, AdGuard, Yandex DNS, Cisco OpenDNS, CleanBrowsing, and Control D. Each choice shows its filtering policy. KeenProxy tries the primary first and uses the secondary if the primary is unavailable. To change the resolver list, specify two different servers. Existing configurations with fewer servers can still be used and saved when the list is unchanged. **Advanced settings** contains any additional resolvers, bootstrap addresses, and the listening address. The DNS route and tunnel failure policy are configured separately.

Open **Settings → YAML configuration** to import, export, or restore a configuration. Importing or restoring prepares a draft. Review it and Apply. Keep unredacted backups private. The browser demo exports synthetic JSON-compatible data and disables YAML import.

## 9. Install or roll back a release

The panel footer shows the running release and build variant, architecture, and short commit hash. A local build may lack a release tag or commit hash. **Settings → Updates** also shows the available update and the previous version when known. **Diagnostics → Build details** lets you copy the running build identity. The diagnostics ZIP includes the same information in `status.json`.

Open **Settings → Updates**. Apply or discard any routing draft before installing or rolling back. Confirm the version and wait for the service to reconnect. You can save a time for automatic installation or leave it off and install releases when ready. See [the update guide](getting-started.md#update-from-the-panel) for first-time setup and rollback requirements.
