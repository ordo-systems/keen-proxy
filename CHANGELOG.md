# Changelog

## Unreleased

- Allow LAN DNS forwarders to bypass UDP/TCP port 53 interception by source IPv4 address without changing interception for other clients or ports.
- Avoid restarting the DNS listener when applying changes that only switch between omitted and empty group lists or group entries.
- Import and export group and local preset resources in TXT, CSV, KeenProxy JSON, sing-box source JSON, and SRS, with preview and shared draft/Apply.
- Raise the memory comparison's absolute allowance from 8 to 12 MiB after retained identical-binary ARM64 and AMD64 false alarms. Keep the 10% relative allowance and AWG stress limits; this reduces detection sensitivity, not application memory use.
- Add full and lite Linux release binaries for x86-64 (AMD64 v1) and 32-bit x86 with SSE2, preserving the pinned compiler and embedded protocol features.
- Support native OpenWrt installation and managed updates through procd on all six release architectures; retain Entware installation and expand its architecture selection. Preserve configuration, checksums, staged validation, and failed-start rollback. Native updates require the new checksummed `keenproxy.openwrt` release asset.
- Raise the documented minimum to 256 MiB of total router RAM for OpenWrt and Keenetic/Netcraze, including lite builds; retain memory headroom warnings and distinguish this requirement from the soft Go memory recommendation.
- Experimental AmneziaWG 2/3 single-peer `.conf` import and editing through the shared draft/Apply workflow, using pinned sing-box-lx 1.14.4-lx.35 and matching dependency forks.
- Use packet-sized buffers in the WireGuard/AmneziaWG receive queue on routers to reduce memory use under load. Large UDP/GRO read slots remain separate; TX is unchanged.
- Support legacy `iptables-restore` with glibc or musl by retrying a known unsupported `-w` diagnostic without the flag while preserving unrelated firewall rules.
- Keep existing DNS ownership and participant UDP/443 rejection; no Amnezia subscription integration.
- Allow a single DNS upstream in Settings and imported YAML; the secondary resolver is optional.
- Enable XHTTP, preserve VLESS encryption and expose REALITY key-share/TLS fragmentation options when importing connection links.
- Reject XHTTP/Vision links without VLESS encryption while preserving compatible encrypted profiles.
- Replace the external TrustTunnel client with the embedded lx outbound, migrate legacy connection settings on load, and remove external-client installation and process status.
- Leave legacy `bin/trusttunnel_client` and `share/keenproxy/trusttunnel/` files under the installation prefix after upgrade/uninstall; remove them manually only after confirming no other service or rollback needs them. Native TrustTunnel selects one endpoint from multi-address links without automatic address fallback.
- API compatibility: remove the `trusttunnel` external-process field from status responses; external consumers must no longer require it.
- Keep lite builds without QUIC/HTTP/3; both registries support XHTTP and native TrustTunnel over TCP/TLS.
- Keep sing-box-lx v1.14.4-lx.35 and its four dependency forks pinned as versioned Go modules; use Go 1.27.3 consistently in local builds and CI.
- Add a System settings tab with an optional process-wide Go memory recommendation through the shared draft/Apply workflow, including CPU/throughput warnings and restart-free application. Default to 768 MiB when no startup Go limit is set; preserve explicit configuration and GOMEMLIMIT precedence.
- Import standalone Amnezia `vpn://` AWG exports locally, with bounded decompression, explicit multi-profile selection and translated errors for service/admin/unsupported exports. No service API calls or device registrations.
- Keep AWG profiles out of redacted support exports and reject excessive junk-packet bursts before starting the engine.
- Mask native AmneziaWG header-protection keys in both Base64 and normalized hexadecimal journal output, including profiles with whitespace around field names.
- Align static and local Go demo build identities with the planned release preview without changing the last published installer version.
- Print the panel URL after installation and updates; add read-only `--url` and `--key` commands for configured access details without starting the service or rotating the token.
- Bound standalone export candidates and their cumulative profile size; preserve edits during asynchronous profile validation and accept validated ordinary WireGuard DNS metadata without importing DNS policy.
- Pause connections, groups, and individual domain/IP/country/category rules without deleting their settings, through the shared draft/Apply workflow; disabled targets use configured fallbacks or block rather than silently route direct.
- Separate connection parameter and diagnostic actions, and keep activation controls available in desktop/mobile layouts and both demos.
- Require a reproducible full-daemon memory regression gate for local application builds, CI, and releases, comparing identical WireGuard workloads against the accepted main checkpoint `e6a1a1d`, application-equivalent to the accepted `37d196c` build, and recording AWG separately. This accepts the current memory footprint as a reference, not as a memory fix.
- Require a separate continuous AWG stress gate before application builds, CI, and releases. The measured daemon uses a 320 MiB Go limit; RSS or lifetime `VmHWM` at or above 384 MiB, stalled streams, or low verified load fail the gate. It never builds the comparison reference.
- Export private memory-gate evidence with host-readable ownership, measure throughput over matching counter timestamps, and replace stale reports when result directories cannot be read.
- Preserve explicit pre-AWG release-asset recovery using the tagged source's verification contract without weakening memory gates for newer source.
- Wait for historical release logs to finish flushing, propagate logger failures without replacing build failures, and document local memory-gate runtime and conflicting host measurements.
- Keep memory-gate fixtures aligned with the current full protocol tags and pinned Go compiler after upstream build changes.
- Report memory comparison, continuous AWG stress, and router compilation as independent CI checks: **Memory regression**, **AWG stress (320 MiB)**, and **Router builds**. CI compiles routers with `build-router-ci` and `build-router-lite-ci`, does not use `make -o`, and does not treat that compilation as a memory certification.
- Keep public local `build`, `build-router`, and `build-router-lite` gated by both memory checks, including under parallel make. Tagged release assets run stress and comparison as separate steps, then `make -o memory-stress -o memory-regression` with the public router targets only after those steps succeed in the same job. The accepted `e6a1a1d` reference, thresholds, sample counts, 320 MiB soft budget, 384 MiB ceiling, and pre-AWG recovery boundary are unchanged.
- Document the separate repository-rules change required to preserve **Tests and builds** and **Network integration** and to add the three new check names. The former combined check **Memory regression and builds** was not a required status, and this change does not update branch protection.

## [0.9.1](https://github.com/ordo-systems/keen-proxy/compare/v0.9.0...v0.9.1) (2026-11-18)


### Bug Fixes

* **dns:** allow a single upstream in Settings and YAML imports ([#42](https://github.com/ordo-systems/keen-proxy/issues/42)) ([e003c02](https://github.com/ordo-systems/keen-proxy/commit/e003c022ee8c6d680a689187abf6321d93641002))
* **dns:** allow LAN resolvers to bypass DNS interception ([#43](https://github.com/ordo-systems/keen-proxy/issues/43)) ([43ae56e](https://github.com/ordo-systems/keen-proxy/commit/43ae56e3338d6a26bee35fc33d4e8ec55cddcadd))
* **netfilter:** support legacy iptables-restore ([#44](https://github.com/ordo-systems/keen-proxy/issues/44)) ([b045b7c](https://github.com/ordo-systems/keen-proxy/commit/b045b7c4505546bfb80e45685ef4b58016e613f5))
* **rules:** import and export resource lists ([#45](https://github.com/ordo-systems/keen-proxy/issues/45)) ([24a100b](https://github.com/ordo-systems/keen-proxy/commit/24a100b49f93d7747d3eb86dd81177d9eeb06b04))
* **wireguard:** pin packet-sized receive buffers ([e63e7cc](https://github.com/ordo-systems/keen-proxy/commit/e63e7cccca0bd160a9d659f2b8b3821581e7d633))
* **wireguard:** reduce queued receive buffer memory ([#40](https://github.com/ordo-systems/keen-proxy/issues/40)) ([e63e7cc](https://github.com/ordo-systems/keen-proxy/commit/e63e7cccca0bd160a9d659f2b8b3821581e7d633))

## [0.9.0](https://github.com/ordo-systems/keen-proxy/compare/v0.8.0...v0.9.0) (2026-11-17)


### Features

* **activation:** disable connections without deleting profiles, credentials or routing references through shared Apply/Discard ([2d14086](https://github.com/ordo-systems/keen-proxy/commit/2d14086848310effe38b7388cb72eb06517fff5e))
* **amneziawg:** import and edit complete native single-peer AWG 2/3 profiles through the shared draft/Apply workflow ([c5c7a86](https://github.com/ordo-systems/keen-proxy/commit/c5c7a868b95cba5ad354b6b35959382f77b380bc))
* **amneziawg:** reject junk bursts exceeding 256 packets or 1 MiB of worst-case payload before engine activation ([c5c7a86](https://github.com/ordo-systems/keen-proxy/commit/c5c7a868b95cba5ad354b6b35959382f77b380bc))
* **api:** remove the obsolete trusttunnel external-process status field; external status consumers must adapt ([a58c9e7](https://github.com/ordo-systems/keen-proxy/commit/a58c9e7b91fe41b5e1fa8947fcef1e414c3666e5))
* **build:** add full and lite Linux x86-64 and x86/SSE2 release binaries ([e6a1a1d](https://github.com/ordo-systems/keen-proxy/commit/e6a1a1df2730418cf9edc2a71df4cec3e99be255))
* **build:** require memory regression and 320 MiB AWG stress gates ([ad88975](https://github.com/ordo-systems/keen-proxy/commit/ad889758c933daac06aa085e6dba1af35e5ac8ee))
* **demo:** align static and local Go demo identities with the planned release without changing published installer metadata ([c5c7a86](https://github.com/ordo-systems/keen-proxy/commit/c5c7a868b95cba5ad354b6b35959382f77b380bc))
* **engine:** keep lite XHTTP and native TrustTunnel on TCP/TLS and reject HTTP/3-only profiles; QUIC requires the full build ([a58c9e7](https://github.com/ordo-systems/keen-proxy/commit/a58c9e7b91fe41b5e1fa8947fcef1e414c3666e5))
* **engine:** pin sing-box-lx v1.14.4-lx.35 and matching Go-module forks for native AWG in full and lite builds ([c5c7a86](https://github.com/ordo-systems/keen-proxy/commit/c5c7a868b95cba5ad354b6b35959382f77b380bc))
* **failover:** route disabled connection references through enabled reserves or block; only use Direct when explicitly configured ([2d14086](https://github.com/ordo-systems/keen-proxy/commit/2d14086848310effe38b7388cb72eb06517fff5e))
* **import:** bound decompression and profile sizes, reject executable hooks and unsupported exports, and preserve edits during asynchronous validation ([c5c7a86](https://github.com/ordo-systems/keen-proxy/commit/c5c7a868b95cba5ad354b6b35959382f77b380bc))
* **import:** decode standalone Amnezia vpn:// exports offline without subscription activation, service calls or device registration ([c5c7a86](https://github.com/ordo-systems/keen-proxy/commit/c5c7a868b95cba5ad354b6b35959382f77b380bc))
* **import:** require explicit selection for multi-profile exports and persist only the selected client configuration ([c5c7a86](https://github.com/ordo-systems/keen-proxy/commit/c5c7a868b95cba5ad354b6b35959382f77b380bc))
* **installer:** print the panel URL after installation and updates and add read-only --url and --key access commands ([c5c7a86](https://github.com/ordo-systems/keen-proxy/commit/c5c7a868b95cba5ad354b6b35959382f77b380bc))
* **openwrt:** add native installation and managed updates across six architectures with a 256 MiB router RAM minimum ([e6a1a1d](https://github.com/ordo-systems/keen-proxy/commit/e6a1a1df2730418cf9edc2a71df4cec3e99be255))
* **presets:** preserve child activation choices across parent toggles and preset updates ([2d14086](https://github.com/ordo-systems/keen-proxy/commit/2d14086848310effe38b7388cb72eb06517fff5e))
* **routing:** preserve raw detour references and keep all-disabled geo conditions inactive, including Except mode ([2d14086](https://github.com/ordo-systems/keen-proxy/commit/2d14086848310effe38b7388cb72eb06517fff5e))
* **routing:** toggle groups and individual domain, IP, country and category conditions while retaining their configured values ([2d14086](https://github.com/ordo-systems/keen-proxy/commit/2d14086848310effe38b7388cb72eb06517fff5e))
* **security:** keep native AWG credentials out of redacted support exports and mask header-protection keys in journal output ([c5c7a86](https://github.com/ordo-systems/keen-proxy/commit/c5c7a868b95cba5ad354b6b35959382f77b380bc))
* **system:** add a process-wide soft Go memory recommendation in Settings &gt; System with a 768 MiB fallback and CPU/throughput warnings ([a58c9e7](https://github.com/ordo-systems/keen-proxy/commit/a58c9e7b91fe41b5e1fa8947fcef1e414c3666e5))
* **system:** honor configuration and startup GOMEMLIMIT including off, apply memory-only changes without restart and restore limits on failure or shutdown ([a58c9e7](https://github.com/ordo-systems/keen-proxy/commit/a58c9e7b91fe41b5e1fa8947fcef1e414c3666e5))
* **trusttunnel:** replace the external client with an embedded outbound and migrate legacy profiles to canonical tt:// links ([a58c9e7](https://github.com/ordo-systems/keen-proxy/commit/a58c9e7b91fe41b5e1fa8947fcef1e414c3666e5))
* **trusttunnel:** select one exported endpoint without automatic address fallback and retain legacy client files for safe manual cleanup ([a58c9e7](https://github.com/ordo-systems/keen-proxy/commit/a58c9e7b91fe41b5e1fa8947fcef1e414c3666e5))
* **ui:** show saved and pending activation state, active rule counts and selected fallbacks in responsive panels and demos ([2d14086](https://github.com/ordo-systems/keen-proxy/commit/2d14086848310effe38b7388cb72eb06517fff5e))
* **vless:** preserve VLESS encryption and REALITY key-share and TLS-fragmentation link parameters ([a58c9e7](https://github.com/ordo-systems/keen-proxy/commit/a58c9e7b91fe41b5e1fa8947fcef1e414c3666e5))
* **xhttp:** support XHTTP and splithttp links with mode, extra JSON and xmux options in full and lite builds ([a58c9e7](https://github.com/ordo-systems/keen-proxy/commit/a58c9e7b91fe41b5e1fa8947fcef1e414c3666e5))


### Bug Fixes

* **build:** select Go 1.27.3 consistently from go.mod for local, CI and release builds ([a58c9e7](https://github.com/ordo-systems/keen-proxy/commit/a58c9e7b91fe41b5e1fa8947fcef1e414c3666e5))
* **installer:** preserve historical update and rollback compatibility without downloading the obsolete TrustTunnel client ([a58c9e7](https://github.com/ordo-systems/keen-proxy/commit/a58c9e7b91fe41b5e1fa8947fcef1e414c3666e5))
* **links:** reject conflicting or unsupported options and XHTTP/Vision without VLESS encryption while retaining encrypted profiles ([a58c9e7](https://github.com/ordo-systems/keen-proxy/commit/a58c9e7b91fe41b5e1fa8947fcef1e414c3666e5))
* **trusttunnel:** reject unrepresentable authentication, transport and TLS-identity options instead of weakening the imported profile ([a58c9e7](https://github.com/ordo-systems/keen-proxy/commit/a58c9e7b91fe41b5e1fa8947fcef1e414c3666e5))
* **ui:** return an empty hosts array instead of null so Connections remains usable after disabling a profile ([2d14086](https://github.com/ordo-systems/keen-proxy/commit/2d14086848310effe38b7388cb72eb06517fff5e))
* **wireguard:** accept validated DNS metadata in ordinary WireGuard imports without changing KeenProxy DNS policy ([c5c7a86](https://github.com/ordo-systems/keen-proxy/commit/c5c7a868b95cba5ad354b6b35959382f77b380bc))

## [0.8.0](https://github.com/ordo-systems/keen-proxy/compare/v0.7.0...v0.8.0) (2026-11-10)


### Features

* recover firewall rules from optional NDM hooks ([#23](https://github.com/ordo-systems/keen-proxy/issues/23)) ([08a9a43](https://github.com/ordo-systems/keen-proxy/commit/08a9a43f6af89447fc7394f31b18b0618824ee2a))

## [0.7.0](https://github.com/ordo-systems/keen-proxy/compare/v0.6.0...v0.7.0) (2026-11-08)


### Features

* show KeenProxy process resource usage ([#18](https://github.com/ordo-systems/keen-proxy/issues/18)) ([1f9f46f](https://github.com/ordo-systems/keen-proxy/commit/1f9f46fea1c90b1f8a32f182d6f12aafe84f2018))

## [0.6.0](https://github.com/ordo-systems/keen-proxy/compare/v0.5.0...v0.6.0) (2026-11-08)


### Features

* expand router release builds for OpenWrt ([#15](https://github.com/ordo-systems/keen-proxy/issues/15)) ([afcb249](https://github.com/ordo-systems/keen-proxy/commit/afcb24932126ee4a60e862dcce6e53978f740f92))
* organize settings and DNS resolver selection ([#16](https://github.com/ordo-systems/keen-proxy/issues/16)) ([e1ff11a](https://github.com/ordo-systems/keen-proxy/commit/e1ff11ab3eb9c703d58fbf8b9ce29e6c462fd05c))

## [0.5.0](https://github.com/ordo-systems/keen-proxy/compare/v0.4.0...v0.5.0) (2026-11-07)


### Features

* show the running release and build identity ([#13](https://github.com/ordo-systems/keen-proxy/issues/13)) ([236a078](https://github.com/ordo-systems/keen-proxy/commit/236a078106f266026b2d85e01cda31aeac624628))

## [0.4.0](https://github.com/ordo-systems/keen-proxy/compare/v0.3.0...v0.4.0) (2026-11-07)


### Features

* **geoip:** multiple country and category databases with auto-updates ([#6](https://github.com/ordo-systems/keen-proxy/issues/6)) ([868ddaf](https://github.com/ordo-systems/keen-proxy/commit/868ddafb2be21b2e89e44694497d019e998c9f78))


### Bug Fixes

* authenticate Release Please with a scoped GitHub App ([#8](https://github.com/ordo-systems/keen-proxy/issues/8)) ([fd3e50d](https://github.com/ordo-systems/keen-proxy/commit/fd3e50d6799d7964e0434443ce58034fbc8bb547))

## [0.3.0](https://github.com/ordo-systems/keen-proxy/compare/v0.2.0...v0.3.0) (2026-11-07)


### Features

* add release installer and LAN hostname discovery ([#2](https://github.com/ordo-systems/keen-proxy/issues/2)) ([860d756](https://github.com/ordo-systems/keen-proxy/commit/860d756c8eb1094168dff5d7464696124dd241f4))

## [0.2.0](https://github.com/ordo-systems/keen-proxy/compare/v0.1.0...v0.2.0) (2026-11-07)


### Features

* add bilingual documentation and standalone browser demo ([5d0c8e6](https://github.com/ordo-systems/keen-proxy/commit/5d0c8e665903ac1a756a4e5bfd4856c209609975))
