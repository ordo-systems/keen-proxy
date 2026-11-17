# Changelog

## Unreleased

- Raise the memory comparison's absolute allowance from 8 to 12 MiB after retained identical-binary ARM64 and AMD64 false alarms. Keep the 10% relative allowance and AWG stress limits; this reduces detection sensitivity, not application memory use.
- Add full and lite Linux release binaries for x86-64 (AMD64 v1) and 32-bit x86 with SSE2, preserving the pinned compiler and embedded protocol features.
- Support native OpenWrt installation and managed updates through procd on all six release architectures; retain Entware installation and expand its architecture selection. Preserve configuration, checksums, staged validation, and failed-start rollback. Native updates require the new checksummed `keenproxy.openwrt` release asset.
- Raise the documented minimum to 256 MiB of total router RAM for OpenWrt and Keenetic/Netcraze, including lite builds; retain memory headroom warnings and distinguish this requirement from the soft Go memory recommendation.
- Experimental AmneziaWG 2/3 single-peer `.conf` import and editing through the shared draft/Apply workflow, using pinned sing-box-lx 1.14.4-lx.35 and matching dependency forks.
- Keep existing DNS ownership and participant UDP/443 rejection; no Amnezia subscription integration.
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
