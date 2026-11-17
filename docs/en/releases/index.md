# Release history

User-facing changes, compatibility notes, and upgrade guidance by version. This history starts with the transition from **0.8.0 to 0.9.0**; older release notes remain available in [GitHub Releases](https://github.com/ordo-systems/keen-proxy/releases).

| Version | Status | Notes |
| --- | --- | --- |
| [0.9.0](0.9.0.md) | Released | AWG, embedded TrustTunnel, connection/rule activation, native OpenWrt updates, x86 builds, memory build gates, and secret scanning. |
| [0.8.0](https://github.com/ordo-systems/keen-proxy/releases/tag/v0.8.0) | Released on 2026-11-10 | Upgrade baseline. Added optional NDM callbacks for firewall recovery on compatible Keenetic/Netcraze firmware, alongside the periodic watchdog. |

!!! note "Release assets"
    Use the tagged GitHub release and its complete checksummed assets when installing or updating. A checkout of `main` is not a substitute for a release binary.

Before upgrading, read the target version's compatibility and migration section and the [installation and update guide](../getting-started.md#install-or-update-from-github). For native OpenWrt, follow its [separate installation instructions](../getting-started.md#native-openwrt-installation).
