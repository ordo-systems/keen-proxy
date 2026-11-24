# Third-party software and data

KeenProxy's GPL-3.0-only declaration applies to its original code. Dependencies, separately installed executables, and imported data retain their own terms. This file records important distinctions; it is not an exhaustive license-compatibility certification.

## Software dependencies

- **sing-box**: embedded engine from [SagerNet](https://github.com/SagerNet/sing-box), licensed under GPL-3.0-or-later by its upstream copyright holders. The pinned upstream file also contains an additional naming/association notice. Its complete notice is preserved in [LICENSES/sing-box.txt](LICENSES/sing-box.txt); retain it and account for the combined distribution when shipping binaries. This description does not certify all compatibility questions.
- **sing-box-lx and dependency forks**: this experimental build embeds [Leadaxe/sing-box-lx](https://github.com/Leadaxe/sing-box-lx) v1.14.4-lx.35 instead of the official engine. Root `go.mod` pins its corresponding WireGuard/AWG, sing-tun, gVisor and uTLS forks through versioned replacements; `go.sum` records their checksums. No Git submodules or local-path replacements are required. The sing-box notice above remains applicable; each dependency retains its own license. Source archives retain the module manifests for fetching the exact dependencies. The official [amneziawg-go/v3](https://github.com/amnezia-vpn/amneziawg-go) module is used by interoperability tests, not linked into the KeenProxy executable.
- **Other Go modules**: versions are recorded in `go.mod` and `go.sum`, including separate modules under `tools/`. Consult each upstream license and preserve required notices in source/binary distributions.
- **Frontend dependencies**: versions are recorded in `web/package.json` and `web/package-lock.json`. Their upstream licenses and notices still apply to the embedded compiled frontend.
- **TrustTunnel protocol**: provided by the embedded sing-box-lx implementation. KeenProxy no longer downloads or launches the separate TrustTunnelClient executable. Previously installed copies retain their own licenses and are not removed by this installer.

## Country databases

Country databases are downloaded separately on the router, are approximate, and are not relicensed as GPL by this project. The built-in sources and their terms:

- **DB-IP IP to Country Lite** (enabled by default): [download page](https://db-ip.com/db/download/ip-to-country-lite), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Attribution, shown in the web interface while the database is in use: [IP Geolocation by DB-IP](https://db-ip.com/).
- **ip-location-db `user-country`** (disabled by default): [sapics/ip-location-db](https://github.com/sapics/ip-location-db) GitHub release, published under the [PDDL 1.0](https://opendatacommons.org/licenses/pddl/1-0/). Upstream notes that it aggregates inputs, some of which follow RIR terms.
- **Loyalsoldier GeoIP `Country-without-asn.mmdb`** (disabled by default): [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) latest GitHub release, built from MaxMind GeoLite2 data. MaxMind's GeoLite2 terms apply; the interface shows "Includes GeoLite2 data created by MaxMind" while it is in use. Review those terms before enabling it.

- **runetfreedom category databases** (disabled by default): `Country-ru-only.mmdb` (labels such as `RU-BLOCKED` and `RE-FILTER`) and `Country-asn.mmdb` (service networks such as `TELEGRAM`) from the latest [runetfreedom/russia-blocked-geoip](https://github.com/runetfreedom/russia-blocked-geoip) GitHub release. The repository is GPL-3.0. Its data comes from antifilter.download, community.antifilter.download and re:filter, whose own terms apply.

Custom databases added by URL or local file have their own terms.

## Fallback root certificates

`golang.org/x/crypto/x509roots/fallback` embeds Mozilla's root certificate set. It is used only when the router provides no system CA bundle. The module is BSD-licensed; the certificate data originates from the Mozilla NSS project.

## Domain presets and filter lists

The unmanaged presets in `internal/catalog/presets.json` are historical data from an exported domain collection. Their provenance and redistribution terms are not established; do not assume that the project license covers them.

<!-- BEGIN PRESET SOURCES (generated) -->
## Generated preset sources

Every managed preset is generated from the pinned sources below. License texts are copied to `LICENSES/presets/`.

| Source | URL | Revision | License |
|---|---|---|---|
| `chebur` | https://codeload.github.com/chebur-net/russia-mobile-whitelist/tar.gz/8df7ae7b8713a11980f76671dcb7d2a956e883d3 | `8df7ae7b8713a11980f76671dcb7d2a956e883d3` | MIT |
| `hxehex` | https://codeload.github.com/hxehex/russia-mobile-internet-whitelist/tar.gz/fad3653ebd4b212643774a4d10af3eb33838e4ff | `fad3653ebd4b212643774a4d10af3eb33838e4ff` | MIT |
| `local` | project-owned seed | `working tree` | GPL-3.0-only |
| `v2fly` | https://codeload.github.com/v2fly/domain-list-community/tar.gz/98c43cad27fa8f02043858763709fe4a95432ffb | `98c43cad27fa8f02043858763709fe4a95432ffb` | MIT |

| Preset | Sources |
|---|---|
| `ru-banks` | `v2fly` (category-bank-ru); `local` (ru-banks-extra.txt) |
| `ru-finance` | `local` (ru-finance.txt) |
| `ru-sber` | `local` (ru-sber.txt) |
| `ru-state` | `v2fly` (category-gov-ru); `local` (ru-state-extra.txt) |
| `ru-social` | `v2fly` (vk, ok, dzen, mailru-group); `local` (ru-social-extra.txt) |
| `ru-video` | `v2fly` (rutube, okko, wink, kinopoisk, category-entertainment-ru); `local` (ru-video-extra.txt) |
| `ru-essential` | `hxehex` (whitelist.txt); `chebur` (moscow-tele2/domains.txt, spb-tele2/domains.txt); `local` (ru-essential-extra.txt) |
| `miro` | `local` (miro.txt) |

<!-- END PRESET SOURCES (generated) -->

DNS blocklists are fetched from separately configured providers. Each provider's license and attribution requirements apply to its content. The ability to download a list is not a license grant.
