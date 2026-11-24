# Preset catalog generator

Generates `internal/catalog/presets.json` from the pinned sources in `recipe.yaml`. The generated catalog preserves unmanaged presets from the current base file, so the tool can take over collections incrementally.

## Commands

```sh
make presets        # regenerate catalog; newly added domains must resolve
make check-presets  # fail if generated files are stale or a newly added domain does not resolve
```

CI compares against the target branch so the DNS gate sees domains added by the change:

```sh
make check-presets PRESET_BASE=.cache/presets-base.json
```

Run `go run ./tools/presets -help` for flags. `-source-root` uses extracted sources from a local directory instead of the network; `-offline` refuses missing archives.

Generated outputs: `internal/catalog/presets.json`, `tools/presets/sources.lock.json`, `tools/presets/sources.snapshot.json`, `PRESET_SOURCES.md`, the generated section of `THIRD_PARTY_NOTICES.md`, and `LICENSES/presets/`.

## Shrink protection

Each source file has an entry in `sources.snapshot.json`. If the fetched file contains fewer domains than the snapshot, the generator:

- keeps the union of old and new domains;
- prints a warning with old, new, and preserved counts;
- updates the snapshot to the preserved set.

The warning repeats while the source remains smaller. Domains are not removed automatically, including when a source file disappears. Review the snapshot and prune deliberately if a removal is intended; the generator does not provide an implicit destructive path.

## Provenance and licenses

Every source is pinned to a revision and archive SHA-256. The generator verifies the archive and license hashes, copies license texts to `LICENSES/presets/`, writes `sources.lock.json`, and replaces the marked generated section in `THIRD_PARTY_NOTICES.md` with the source and preset mapping. Project-owned seed lists are marked `local` and use the project GPL-3.0-only license. The recipe rejects unsupported licenses, mutable archive URLs, non-project local sources, and `kvaspro.su`.

## Sources

- `v2fly/domain-list-community` (MIT)
- `hxehex/russia-mobile-internet-whitelist` (MIT)
- `chebur-net/russia-mobile-whitelist` (MIT)
- `tools/presets/data/*.txt` (project-owned, GPL-3.0-only)

The generator rejects unknown source kinds; it does not fetch from `kvaspro.su` or other restricted hosts.
