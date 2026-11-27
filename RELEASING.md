# Preparing a public release

This guide is for maintainers preparing an initial public repository or a later source/binary release. It does not imply that a release has been published or that every router is supported.

## Version and release pull request

Follow the versioning and Conventional Commit rules in [CONTRIBUTING.md](CONTRIBUTING.md#versioning-and-pull-request-titles). The selected workflow uses [Release Please](https://github.com/googleapis/release-please) to propose releases, with a maintainer reviewing each release PR.

The repository defines [CI](.github/workflows/ci.yml) and [release](.github/workflows/release.yml) workflows. CI runs on pull requests and can be started manually. Pushes to `main` run the release workflow, which also runs CI. CI scans PR commits or the history reachable from the checked `main` commit for leaked credentials. A clean scan does not replace the history review below.

1. Merge reviewed changes into `main` after the relevant checks pass. With squash merges, preserve the Conventional Commit PR title and any breaking-change details in the resulting commit.
2. Release Please accumulates releasable changes since the previous release and creates or updates a release PR containing the proposed version and changelog. Its pre-1.0 settings match the project's policy.
3. A maintainer checks the bump against the actual compatibility impact, edits release notes as needed, and verifies migration instructions, validation results, and the publication checks below. The automation's proposal does not replace this review.
4. Merge the release PR when ready. Release Please creates a Git tag and a draft GitHub Release. One job builds full/lite binaries for AMD64 (baseline v1), 386 (SSE2), ARMv5, ARM64, MIPSLE, and MIPSBE, and packages them with `install.sh`, service scripts, source, notices, build identity, and checksums. CI verifies the same commit in parallel. Only after both jobs succeed does publication upload the retained payload to the draft, verify the complete remote asset set and its bytes, and make the release public.
5. The default automation produces stable releases. Release candidates require a separately reviewed prerelease configuration and must be marked as prereleases with their known limits. A candidate such as `v1.5.0-rc.1` must pass the relevant release checks before promotion to `v1.5.0`.

Use the Git tag as the release identity and derive build versions from it; any tracked version metadata must be updated consistently by the release PR. Keep published versions immutable: do not move a published tag or replace its binaries with a different build. Publish a new version to correct a released defect.

### GitHub setup and recovery

- Register a private [GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app) owned by the repository's organization. Disable its webhook, grant repository write access to Contents, Issues, and Pull requests, and install it only on this repository.
- Create an environment named `release` and allow deployments only from the `main` branch. Store the App's client ID as the environment variable `RELEASE_APP_CLIENT_ID` and its private key as the environment secret `RELEASE_APP_PRIVATE_KEY`. See [GitHub App authentication in Actions](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/making-authenticated-api-requests-with-a-github-app-in-a-github-actions-workflow).
- The version job uses the App to open release PRs, create tags, and create drafts. It also needs Contents write on its `GITHUB_TOKEN` to see drafts on retries. Build and CI jobs use read-only tokens. Upload and promotion run in a separate job. Keep required reviews and CI in place for `main`.
- After merging a change to release authentication, verify a fresh Release run on `main`. Rerunning an older run uses its original workflow revision. For asset recovery with a supplied tag, the workflow skips the App token step.
- `version.txt` and `.release-please-manifest.json` start at the development baseline `0.1.0`; this does not assert that `v0.1.0` has been published. The initial commit is the bootstrap boundary. The first releasable changes determine the next version; if the first public release must be `0.1.0`, use a reviewed commit with a `Release-As: 0.1.0` footer before merging its release PR.
- Release PRs update `version.txt`, the manifest, `CHANGELOG.md`, and the private frontend package/lockfile version fields together. `BUILD_INFO.txt` records the tag, source commit, toolchains, and protocol build tags; the running release and build appear in the panel footer, **Diagnostics → Build details**, and the diagnostic ZIP's `status.json`.
- `web/src/demo/release.json` records the planned demo preview separately from public release availability. Release Please synchronizes it through its JSON extra-file updater. Both the static demo and `make ui-demo` read this one source.
- Without `--version`, `tools/bootstrap.sh` follows GitHub's latest published stable release, not `main/version.txt`. It still requires the selected release's checksums, binary, and platform assets before touching an installed service.
- Starting with `v0.10.2`, the complete payload includes `bootstrap.sh` from the tagged source and its `SHA256SUMS` entry. It is an optional fallback for newer clients and is deliberately excluded when repairing older releases.
- If publication fails, rerun failed jobs while the workflow artifact is retained to reuse the same bytes without rebuilding. For a fresh run, dispatch Release on `main` with the exact draft tag. A public tag in `tag` selects repair only: it never promotes the release to latest or overwrites published files. For both paths, existing completed assets must byte-match before missing ones are uploaded. If a retained artifact has expired, a rebuild can fail this check because of historical packaging or toolchain differences; do not overwrite published assets to recover. Older tags use their own architecture list and service controllers.
- All draft publications, including explicit resumes of older drafts, require `tools/keenproxy.openwrt` in the tagged source and `keenproxy.openwrt` in the verified payload. If an old draft lacks the controller, prepare a new reviewed version instead of publishing that draft. Repair of an already published historical release preserves its original layout and may omit the controller if it was absent from the tagged source. Both paths recheck the release identity after verifying the remote assets.
- Historical recovery is a separate, explicit contract only for a tag whose commit is an ancestor of, or equal to, the fixed pre-AWG boundary `9d398fb3754036cbe35df1cf07098164ff62a9d5` (including `v0.8.0`). Current workflow CI remains a prerequisite. The tagged `version.txt` must match the requested tag before toolchain setup or expensive work. The workflow leaves tagged source unchanged and uses its original Makefile and protocol flags for Go tests, vet, network integration, frontend tests, and full/lite router cross-builds with the requested release identity. A visible notice and `.agents-work/release-legacy/<run>-<attempt>/` manifest, command log, and exit code distinguish this evidence from memory reports; the always-run evidence uploader retains it even on failure. Pre-AWG source cannot execute AWG tests: this recovery is not AWG stress or memory-comparison certification. Every commit outside that ancestry boundary must pass both memory gates; a missing target fails and never selects historical recovery. Existing-asset byte checks and publication order are unchanged.
- Keep **Tests and builds**, **Network integration**, **Memory regression**, **AWG stress (320 MiB)**, and **Router builds** as merge requirements through the GitHub Actions integration (`15368`). Repository rules are independent of these workflow files. The release uses one router build for the payload instead of the redundant router build in the reusable CI workflow.

## Review the material being published

1. Choose a specific, reviewed commit. Inspect the full tracked tree and every intended release artifact.
2. Check for credentials, production configuration, private device identifiers, personal paths, logs, source maps, and embedded data. The CI secret scan is one pattern scan; it does not replace manual review.
3. Review Git history as well as the current checkout. Ignoring or deleting a file does not remove old versions. If a private development history contains local reports or memories, prepare a separately reviewed public history before publishing; do not push that history blindly or rewrite an existing shared history without coordination.
4. Confirm that public guides use synthetic examples and link only to files included in the public tree. Keep internal work notes and agent memories excluded.

## Check licenses and provenance

- Include the canonical `LICENSE` and applicable third-party notices with source distributions.
- Review the exact pinned versions of Go modules, frontend packages, and optional external executables. Preserve required notices in binary distributions as well.
- Meet GPLv3's corresponding-source requirements when conveying binaries; the corresponding source must match the distributed build and include the necessary build material.
- Build from the versioned modules recorded in `go.mod` and `go.sum`, never local-path replacements or `@latest`. Source archives retain these manifests and the build scripts; rebuilding downloads the pinned modules. `BUILD_INFO.txt` records the resolved module versions and replacements.
- Confirm permission/license and attribution for community presets and fetched data. A source URL or a community origin does not alone establish redistribution terms.
- Retain DB-IP attribution where its data is displayed. Alternative country databases and blocklists need their own review.
- Preserve upstream naming/association notices. Do not imply endorsement by Keenetic, Netcraze, SagerNet, or another upstream project.

## Validate the selected build

```sh
CGO_ENABLED=0 make test
CGO_ENABLED=0 make vet
cd web && npm ci && npm test && npm run build
```

Run `make integration` for the full network test suite. Test the relevant x86, ARM32, ARM64, or MIPS build and the relevant protocol registry on the intended hardware; a host build alone is insufficient. Auxiliary tools have separate Go modules. Document checks that could not be run.

The public local targets `make build`, `make build-router`, and `make build-router-lite` require both the [memory regression gate](docs/en/development.md#memory-regression-gate) and continuous AWG stress, including under parallel make. `make build-router-ci` and `make build-router-lite-ci` compile the same router artifacts without certifying memory. For new releases the payload build uses those CI targets while **Memory regression** and **AWG stress (320 MiB)** run once each on the exact same commit. The publish job waits for all checks. Repairing a previously published AWG tag preserves the same-job gates and public build commands for Makefiles without CI targets; only that repair path acknowledges successful gates using `-o`. A missing gate never selects pre-AWG recovery, and a failed or missing measurement blocks publication. Preserve the raw evidence; do not retry away failures or raise thresholds without separate review.

Build from the reviewed source with dependencies locked, record commit/build tags/toolchains, and generate checksums for the exact published files. Exercise the installer, authentication, configuration backup/recovery, and expected startup mechanism on a disposable or recoverable target.

## Publish only after review

Describe supported behavior, known limits, tested hardware, upgrade/recovery steps, and any incompatible changes. Avoid transferring local operational reports into release notes. Publish a private security-reporting channel before soliciting vulnerability reports where possible.

Creating these files or running local checks is preparation only. Publishing a repository, pushing a branch, changing its visibility, or deploying to a router requires a separate maintainer decision.
