# Preparing a public release

This guide is for maintainers preparing an initial public repository or a later source/binary release. It does not imply that a release has been published or that every router is supported.

## Version and release pull request

Follow the versioning and Conventional Commit rules in [CONTRIBUTING.md](CONTRIBUTING.md#versioning-and-pull-request-titles). The selected workflow uses [Release Please](https://github.com/googleapis/release-please) to propose releases, with a maintainer reviewing each release PR.

The repository defines [CI](.github/workflows/ci.yml) and [release](.github/workflows/release.yml) workflows. CI runs on pull requests and can be started manually. Pushes to `main` run the same checks before Release Please. They become active after the workflow files are pushed to GitHub and Actions is enabled. CI also scans for leaked credentials: a pull request scans the commits introduced by that branch, and a push to `main` scans every commit reachable from `main`. A clean scan does not replace the history review below.

1. Merge reviewed changes into `main` after the relevant checks pass. With squash merges, preserve the Conventional Commit PR title and any breaking-change details in the resulting commit.
2. Release Please accumulates releasable changes since the previous release and creates or updates a release PR containing the proposed version and changelog. Its pre-1.0 settings match the project's policy.
3. A maintainer checks the bump against the actual compatibility impact, edits release notes as needed, and verifies migration instructions, validation results, and the publication checks below. The automation's proposal does not replace this review.
4. Merge the release PR when the release is ready. After checks pass on `main`, Release Please creates the corresponding Git tag, such as `v1.5.0`, and GitHub Release. A dependent job builds from that exact tag and attaches full/lite Linux binaries for AMD64 (baseline v1), 386 (SSE2), ARMv5, ARM64, MIPSLE, and MIPSBE, `install.sh`, the Entware service script `S99keenproxy`, the native OpenWrt procd script `keenproxy.openwrt`, source archive, license notices, build identity, and `SHA256SUMS`. Check that the asset job succeeds before announcing the release.
5. The default automation produces stable releases. Release candidates require a separately reviewed prerelease configuration and must be marked as prereleases with their known limits. A candidate such as `v1.5.0-rc.1` must pass the relevant release checks before promotion to `v1.5.0`.

Use the Git tag as the release identity and derive build versions from it; any tracked version metadata must be updated consistently by the release PR. Keep published versions immutable: do not move a published tag or replace its binaries with a different build. Publish a new version to correct a released defect.

### GitHub setup and recovery

- Register a private [GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app) owned by the repository's organization. Disable its webhook, grant repository write access to Contents, Issues, and Pull requests, and install it only on this repository.
- Create an environment named `release` and allow deployments only from the `main` branch. Store the App's client ID as the environment variable `RELEASE_APP_CLIENT_ID` and its private key as the environment secret `RELEASE_APP_PRIVATE_KEY`. See [GitHub App authentication in Actions](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/making-authenticated-api-requests-with-a-github-app-in-a-github-actions-workflow).
- The version job issues a short-lived token restricted to this repository. The built-in `GITHUB_TOKEN` keeps read permissions by default. The separate asset job requests Contents write to attach files to the release. The app needs access to the Release Please branch and release tags under the repository rules. Keep required reviews and CI in place for `main`.
- After merging a change to release authentication, verify a fresh Release run on `main`. Rerunning an older run uses its original workflow revision. For asset recovery with a supplied tag, the workflow skips the App token step.
- `version.txt` and `.release-please-manifest.json` start at the development baseline `0.1.0`; this does not assert that `v0.1.0` has been published. The initial commit is the bootstrap boundary. The first releasable changes determine the next version; if the first public release must be `0.1.0`, use a reviewed commit with a `Release-As: 0.1.0` footer before merging its release PR.
- Release PRs update `version.txt`, the manifest, `CHANGELOG.md`, and the private frontend package/lockfile version fields together. `BUILD_INFO.txt` records the tag, source commit, toolchains, and protocol build tags; the running release and build appear in the panel footer, **Diagnostics → Build details**, and the diagnostic ZIP's `status.json`.
- `web/src/demo/release.json` records the planned demo preview separately from the last published installer/package versions. Update it when planning the next feature release; the release PR synchronizes it through the same JSON extra-file updater. Both the static demo and `make ui-demo` read this one source, so previewing an unpublished version never redirects the bootstrap to missing assets.
- The main-branch `tools/bootstrap.sh` reads `version.txt` unless the user supplies `--version`. It needs the selected release's checksum file, binary, and platform-specific installer assets before touching a running service. Entware requires `install.sh` and `S99keenproxy`; native OpenWrt requires `keenproxy.openwrt`. Missing native assets must not prevent Entware upgrades to existing releases. Validate these assets on the published release before advertising the installation command.
- If asset publication fails after release creation, manually run the Release workflow from `main` with its existing tag in the `tag` input. Packaging includes `keenproxy.openwrt` only when that controller exists in the checked-out tag, including its checksum and upload entry; retries of older Entware-only tags must not require it. Existing assets must be byte-identical before missing ones are uploaded. A different rebuild fails rather than replacing files; investigate toolchain/dependency differences and publish a new version when needed. Running without a tag retries Release Please.
- Historical recovery is a separate, explicit contract only for a tag whose commit is an ancestor of, or equal to, the fixed pre-AWG boundary `9d398fb3754036cbe35df1cf07098164ff62a9d5` (including `v0.8.0`). Current workflow CI remains a prerequisite. The tagged `version.txt` must match the requested tag before toolchain setup or expensive work. The workflow leaves tagged source unchanged and uses its original Makefile and protocol flags for Go tests, vet, network integration, frontend tests, and full/lite router cross-builds with the requested release identity. A visible notice and `.agents-work/release-legacy/<run>-<attempt>/` manifest, command log, and exit code distinguish this evidence from memory reports; the always-run evidence uploader retains it even on failure. Pre-AWG source cannot execute AWG tests: this recovery is not AWG stress or memory-comparison certification. Every commit outside that ancestry boundary must pass both memory gates; a missing target fails and never selects historical recovery. Existing-asset byte checks and publication order are unchanged.
- Configure branch protection or a ruleset separately so merge is gated by **Tests and builds**, **Network integration**, **Memory regression**, **AWG stress (320 MiB)**, and **Router builds**. A read-only ruleset inspection found that `main` currently requires only the first two. The former combined check **Memory regression and builds** was not enforced. Preserve those two and add the three new names, each through the GitHub Actions integration (`15368`). Workflow files alone do not enforce merge requirements, and this change does not modify repository rules. Until that administrative update, GitHub will not block merges on the three new names. Release publication is gated by the checks workflow, which waits for every CI job, and by both memory gates in the asset job before the public router builds.

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

The public local targets `make build`, `make build-router`, and `make build-router-lite` require both the [memory regression gate](docs/en/development.md#memory-regression-gate) and the continuous AWG stress gate, including under parallel make. `make build-router-ci` and `make build-router-lite-ci` compile the same router artifacts and do not certify memory. CI's **Router builds** job uses only those targets and does not pass `make -o`. The release asset job keeps the version and tag checks before expensive work and publication. For tagged source outside historical recovery it runs `make memory-stress` and `make memory-regression` as separate steps, then `make -o memory-stress -o memory-regression build-router build-router-lite` with the existing release identity arguments. Both `-o` flags are permitted only after the corresponding step has succeeded in that same job, so the public targets do not repeat the gates. Public targets are required because older AWG tags lack the CI-only names; a missing gate target remains fatal and never selects historical recovery. Those flags are not a local bypass, a cache, or an environment bypass. Preserve the report and raw evidence for the selected source. A failed comparison against the fixed accepted checkpoint, or a failed stress run, blocks binary production; do not bypass either gate, retry away the failure, or raise a threshold without a separately reviewed justification. The AWG sample and stress run are candidate-only checks, not inputs to the common WireGuard comparison. The historical asset-recovery contract above retains its separate pre-AWG ancestry boundary and original verification. Release checks wait for every CI job, including **Memory regression**, **AWG stress (320 MiB)**, and **Router builds**, before version and asset publication.

Build from the reviewed source with dependencies locked, record commit/build tags/toolchains, and generate checksums for the exact published files. Exercise the installer, authentication, configuration backup/recovery, and expected startup mechanism on a disposable or recoverable target.

## Publish only after review

Describe supported behavior, known limits, tested hardware, upgrade/recovery steps, and any incompatible changes. Avoid transferring local operational reports into release notes. Publish a private security-reporting channel before soliciting vulnerability reports where possible.

Creating these files or running local checks is preparation only. Publishing a repository, pushing a branch, changing its visibility, or deploying to a router requires a separate maintainer decision.
