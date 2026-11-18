# Documentation development

## Build locally

Use Python 3.12+ and Node 22.12+:

```sh
make docs-preview
```

This creates `.venv-docs`, builds the documentation in strict mode with the browser demo in `site/`, and serves it on port 8097. Set `DOCS_PORT` to use another port. `make docs` builds without serving. The equivalent manual steps are:

```sh
python3 -m venv .venv-docs
.venv-docs/bin/pip install -r requirements-docs.txt
DOCS_SITE_URL=http://localhost:8097/ .venv-docs/bin/mkdocs build --strict
cd web
npm ci
npm test
npm run build:demo
cd ..
mkdir -p site/demo
cp -R web/dist-demo/. site/demo/
python3 -m http.server 8097 --directory site
```

Open `http://localhost:8097/` for English, `/ru/` for Russian and `/demo/` for the independent demo. The server serves static files only. `npm run build` still builds the normal router UI in `web/dist`; `build:demo` writes to `web/dist-demo`.

## Embedded engine modules

Run `go mod download` after cloning; no Git submodules are required. Root `go.mod` keeps upstream import paths and pins sing-box-lx `v1.14.4-lx.35` plus the corresponding WireGuard/AWG, sing-tun, gVisor and uTLS forks through five versioned `replace` directives. Go does not inherit replacement directives from dependencies; keep all five pins in the root module and review them together when updating the engine.

The WireGuard/AWG replacement pins a commit of [the Ordo Systems fork](https://github.com/ordo-systems/wireguard-go-awg2-lx), not a moving branch. On router builds, its receive queue uses packet-sized buffers while UDP/GRO read slots keep their original capacity. This adds a receive copy without changing transmission. Platforms with a bounded receive pool retain their original receive path.

Makefile and CI select Go **1.27.3** from the root `go.mod` `go` directive, preserving main's language floor. For direct commands, use `GOTOOLCHAIN=go1.27.3 go …` when your PATH selects a different compiler. Do not copy the entire upstream `LX_TAGS`: KeenProxy owns a smaller full/lite feature set and does not enable the tags requiring `-checklinkname=0`.

Release source archives contain the module manifests and build scripts. Rebuilding fetches the exact versions verified by `go.sum`; it does not require Git submodule initialization. Do not replace pins with `@latest`.

## Memory regression gate

The public local targets `make build`, `make build-router`, and `make build-router-lite` require both the comparison gate and the continuous AWG stress gate before producing application binaries, including under parallel make. A public local entry point does not bypass either gate. The CI-only targets `make build-router-ci` and `make build-router-lite-ci` compile the same full and lite router artifacts and do not run or certify either memory gate. Docker (including permission to run privileged containers), Python 3, Git history, and the Go toolchain from `go.mod` are required to run the gates. The comparison gate needs the fixed baseline commit. Run the gates independently with:

```sh
make memory-regression-unit
make memory-regression
make memory-stress
```

CI compiles the router artifacts without either gate:

```sh
make build-router-ci
make build-router-lite-ci
```

Those targets do not certify memory. Do not use them instead of the public local targets when a binary must have passed both gates.

The gate builds the current source and the fixed accepted main checkpoint `e6a1a1df2730418cf9edc2a71df4cec3e99be255`, using the compiler selected by the current Makefile. The reference retains that checkpoint's full-build tags, including AWG, XHTTP and native TrustTunnel; the candidate takes its current full-build tags from `make memory-build-settings`. Both daemons run the same synthetic two-WireGuard configuration and TCP/UDP workload, without a router, production credentials, or external test destinations. Namespace and firewall changes stay inside uniquely owned disposable Linux containers.

This reference explicitly accepts the current build's memory footprint as the starting point for future regressions. It is a baseline-policy reset, not a memory fix or a cancellation of the retained failures against the parent of PR #25. That reset left thresholds, sample counts and the separate 320 MiB AWG stress contract unchanged; the later absolute-allowance adjustment is documented below. The historical release-recovery boundary remains the independent pre-AWG commit documented below.

This main-branch ancestor has the same application sources and full-feature build inputs as the accepted `37d196c` build; byte-for-byte ARM64 binary equivalence was verified with the gate compiler and flags. Keeping the immutable reference in main history preserves it after squash-merging and deleting the PR branch, without an extra tag or network fetch. Full repository history remains required.

Three paired runs measure idle, loaded, TCP-drained, and repeated-Apply phases. The loaded phase carries concurrent TCP streams and verified UDP exchanges on both tunnels. After TCP closes, the same two UDP sockets keep exchanging payloads during the drained measurements. Zero client/server TCP streams, fresh UDP echoes, and exactly one daemon session per tunnel prove the drain; arbitrary residual tracker entries are not classified as UDP. Apply-cycle sampling includes transient RSS peaks, not only the final settled state. The comparison uses the median RSS, anonymous RSS, and sampled RSS peak for each phase. An increase greater than `max(10% of baseline, 12 MiB)` fails the gate; equality passes. Missing samples, failed transfers, incomplete TCP drain, and failed Apply operations are errors, not skipped checks. No forced GC or scavenging changes the measured process.

The absolute allowance was explicitly raised from 8 to 12 MiB after identical-binary A/A evidence: two of ten native ARM64 comparisons falsely failed on reapplied anonymous RSS, with a maximum positive delta of 9.62 MiB; a separate GitHub AMD64 comparison failed in the same phase/metric at 9.42 MiB. Original reports remain retained. Twelve MiB provides policy headroom above those observations, not a statistically established noise bound. This reduces growth-detection sensitivity by up to 4 MiB; it is not a memory fix or a guarantee against false alarms. Rescoring those same inputs is post-hoc evaluation, not an independent calibration. The 10% relative allowance, three-run medians, reference, workload and separate AWG 320/384 MiB limits remain unchanged.

A separate candidate-only AWG run proves traffic and records its memory. It stays outside the common WireGuard medians even though the accepted reference also supports AWG. This keeps the shared WireGuard workload and AWG smoke scenario separate; it is not the continuous stress gate below.

Reports, raw samples, transfer evidence, logs, and build identities are retained under `.agents-work/memory-regression/`. **Memory regression** uploads that comparison evidence even when the job fails. **AWG stress (320 MiB)** uploads its own `awg-stress-<run>-<attempt>` artifact with the same evidence coverage, including failures. **Router builds** uploads no memory evidence. Review the report before changing a threshold or baseline; do not raise a budget merely to make a regression green. A threshold or baseline change requires a separate rationale and before/after measurements.

The fixture runs at the Docker server's native Linux architecture. Results are not an ARM64/MIPS hardware certification, a long-duration leak audit, or a DNS-leak/security guarantee. The gates measure the full daemon with production protocol features but without embedded UI assets; router cross-builds still compile the normal UI-enabled binaries. Public local build entry points do not bypass either gate when Docker is unavailable. The CI-only router targets compile without those gates and are not a local substitute for them.

### Runtime and conflicting host measurements

Local build gating is deliberate: the public targets `make build`, `make build-router`, and `make build-router-lite` stay fail-closed, including under parallel make. CI no longer couples those gates to router compilation; the independent jobs are described below, next to the stress gate. Tagged release assets still run both gates before the public router targets. A successful serial run schedules at least 5 minutes 21 seconds of measurements and Apply pauses: seven comparison scenarios at 38 seconds each, plus 55 seconds of stress phases. Baseline/candidate/server compilation, downloads, image builds, startup, drain waits, evidence handoff, frontend compilation, and router cross-builds add time; cold runs take longer. This is a lower bound for serial execution, not a completion-time guarantee. Avoid parallel make and competing CPU/memory workloads when collecting comparable measurements; prefer a controlled Linux build host.

If a local comparison fails while the **Memory regression** job passes:

1. Stop the build and retain that run's `report.json`, raw phase samples, logs, and manifest. The CI pass does not erase or override the local failure.
2. Compare source/binary identities, Go toolchains, protocol tags, Docker architectures and resource limits. Record host CPU/memory pressure and other workloads; different architectures or environments are separate observations, not interchangeable repetitions.
3. Investigate the failed phase and distinguish a reproducible increase from an identified environmental cause. If such a cause is corrected, record a separate measurement and retain the original failure and explanation. Do not retry merely until a run passes, force GC, or change thresholds/baseline to hide the result.
4. If the discrepancy remains unexplained, keep the local build blocked and review the evidence. Do not bypass the local gate with `-o`, `build-router-ci`, `build-router-lite-ci`, direct build commands, or a previously successful CI result. A passing **Router builds** check does not certify memory.

### AWG memory stress

`make memory-stress` (`sh test/memory/run.sh --stress`) is a separate gate. It builds only the current daemon and the test server, copies the fixture, and does not archive, build, or run the comparison reference. The result is not an input to the comparison report.

The container is uniquely owned, uses `--network none`, and is privileged so the fixture can create its own namespaces. Limits are 2 GiB of memory with swap disabled, a 2 CPU quota, and affinity `0-1`. The container parent gets `GOMAXPROCS=2`, `GOGC=100`, and `GOMEMLIMIT=off`. The 320 MiB Go limit applies only to the measured daemon inside the fixture; it is a soft budget, not a production default or an RSS cap. Container memory also includes the synthetic remote peer. If the Docker engine reports fewer than 2 CPUs, the run fails instead of dropping affinity or quota. The runner checks the applied memory, swap, CPU, affinity, network, and parent environment before starting; a mismatch is a failure.

The fixture drives 32 continuously progressing TCP streams through the first AWG tunnel with MTU 1280 and `S4=12`; a second ordinary WG tunnel stays idle. It measures 5 seconds idle, 30 seconds under load, and 20 seconds after both the daemon and server report zero sessions. Verified payload echo must reach at least 50 Mbps over the actual load window, and RSS and lifetime `VmHWM` must stay below 384 MiB. Stalls, low load, threshold breaches, and cleanup errors fail the gate. There is no retry and no forced GC. Evidence stays under `.agents-work/memory-regression/` even when the run fails. Owned containers and images are removed on every exit; if copying in-container temporary files fails, that limit is reported and the container is still removed.

Throughput uses the publication timestamps of the same two counter snapshots; memory and CPU phases retain their own wall-clock duration. Exported evidence keeps private file modes and is handed to the invoking host UID/GID only after the workload is confirmed stopped. A constrained, separately tracked helper mounts only this run's evidence trees; ownership handoff failures fail the gate without preventing cleanup.

Local `make build`, `make build-router`, and `make build-router-lite` run this gate and `make memory-regression`. CI does not repeat that coupling and does not use `make -o`. Three independent jobs on separate runners report the work separately. A failure in one does not cancel or skip the others:

- **Memory regression** runs `make memory-regression` with full Git history and uploads comparison evidence even when the job fails.
- **AWG stress (320 MiB)** runs `make memory-stress`. It does not need Node or the comparison reference history. It uploads a separate `awg-stress-<run>-<attempt>` artifact with the same evidence coverage, including failures.
- **Router builds** runs `make build-router-ci build-router-lite-ci` with Go and Node. It does not run either memory workload, does not upload memory evidence, and does not certify memory.

**Tests and builds** and **Network integration** are unchanged. A green **Router builds** result is not a memory result.

For tagged source outside historical recovery, the release asset job runs `make memory-stress` and `make memory-regression` as separate steps, then `make -o memory-stress -o memory-regression build-router build-router-lite` with the existing release identity arguments. Both `-o` flags are permitted only after the corresponding step has succeeded in that same job. GNU make `-o` marks those phony targets already satisfied so the public targets do not repeat the gates. Public targets are required because older AWG tags do not define the CI-only names. A missing gate target fails and never selects historical recovery. `-o` is not an environment bypass, a cache, or a local shortcut. Do not use it unless both separate steps have just succeeded in the same job.

Release publication waits for the CI checks workflow, so every independent job must succeed before version and asset work, and the asset job must pass both gates before the public router builds. Merge requirements are managed separately from workflow files. After a separately authorized administrative update, the active `main` ruleset requires **Tests and builds**, **Network integration**, **Memory regression**, **AWG stress (320 MiB)**, and **Router builds**, all from the GitHub Actions integration (`15368`). The two existing checks and all other rules, bypass settings, conditions and status-check parameters were preserved. The old combined **Memory regression and builds** status was not required. Workflow YAML does not configure this protection; preserve all five required contexts when recreating the ruleset.

Historical release-asset recovery from `main` is explicitly limited by Git ancestry to commits at or before the fixed pre-AWG boundary `9d398fb3754036cbe35df1cf07098164ff62a9d5`, including `v0.8.0`. Current workflow CI is still required, and the tagged version is checked before expensive work. Recovery leaves tagged source unchanged and runs its original Makefile/protocol flags for Go tests, vet, network integration, frontend tests, and full/lite router builds with the requested release identity. A visible notice and uploaded `.agents-work/release-legacy/<run>-<attempt>/` manifest, command log, and exit code record this separate verification contract, including failures; they are not memory measurements or AWG certification, because that source does not support AWG. Commits outside this ancestry must pass both memory gates; missing targets fail rather than selecting recovery. Existing assets must remain byte-identical before missing assets are published. See [RELEASING](https://github.com/ordo-systems/keen-proxy/blob/main/RELEASING.md#github-setup-and-recovery).

## Edit and translate

Maintain matching Markdown filenames under `docs/en/` and `docs/ru/`. Navigation is configured in `mkdocs.yml`; the i18n plugin creates language switching and localized search/navigation. Add screenshots under `docs/assets/screenshots/` in both UI languages. Capture only synthetic sessions and update related captions when screens change.

Demo mode replaces imports of the API module with `web/src/demo/api.ts` through a Vite alias. Its `satisfies` contract catches differences from the normal API. Add behavior tests when extending the adapter; do not add backend networking to simulate a feature.

## GitHub Pages

The **Documentation** workflow builds and checks both outputs on relevant PRs and pushes. It uploads only `site/`, containing generated documentation and the demo. Internal reports, local memories, application source maps, credentials, and Go runtime state are not part of that directory.

Enable GitHub Pages with **GitHub Actions** as its source. Changes to the docs or demo on `main` are published after the **Documentation** build succeeds. To republish on demand, run **Documentation** on `main` with **Deploy to GitHub Pages** enabled. Pull request runs build a preview artifact. The default site URL is `https://ordo-systems.github.io/keen-proxy/`. A private repository requires a supporting GitHub plan; publishing Pages can make the generated site publicly accessible. Do not change repository visibility merely to enable Pages.

The release workflow and Pages deployment are independent. Follow [CONTRIBUTING](https://github.com/ordo-systems/keen-proxy/blob/main/CONTRIBUTING.md) for versioning and [RELEASING](https://github.com/ordo-systems/keen-proxy/blob/main/RELEASING.md) for binary releases.
