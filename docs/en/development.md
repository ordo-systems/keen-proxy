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

Makefile and CI select Go **1.27.3** from the root `go.mod` `go` directive, preserving main's language floor. For direct commands, use `GOTOOLCHAIN=go1.27.3 go …` when your PATH selects a different compiler. Do not copy the entire upstream `LX_TAGS`: KeenProxy owns a smaller full/lite feature set and does not enable the tags requiring `-checklinkname=0`.

Release source archives contain the module manifests and build scripts. Rebuilding fetches the exact versions verified by `go.sum`; it does not require Git submodule initialization. Do not replace pins with `@latest`.

## Memory regression gate

`make build`, `make build-router`, and `make build-router-lite` require the memory gate before producing application binaries. Docker (including permission to run privileged containers), Python 3, Git history, and the Go toolchain from `go.mod` are required. Run the gate independently with:

```sh
make memory-regression-unit
make memory-regression
```

The gate builds the current source and `9d398fb3754036cbe35df1cf07098164ff62a9d5`, the parent of PR #25, using the same Go compiler and matching full protocol features. Only the candidate enables AWG. Both daemons run the same synthetic two-WireGuard configuration and TCP/UDP workload, without a router, production credentials, or external test destinations. Namespace and firewall changes stay inside uniquely owned disposable Linux containers.

Three paired runs measure idle, loaded, TCP-drained, and repeated-Apply phases. The loaded phase carries concurrent TCP streams and verified UDP exchanges on both tunnels. After TCP closes, the same two UDP sockets keep exchanging payloads during the drained measurements. Zero client/server TCP streams, fresh UDP echoes, and exactly one daemon session per tunnel prove the drain; arbitrary residual tracker entries are not classified as UDP. Apply-cycle sampling includes transient RSS peaks, not only the final settled state. The comparison uses the median RSS, anonymous RSS, and sampled RSS peak for each phase. An increase greater than `max(10% of baseline, 8 MiB)` fails the gate; equality passes. Missing samples, failed transfers, incomplete TCP drain, and failed Apply operations are errors, not skipped checks. No forced GC or scavenging changes the measured process.

A separate candidate-only AWG run proves traffic and records its memory. It is not compared with the old binary, which cannot consume AWG profiles. This separates dependency regressions on existing configurations from the cost of a newly added tunnel.

Reports, raw samples, transfer evidence, logs, and build identities are retained under `.agents-work/memory-regression/`. CI retains the results even when the gate fails. Review the report before changing a threshold or baseline; do not raise a budget merely to make a regression green. A threshold or baseline change requires a separate rationale and before/after measurements.

The fixture runs at the Docker server's native Linux architecture. Results are not an ARM64/MIPS hardware certification, a long-duration leak audit, or a DNS-leak/security guarantee. The gate measures the full daemon with production protocol features but without embedded UI assets; router cross-builds still compile the normal UI-enabled binaries. Build entry points do not bypass the gate when Docker is unavailable.

## Edit and translate

Maintain matching Markdown filenames under `docs/en/` and `docs/ru/`. Navigation is configured in `mkdocs.yml`; the i18n plugin creates language switching and localized search/navigation. Add screenshots under `docs/assets/screenshots/` in both UI languages. Capture only synthetic sessions and update related captions when screens change.

Demo mode replaces imports of the API module with `web/src/demo/api.ts` through a Vite alias. Its `satisfies` contract catches differences from the normal API. Add behavior tests when extending the adapter; do not add backend networking to simulate a feature.

## GitHub Pages

The **Documentation** workflow builds and checks both outputs on relevant PRs and pushes. It uploads only `site/`, containing generated documentation and the demo. Internal reports, local memories, application source maps, credentials, and Go runtime state are not part of that directory.

Enable GitHub Pages with **GitHub Actions** as its source. Changes to the docs or demo on `main` are published after the **Documentation** build succeeds. To republish on demand, run **Documentation** on `main` with **Deploy to GitHub Pages** enabled. Pull request runs build a preview artifact. The default site URL is `https://ordo-systems.github.io/keen-proxy/`. A private repository requires a supporting GitHub plan; publishing Pages can make the generated site publicly accessible. Do not change repository visibility merely to enable Pages.

The release workflow and Pages deployment are independent. Follow [CONTRIBUTING](https://github.com/ordo-systems/keen-proxy/blob/main/CONTRIBUTING.md) for versioning and [RELEASING](https://github.com/ordo-systems/keen-proxy/blob/main/RELEASING.md) for binary releases.
