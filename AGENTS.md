# Contributor and agent instructions

## Workspace and publication

- Name Git branches by the type of work using `<type>/<short-description>`, with prefixes such as `feature/`, `fix/`, `docs/`, `refactor/`, or `chore/`. Do not use agent, model, or tool names as branch prefixes, including `codex/` and `claude/`.
- Create all Git worktrees under the main checkout's `.agents-worktree/<task>/` directory, regardless of the agent host. Do not use `.claude/worktrees/`, `.codex/worktrees/`, temporary directories, or sibling directories. When already inside a linked worktree, use the main checkout's directory rather than nesting another worktree.
- Keep `/.agents-worktree/` in the root `.gitignore`. Never force-add this directory or its contents.

## Language and documentation

- Whenever a new feature or behavior change requires documentation, add or update the affected documentation and user guides in the same change. Keep the English and Russian versions in sync.
- Write developer documentation, code comments, and shared Serena memories in concise English.
- Keep runtime errors, logs, generated comments, and code text in English. Literal Cyrillic belongs only in `docs/ru/` and Russian localization resources. Use Unicode escapes for essential Cyrillic test fixtures without changing their runtime values. Run `make check-language` to verify this boundary.
- Explain the purpose, contract, ownership, or important constraint of significant types and functions. Avoid comments that merely repeat their names.
- Preserve translated UI messages, test inputs, protocol examples, and original third-party data when their language is part of behavior or provenance.
- Keep public project documentation in the repository: README.md, AGENTS.md, CONTRIBUTING.md, SECURITY.md, and LICENSE.
- Store internal plans, investigations, work logs, deployment reports, and visual QA reports only in ignored `.agents-work/`. Use `.agents-work/design-qa.md` even when a skill suggests a root-level report.
- Treat everything in [`.serena/memories/`](.serena/memories/core.md) as public. Store only durable project knowledge there. Keep credentials, private network addresses, device identifiers, production configuration, private transcripts, and deployment records out of shared memories. Keep local Serena configuration and caches ignored.

## Required workflow for AI agents

1. For code changes, use the relevant [ub-mode](https://github.com/unclebob/ub-mode) principles: **First Make it Work → Then Make it Right → Follow Practice**. Read its `SKILL.md` before editing code. Make the smallest change that solves the problem, remove unnecessary complexity, and verify behavior at its normal entry point. Documentation-only changes, formatting, and read-only investigations do not require the code-quality toolchain. This repository's authorization, publication, and verification rules take precedence over generic skill instructions.
2. Choose verification by changed behavior and risk. Reuse existing tests; add a regression test when a bug is not already covered. For new or uncertain behavior, use a focused test or disposable smoke scenario. Tests must check observable results, not source text or incidental implementation details. Run the narrowest meaningful checks once after the affected changes are integrated; expand only for uncovered risks or repository-required gates. Record commands, results, and limitations briefly in `.agents-work/`.
3. Before analyzing code, read [`core`](.serena/memories/core.md) and the relevant project memories. When [Serena](https://github.com/oraios/serena) is available, activate this checkout, check onboarding, and prefer it for memory reads. For symbol lookup, definitions, references, and other semantic code navigation, use the host's preferred LSP tooling when available; otherwise prefer Serena's semantic tools. Confirm that the selected tooling targets the current checkout. In a Git worktree, confirm that Serena points at the worktree and not at the main checkout before using its editing tools. If Serena is unavailable, open `.serena/memories/core.md` directly and follow relevant `mem:<name>` references by reading `.serena/memories/<name>.md` with the available file tools. Regardless of the tools used, verify memory claims against the current source.

### Targeted quality analysis

Use Crapper, Dryer, and Mutator only when they answer a concrete question raised by the change or are explicitly requested. They are not mandatory for every code edit and do not replace normal project tests. State the reason and select only the relevant tool, affected functions or lines, and test command:

- **Crapper:** For changed complex or branch-heavy logic when coverage adequacy is uncertain. Use real Go `-coverprofile` output with the Makefile tags or real frontend LCOV. Treat CRAP below 10 as a diagnostic target, not a reason to add low-value tests or refactor unrelated code.
- **Dryer:** For substantial refactoring or suspected duplication. Run `dryer --threshold 0.8 <affected files>` and inspect candidates; do not deduplicate code solely to satisfy a score.
- **Mutator:** For critical changed decisions whose test assertions are uncertain, such as configuration validation, routing, failover, update/rollback, or authorization. Use a bounded function or line selection and the narrowest relevant test command: `mutator --test-command '<project test command>' <affected files>`. Do not launch repository-wide mutation runs by default. Report executed, killed, survived, and uncovered sites; a scan, a failed baseline, or zero selected mutations is not mutation-resistance evidence.

Install skills, Serena, and any selected quality tools using their upstream instructions outside the repository, in isolated tool environments. Use the official [Crapper](https://github.com/unclebob/crapper), [Dryer](https://github.com/unclebob/dryer), and [Mutator](https://github.com/unclebob/mutator) launchers; keep Mutator next to Crapper as required upstream. Check `--help` before a tool's first run. Do not install or run unneeded analyzers for the sake of completing a checklist.

If a selected skill, Serena, or analyzer is unavailable or cannot read an affected format, report the specific limitation and use applicable repository checks instead. Do not broaden testing merely to compensate for an irrelevant analyzer. Use [the verification memory](.serena/memories/task_completion.md) for project test entry points. Required build, memory, integration, and release gates remain mandatory where applicable.

## Engineering

- Keep configuration changes consistent across the Go model, compiler, API, frontend types, examples, and tests.
- Preserve the shared frontend draft/Apply workflow; do not bypass it with separate configuration writes.
- Keep compilation deterministic; put runtime effects in the daemon, engine, and firewall layers.
- Preserve build constraints, generated-file markers, license notices, and compiler/tool directives when editing comments.
- Do not access or modify a live router without an explicit deployment or diagnostic request. Use synthetic configurations in tests.

## Verification

- Run relevant Go tests with the Makefile's sing-box build tags; use CGO_ENABLED=0 where a C toolchain is unavailable.
- Run frontend tests and the production build after frontend changes. Run installer tests when changing installer behavior.
- Use make integration for routing/DNS/firewall changes when Docker is available; it runs privileged network namespaces inside a disposable container.
- Before producing application binaries, run `make memory-regression` and `make memory-stress`. The public local targets `make build`, `make build-router`, and `make build-router-lite` enforce both, including under parallel make. `make build-router-ci` and `make build-router-lite-ci` are CI-only compilation targets; they do not certify memory and are not a local bypass. Compare the regression gate against the fixed accepted checkpoint declared in `test/memory/run.sh` using identical synthetic configuration, workload, compiler, and architecture. Preserve raw phase metrics and traffic/Apply evidence. Treat missing or failed measurements as failures. Do not force GC in the measured daemon, silently skip unavailable Docker, or replace a failed result with a retry. Historical release-recovery ancestry is independent and must not follow the comparison baseline.
- Keep candidate-only AWG measurements separate from the common WireGuard comparison. The continuous stress gate is also candidate-only: 320 MiB Go limit on the measured daemon, 384 MiB RSS ceiling, 2 CPU affinity, and no baseline build. Do not raise memory thresholds or move the baseline to hide a regression; require an explicit rationale and before/after evidence. See the [memory gate guide](docs/en/development.md#memory-regression-gate). Native Docker results do not certify router architectures or long-duration memory behavior, and router compilation does not certify memory.
- Do not pass `make -o memory-stress` or `make -o memory-regression` to skip a local gate. CI no longer uses `-o`. **Memory regression**, **AWG stress (320 MiB)**, and **Router builds** are independent jobs; the router job runs only `make build-router-ci build-router-lite-ci`. The tagged-source release asset job may pass both `-o` flags only after successful `make memory-stress` and `make memory-regression` steps in that same job, then builds with the public router targets. Those flags are not a cache or an environment bypass. Those three statuses, with **Tests and builds** and **Network integration**, are what should gate merge. Release publication waits for every CI job and for both asset-job gates. Configuring the merge requirements is a separate repository-rules action; editing these instructions does not do it. See [RELEASING.md](RELEASING.md).
- For documentation-only edits, check links and prove executable tokens are unchanged rather than adding implementation-mirroring tests.
- Report validation limits honestly. A successful HTTP probe does not prove HTTPS transfers or DNS-leak protection.

## Publication

- The project is licensed under GPL-3.0-only; retain third-party notices and document separate data licenses.
- Use placeholders in examples. Keep local device identifiers, production logs, and credentials out of public documentation.
- Preparing public files does not authorize publishing, pushing, rewriting Git history, or deploying changes.
