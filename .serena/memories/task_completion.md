# Change verification
- Run make check-language for English source and shared memory changes. Check public document links and memory references. Keep local evidence in `.agents-work/`.
- Run CGO_ENABLED=0 make test and CGO_ENABLED=0 make vet for relevant Go changes. Use the Makefile protocol tags in focused tests and coverage runs.
- For frontend changes run npm --prefix web test and npm --prefix web run build. Also run npm --prefix web run build:demo when demo contracts change.
- Run make integration for DNS, firewall, and routing changes. Verify Linux packet behavior in disposable namespaces before requesting hardware validation.
- Follow the targeted quality analysis section in AGENTS.md: select Crapper, Dryer, or Mutator only for a concrete risk or explicit request, not for every code change. Keep scopes bounded and report relevant tool limitations and findings.
- Inspect the final diff, confirm only intended files are visible to Git, and distinguish unit, integration, demo, and hardware evidence.
