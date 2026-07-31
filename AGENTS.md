# Repository instructions

This repository builds `setup-engineering-harness`: a one-shot skill that
configures a project so one coding agent follows the repository's evidence-led
conversation, research, implementation, verification, context, and
documentation workflow automatically.

Before changing this repository:

- Read `CONTEXT.md` for canonical terms.
- Read `docs/design/setup-engineering-harness.md` for the accepted behavior and
  test evidence.
- Keep `AGENTS.md` as a thin entrypoint. Route detailed procedures through
  progressively loaded playbooks.
- Treat prompts as workflow guidance. Keep the default provider Hook a thin
  boundary for secrets, Harness internals, provider configuration, and the
  verification canary; do not blanket-block normal or future tools.
- Follow the repository's current architecture first. Use DDD, cohesive
  modules, ports/adapters, or other patterns only when the actual boundaries
  and tradeoffs justify them.
- Do not create progress reports, meeting notes, speculative roadmaps, or
  duplicate documentation.
