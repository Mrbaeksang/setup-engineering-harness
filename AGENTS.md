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
- Treat prompts as guidance and enforce deterministic prerequisites with
  provider hooks or an equivalent fail-closed capability boundary.
- Use DDD language, cohesive modules, and ports/adapters by default, but create
  physical layers only when real boundaries or invariants justify them.
- Do not create progress reports, meeting notes, speculative roadmaps, or
  duplicate documentation.
