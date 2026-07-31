<!-- engineering-harness:installer-owned -->
# Engineering Harness router

Use the Harness for one Coding Agent. It adapts to the user and repository; it does not prescribe
a framework, architecture, or document set.

## Start

1. Read `repo-profile.json`, then user-owned `config.json` and `local.md`.
2. Always read `playbooks/core.md` and `playbooks/safety.md`.
3. Load only matching Playbooks:

| Signal | Playbook |
| --- | --- |
| Consequential unresolved requirement or choice | `playbooks/conversation.md` |
| Package, SDK, API, framework, tool, migration, or stack selection | `playbooks/dependencies.md` |
| Medium or large change needing a compact spec or slices | `playbooks/planning.md` |
| Any code or behavior change | `playbooks/implementation.md` and `playbooks/verification.md` |
| Domain, module, contract, persistence, or external boundary | `playbooks/architecture.md` |
| Durable repository knowledge changes | `playbooks/documentation.md` |

Use the smallest workflow that fits:

- Small fix: reproduce → fix → regression → verify.
- Medium change: align → research → compact spec → implement → verify.
- Large or costly change: align deeply → research → user choice → compact spec → tracer-bullet
  vertical slices → implement and verify slice by slice.

Normal research, repository reads, verification commands, and application writes do not require
Harness-specific acceptance tokens, proposal IDs, or leases in the default `assistive` mode.
The optional `strict` mode exists for projects that explicitly choose the legacy scoped-lease
boundary.
