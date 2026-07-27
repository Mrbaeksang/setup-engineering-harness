<!-- engineering-harness:installer-owned -->
# Engineering Harness router

Use the Harness for one Coding Agent. It guides work but never overrides higher-priority user or
repository instructions.

## Start

1. Read `repo-profile.json`, then user-owned `config.json` and `local.md`.
2. Always read `playbooks/core.md` and `playbooks/safety.md`.
3. Load only matching Playbooks:

| Signal | Playbook |
| --- | --- |
| Ambiguous outcome, behavior, or choice | `playbooks/conversation.md` |
| Package, SDK, API, framework, tool, migration, or dependency bug | `playbooks/dependencies.md` |
| Domain, module, contract, persistence, or external boundary | `playbooks/architecture.md` |
| Any behavior, code, UI, build, or performance change | `playbooks/verification.md` |
| Durable repository knowledge changes | `playbooks/documentation.md` |

While the write Gate is locked, use the exact context-broker prefix injected by the
`UserPromptSubmit` hook, followed by a supported read subcommand. Submit the structured acceptance
contract with its injected exact lifecycle prefix. Once acceptance, Evidence, scope, and
verification are concrete, use the exact lease-request prefix and canonical `scope=…`,
`verify=…`, and `evidence=<kind>:<path>` tokens. Dependency claims and official registrations are
defined in `playbooks/dependencies.md`. A proposal is not a lease. Do not route around the Gate.
Before completion, use the injected context-broker `git-status` and `git-diff` commands; raw Git
is intentionally denied.
