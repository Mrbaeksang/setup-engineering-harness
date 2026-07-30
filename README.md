# setup-engineering-harness

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

`setup-engineering-harness` configures a repository so one coding agent follows an adaptive,
evidence-led workflow without imposing a favorite framework or architecture.

The installed workflow:

- aligns consequential requirements in natural conversation and batches independent questions;
- inspects the existing repository before recommending changes;
- verifies exact installed versions and re-learns current APIs from primary official sources;
- compares current stack candidates for greenfield or intentional stack changes;
- scales from a tiny bug loop to compact specs and tracer-bullet vertical slices;
- keeps research and planning ephemeral unless durable documentation or tickets are genuinely
  useful;
- verifies behavior and inspects the diff before claiming completion.

The default `assistive` mode does not require proposal IDs, hashes, magic approval phrases, or
write leases. Its Codex Hook is a thin safety boundary for secrets, Harness-owned files, provider
hook configuration, and the provider canary. Normal repository work and specialized tools such as
web research, documentation connectors, and image generation remain available.

An optional `strict` mode preserves the original scoped-lease protocol for projects that
explicitly need it.

## What Setup installs

The standard-library-only Python installer preserves existing instructions and hooks, then adds a
thin provider-native bridge:

```text
AGENTS.md or CLAUDE.md            thin managed bridge
.codex/hooks.json or
.claude/settings.json             merged prompt and safety hooks
.agent-harness/
  config.json                     user-owned policy; defaults to assistive mode
  local.md                        user-owned local constraints
  repo-profile.json               regenerable repository facts
  router.md                       adaptive Playbook router
  playbooks/                      conversation, research, planning, implementation, verification
  bin/                            optional read, strict-lifecycle, and verification helpers
  checks/audit.py                 Harness integrity audit
  manifest.json                   ownership and host-runtime pointers
```

Trusted runtime code and provider-canary receipts live outside the Project under the user's XDG
state directory. Secrets, logs, caches, and transient receipts are not added to Git.

## Install from a clone

No npm installation is required:

```bash
git clone https://github.com/Mrbaeksang/setup-engineering-harness.git
cd setup-engineering-harness

python3 skills/setup-engineering-harness/scripts/setup_harness.py \
  plan --provider codex --repo /path/to/project

python3 skills/setup-engineering-harness/scripts/setup_harness.py \
  install --provider codex --repo /path/to/project
```

The plan is read-only. After approving the exact install scope, verify the real provider Hook and
audit the installed Harness:

```bash
python3 skills/setup-engineering-harness/scripts/setup_harness.py \
  verify-provider --provider codex --repo /path/to/project

python3 skills/setup-engineering-harness/scripts/setup_harness.py \
  audit --repo /path/to/project
```

Use `--provider claude-code` for Claude Code. The same entrypoint supports explicit `repair` and
`uninstall` operations. Install and repair never run Project commands, install packages, read
secrets, or change application code.

## Install as an Agent Skill

The repository also follows the open Agent Skills layout. Install or copy
`skills/setup-engineering-harness` into the provider's skills directory, restart the provider,
then invoke `$setup-engineering-harness`.

An npm executable remains available as an optional distribution channel; it runs the same Python
installer and is not required by the installed Harness.

## Configuration

`.agent-harness/config.json` is seeded once and remains user-owned.

```json
{
  "write_gate": {
    "mode": "assistive"
  }
}
```

Set `mode` to `strict` only when the Project intentionally wants the compatibility scoped-lease
workflow. Missing `mode` is treated as `assistive`, so existing installations adopt the less
ceremonial default without overwriting user-owned configuration.

## Development checks

```bash
PYTHONDONTWRITEBYTECODE=1 \
python3 -m unittest discover -s tests -p 'test_*.py'

npm run verify:distribution
```

The benchmark fixture is synthetic test data, not empirical proof. Current design, threat model,
and verification evidence live in the canonical
[design document](docs/design/setup-engineering-harness.md).

## Boundaries

- The adaptive workflow is guidance; provider permissions and sandboxing remain the authority for
  normal execution.
- The thin Hook cannot infer the side effects of every future specialized tool. External writes
  still require the user's explicit authorization under the provider's normal rules.
- A live provider canary must pass on the user's machine; simulated Hook replay is not equivalent.
- Clean-context behavior screens are directional, not statistically significant.

## License

Licensed under the [Apache License 2.0](LICENSE).
