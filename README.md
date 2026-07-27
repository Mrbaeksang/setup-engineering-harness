# setup-engineering-harness

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

`setup-engineering-harness` is a one-shot skill that configures a repository so
one coding AI works evidence-first by default.

It is not a multi-agent manager. It improves the session the user is already
using:

- ambiguous product choices are asked together before implementation;
- dependency work starts from the installed version, official sources, types,
  source, and a reproduction;
- native library capabilities are checked before custom code;
- writes require a scoped acceptance contract and lease;
- completion requires fresh verification and a diff-backed receipt;
- repository context is loaded progressively instead of dumped into the model;
- durable documentation is canonical and updated, not accumulated as meeting
  notes or speculative roadmaps.

The current implementation targets Codex project hooks. It is an R&D-quality
prototype, not a claim of statistically validated production readiness.

## What Setup installs

The installer preserves existing repository instructions and adds a thin
`AGENTS.md` bridge. Detailed behavior lives in task-routed Playbooks under
`.agent-harness/`.

```text
AGENTS.md                         thin managed bridge
.codex/hooks.json                 merged UserPromptSubmit and PreToolUse hooks
.agent-harness/
  config.json                     user-owned policy
  local.md                        user-owned local constraints
  repo-profile.json               regenerable repository facts
  router.md                       progressive Playbook router
  playbooks/                      focused conversation/research/work rules
  bin/                            read, lifecycle, and verification brokers
  checks/audit.py                 Harness integrity audit
  manifest.json                   ownership and host-runtime pointers
```

Authoritative Gate state and trusted runtime code are placed outside the
repository under the user's XDG state directory. Secrets, raw logs, caches, and
transient receipts are not added to Git.

## Install

The current supported enforcement target is Codex. Install the Setup skill
globally from GitHub with the open `skills` CLI:

```bash
npx skills@latest add Mrbaeksang/setup-engineering-harness \
  --skill setup-engineering-harness \
  -a codex -g -y
```

No npm package from this repository is installed. The command copies the
versioned skill from GitHub into Codex's skill directory.

Open Codex in the repository you want to configure and invoke:

```text
$setup-engineering-harness
```

The skill first shows a read-only repository profile, unresolved decisions, and
the exact planned changes. One approval covers that scope; it then installs,
runs the real-provider canary, and audits the result.

The Agent Skill format can also be copied into Claude Code, but the current
mechanical enforcement adapter targets Codex project hooks. This repository
therefore does not advertise a Claude Marketplace install as fully supported.

Requirements after skill installation: Python 3.12, Git, Codex CLI, and a
supported local isolation mechanism for managed verification (`bubblewrap` on
Linux/WSL or `sandbox-exec` on macOS).

## Run from a clone

For development or manual inspection, clone this repository and call the same
installer directly:

```bash
python3 skills/setup-engineering-harness/scripts/setup_harness.py \
  plan --repo /path/to/project

python3 skills/setup-engineering-harness/scripts/setup_harness.py \
  install --repo /path/to/project
```

Then review and trust the exact project hook definitions in Codex and run:

```bash
python3 skills/setup-engineering-harness/scripts/setup_harness.py \
  verify-provider --repo /path/to/project

python3 skills/setup-engineering-harness/scripts/setup_harness.py \
  audit --repo /path/to/project
```

`install` can intentionally report `INCOMPLETE` until provider trust and the
write-deny canary are proven. It does not run project commands, install
packages, read secrets, or change application code.

The same entrypoint supports `repair` and `uninstall`; both are explicit
operations because managed drift and deletion should not be silently accepted.

## Development checks

```bash
PYTHONDONTWRITEBYTECODE=1 \
python3 -m unittest discover -s tests -p 'test_*.py'

PYTHONDONTWRITEBYTECODE=1 \
python3 /path/to/skill-creator/scripts/quick_validate.py \
  skills/setup-engineering-harness
```

The benchmark fixture under `benchmarks/fixtures/` is synthetic test data for
the scoring engine. It is not empirical proof. Actual clean-context behavior
screens and their limitations are recorded in the canonical
[design document](docs/design/setup-engineering-harness.md).

## Current boundaries

- The installed provider adapter is Codex-specific.
- Clean-context behavior screens currently have one run per arm, so findings
  are directional rather than statistically significant.
- A live Codex provider canary must pass on the user's machine; a simulated hook
  replay is not equivalent.

## License

Licensed under the [Apache License 2.0](LICENSE).
