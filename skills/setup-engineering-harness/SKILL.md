---
name: setup-engineering-harness
description: Inspect a repository and deterministically plan, install, audit, repair, or uninstall its adaptive coding workflow. Use when asked to configure one coding agent to align requirements naturally, batch independent questions, research exact and current dependency behavior, select a suitable stack without framework bias, plan proportionately, verify claims, and preserve only durable documentation without replacing user instructions.
---

# Set Up Engineering Harness

Configure one existing Project in a single approved pass. Keep `AGENTS.md` thin and load detailed
Playbooks only when routed.

## One-shot workflow

1. Resolve the target Project; never target this Skill directory.
2. Resolve the current provider as `codex` or `claude-code`. If the host is
   unclear, ask one objective provider choice. Run the read-only preview:

   ```bash
   python3 <skill-dir>/scripts/setup_harness.py plan \
     --provider <provider> --repo <project>
   ```

3. Present detected facts and unresolved decisions together. Make every choice objectively
   comparable; put recommendations in a separate section with their criteria and rationale.
4. Show the planned file and host-state changes. Obtain one approval for that exact scope.
5. Install, run the normal-provider canary, then audit:

   ```bash
   python3 <skill-dir>/scripts/setup_harness.py install \
     --provider <provider> --repo <project>
   python3 <skill-dir>/scripts/setup_harness.py verify-provider \
     --provider <provider> --repo <project>
   python3 <skill-dir>/scripts/setup_harness.py audit --repo <project>
   ```

   `verify-provider` starts one constrained fresh provider session and proves
   that its `PreToolUse` hook denies a reserved write canary. If the provider
   has not reviewed the exact Project hooks, tell the user to open it in the
   Project, run `/hooks`, review and trust the two Engineering Harness entries,
   then rerun `verify-provider`. Persisted hook trust is a provider/user
   security decision; do not forge or edit it.

6. Report `PASS`, `INCOMPLETE`, or `FAIL` exactly. `INCOMPLETE` means a provider or integrity
   prerequisite is still unverified.

Install, repair, audit, and uninstall use the Python 3.12-or-newer standard library only. They never run
Project commands, read secrets, change application code, or install packages. `verify-provider`
runs only the reserved write-deny canary and binds its receipt to the current manifest checksum.

The seeded default is `write_gate.mode = "assistive"`: normal reads, research tools, shell
commands, verification, and app writes use the provider's ordinary permissions. The Hook protects
secrets, Harness-owned paths, provider Hook configuration, and the reserved canary. `strict` is an
explicit compatibility mode for the scoped-lease protocol.

## Ownership and recovery

- Preserve every existing provider instruction file byte outside the stable
  managed block (`AGENTS.md` for Codex or `CLAUDE.md` for Claude Code).
- Treat `.agent-harness/config.json` and `.agent-harness/local.md` as user-owned seed-once files.
- Treat the manifest, repository profile, Router, Playbooks, checker, and broker as
  installer-owned.
- Preserve unrelated provider hooks in `.codex/hooks.json` or
  `.claude/settings.json`. Manage exactly one `PreToolUse` and one
  `UserPromptSubmit` entry.
- Stop `install` on owned drift without writing. Use `repair` only after explicit approval; it
  writes content-addressed recovery copies before replacement.
- Repeated `install` must be byte-identical. Use `uninstall` only after explicit approval; it
  removes managed content while retaining user-owned and unknown files.

Commands:

```bash
python3 <skill-dir>/scripts/setup_harness.py plan --provider <provider> --repo <project>
python3 <skill-dir>/scripts/setup_harness.py install --provider <provider> --repo <project>
python3 <skill-dir>/scripts/setup_harness.py verify-provider --provider <provider> --repo <project>
python3 <skill-dir>/scripts/setup_harness.py audit --repo <project>
python3 <skill-dir>/scripts/setup_harness.py repair --provider <provider> --repo <project>
python3 <skill-dir>/scripts/setup_harness.py uninstall --repo <project>
```

Do not manually copy assets or edit managed files. The installer owns merge, hashing, atomic
rollback, and host-state placement.
