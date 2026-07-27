---
name: setup-engineering-harness
description: Inspect an existing repository and deterministically plan, install, audit, repair, or uninstall its project-local evidence-gated coding harness. Use when asked to set up the repository so one coding agent automatically asks objective batched questions, researches exact dependency versions and native capabilities, plans narrow changes, verifies claims, maintains durable documentation, or when an existing Engineering Harness must be checked or restored without replacing user instructions.
---

# Set Up Engineering Harness

Configure one existing Project in a single approved pass. Keep `AGENTS.md` thin and load detailed
Playbooks only when routed.

## One-shot workflow

1. Resolve the target Project; never target this Skill directory.
2. Run the read-only preview:

   ```bash
   python3 <skill-dir>/scripts/setup_harness.py plan --repo <project>
   ```

3. Present detected facts and unresolved decisions together. Make every choice objectively
   comparable; put recommendations in a separate section with their criteria and rationale.
4. Show the planned file and host-state changes. Obtain one approval for that exact scope.
5. Install, run the normal-provider canary, then audit:

   ```bash
   python3 <skill-dir>/scripts/setup_harness.py install --repo <project>
   python3 <skill-dir>/scripts/setup_harness.py verify-provider --repo <project>
   python3 <skill-dir>/scripts/setup_harness.py audit --repo <project>
   ```

   `verify-provider` starts one fresh Codex session in `read-only` sandbox mode and does not pass
   `--dangerously-bypass-hook-trust`. If Codex has not reviewed the exact Project hooks, tell the
   user to open Codex in the Project, run `/hooks`, review and trust the two Engineering Harness
   entries, then rerun `verify-provider`. Persisted hook trust is a Codex/user security decision;
   do not forge or edit it.

6. Report `PASS`, `INCOMPLETE`, or `FAIL` exactly. `INCOMPLETE` means an enforcement prerequisite
   is still unverified.

Install, repair, audit, and uninstall use Python 3.12 standard library only. They never run
Project commands, read secrets, change application code, or install packages. `verify-provider`
runs only the reserved write-deny canary, restores Task state, and binds its receipt to the
current manifest checksum.

## Ownership and recovery

- Preserve every existing `AGENTS.md` byte outside the stable managed block.
- Treat `.agent-harness/config.json` and `.agent-harness/local.md` as user-owned seed-once files.
- Treat the manifest, repository profile, Router, Playbooks, checker, and broker as
  installer-owned.
- Preserve unrelated provider hooks. Manage exactly one `PreToolUse` and one
  `UserPromptSubmit` entry.
- Stop `install` on owned drift without writing. Use `repair` only after explicit approval; it
  writes content-addressed recovery copies before replacement.
- Repeated `install` must be byte-identical. Use `uninstall` only after explicit approval; it
  removes managed content while retaining user-owned and unknown files.

Commands:

```bash
python3 <skill-dir>/scripts/setup_harness.py plan --repo <project>
python3 <skill-dir>/scripts/setup_harness.py install --repo <project>
python3 <skill-dir>/scripts/setup_harness.py verify-provider --repo <project>
python3 <skill-dir>/scripts/setup_harness.py audit --repo <project>
python3 <skill-dir>/scripts/setup_harness.py repair --repo <project>
python3 <skill-dir>/scripts/setup_harness.py uninstall --repo <project>
```

Do not manually copy assets or edit managed files. The installer owns merge, hashing, atomic
rollback, and host-state placement.
