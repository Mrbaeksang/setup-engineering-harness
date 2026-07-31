<!-- engineering-harness:installer-owned -->
# Narrow implementation

- Follow existing style, contracts, and boundaries unless the agreed change intentionally alters
  them.
- Make the smallest coherent change that delivers the accepted behavior.
- For bugs, add or identify a failing regression before the fix when practical.
- For large work, implement one tracer-bullet slice at a time and keep each slice runnable.
- Use the selected dependency's version-correct documented API; do not copy remembered syntax
  across major versions.
- Preserve compatibility unless the Task explicitly changes it.
- Do not mix unrelated cleanup, upgrades, formatting, or speculative abstractions into the diff.
- After each meaningful slice, run narrow verification; before completion, run proportionate
  nearby checks and inspect the whole diff.
