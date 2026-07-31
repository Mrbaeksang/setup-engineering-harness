<!-- engineering-harness:installer-owned -->
# Proportionate verification

Never claim a check passed unless it ran and its result was observed.

1. Reproduce the failure or establish a comparable baseline when feasible.
2. Run the narrowest check that exercises changed public behavior and boundary failures.
3. Run nearby repository-native test, type, lint, build, integration, format, browser, or
   performance checks in proportion to risk.
4. Inspect `git status` and the diff for scope, surrounding style, debug artifacts, generated
   noise, accidental formatting, and secret exposure.
5. Run `python3 .agent-harness/checks/audit.py` after Harness or instruction changes, not for an
   ordinary application-code change.

Commands in `repo-profile.json` are detected candidates, not proof. Confirm they remain valid
before running them. In default `assistive` mode, run normal repository-native commands through
the provider's standard permissions and sandbox. Projects that explicitly enable `strict` mode
may use the installed verification broker and scoped lease protocol.

For UI changes, exercise the real flow when a browser or native UI is available and inspect
loading, empty, error, success, focus, relevant viewport, console, and network states. For
performance claims, compare the same workload and environment before and after; report the
metric, sampling method, and variance.

Completion reports state delivered behavior, changed paths or boundaries, commands/interactions
and outcomes, checks not run, and residual uncertainty.
