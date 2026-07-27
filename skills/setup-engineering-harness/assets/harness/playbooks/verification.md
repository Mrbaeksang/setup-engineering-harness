<!-- engineering-harness:installer-owned -->
# Evidence-based verification

Never claim a check passed unless it ran and its result was observed.
While discovery-locked, inspect only bounded facts: establish acceptance and obtain the scoped
Write Lease before invoking the verification broker. Then reproduce the baseline before editing.

1. Reproduce the failure or establish a comparable baseline when feasible.
2. Run the narrowest check that exercises changed public behavior and boundary failures.
3. Run nearby repository-native test, type, lint, build, integration, or format checks in
   proportion to risk.
4. Inspect the diff for scope, surrounding style, debug artifacts, generated noise, and secret
   exposure through the injected context-broker `git-status` and `git-diff` commands. Preserve
   existing indentation and formatting unless changing them is part of the Task.
5. Run the Harness audit after Harness or instruction changes. Do not run it for an ordinary
   application-code change.

`repo-profile.json` commands are candidates, not proof or authority. A Write Lease may authorize
only the exact protected broker shape
`<approved-python> <project>/.agent-harness/bin/run_verification.py run <id>`. Never put a raw
package/build command in `allowedCommands`, add prefixes or suffixes, redirect output, or run the
broker outside the Project root.

On success, the broker records a host receipt bound to the exact disposable snapshot input and
the unchanged live implementation hash. Passing output alone is not a receipt. When every
lease-required verification has a current receipt, the Task enters `verifying`; use the exact
protected lifecycle command `complete <lease-id>` to re-attest receipts and revoke the lease.
Use `renew <lease-id>` for rework; renewal revokes the old lease and re-evaluates approval rather
than extending stale authority.

Acceptance creates host-owned criterion IDs and a verification plan. Explicit test, build,
typecheck, lint, and format claims bind only to detected commands of the same kind. UI and
performance claims additionally bind to IDs in user-owned `verification.ui_flows` and
`verification.performance_scenarios`. The plan always includes user-owned
`verification.required_commands` and risk-required proof; agent-selected `verify=…` strings may
add checks but cannot remove these requirements. A claim without mapped proof closes the Decision
Gate. Only a later user prompt in the exact form
`skip DECISION-unrun-id: explicit reason` can record that claim as intentionally unrun. When every
claim is covered only by such decisions, completion still requires an observed in-scope change.

For UI changes, exercise the actual flow when a browser/native UI is available and inspect
loading, empty, error, success, focus, relevant viewports, console, and network states. For
performance claims, compare the same workload and environment before/after and report metric,
sampling method, and variance.

Report delivered behavior, changed paths/boundaries, commands or interactions and outcomes,
checks not run, and residual uncertainty.
