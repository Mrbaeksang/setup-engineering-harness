<!-- engineering-harness:installer-owned -->
# Core workflow

## Establish the Task

- Restate the requested outcome, observable acceptance, and explicit exclusions.
- Inspect bounded repository facts before asking the user.
- Keep unrelated cleanup, upgrades, formatting, and refactors out of scope.
- Prefer existing Project and platform capabilities over new abstractions or dependencies.

## Read efficiently

Map filenames, manifests, symbols, callers, and tests before opening implementation bodies. Read
the smallest source slices that establish the change surface and verification path. Expand only
along evidence-backed references. Avoid full-tree dumps, generated output, vendored code, broad
dependency reads, and unrelated history.

## Open the write Gate only when ready

Before writing, establish:

- outcome and acceptance evidence;
- resolved user decisions or an explicit reversible assumption;
- exact dependency evidence when routed;
- expected paths and boundaries;
- proportionate verification.

The first user turn is discovery-locked. Use the injected exact `set-acceptance` broker prefix to
submit a structured outcome, mechanically observable criteria, exclusions, assumptions, and the
current Task revision/user-provenance hash. A raw prompt is never the acceptance contract.
Encode each value as one hyphenated shell token; never add spaces, quotes, escapes, semicolons, or
other shell punctuation. Include a registered proof kind or verification ID such as `test`,
`build`, `typecheck`, or `lint` in every criterion token.
Write acceptance criteria as externally visible outcomes and map each one to registered proof.
Put implementation mechanisms, preferred APIs, and library-option choices in the plan or
assumptions rather than inventing a second source-level acceptance criterion. If the host reports
an unrun verification decision before any Write Lease exists, replace the same-provenance draft
with a proof-mapped contract; do not ask the user to adjudicate an agent-authored drafting error.
Resolve a pending decision only against a later recorded user answer. If discovery widens the
scope, revise acceptance before requesting a scoped Write Lease.

Use only exact protected lifecycle commands. Supply safe project-relative scope globs, registered
verification IDs, and regular-file Evidence with a precise kind. Treat
`awaiting-user-approval` and `decision-required` as closed Gate states; only `lease-issued` permits
native writes. Ask the user to send exactly `approve PROPOSAL-ID`; the UserPrompt hook records that
provenance and invokes approval. Never invoke `approve` through a Coding Agent shell.

Any new user prompt revokes the current lease. `continue` keeps the Task identity but advances its
revision; `new task: …` explicitly abandons a pending Task. Request or renew a lease after the
revised contract is bound.

## Implement narrowly

Match established style and boundaries. Make the smallest coherent change. Preserve compatibility
unless the Task explicitly changes it. Keep claims tied to paths, exact versions, commands, diffs,
or observed UI/measurements.
