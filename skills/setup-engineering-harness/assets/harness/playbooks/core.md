<!-- engineering-harness:installer-owned -->
# Adaptive core workflow

## Understand before choosing

- Translate the request into the intended outcome, observable acceptance, explicit exclusions,
  and unresolved decisions.
- Inspect repository facts before asking questions the Project can answer.
- Ask only about answers that can materially change behavior, architecture, cost, security,
  external contracts, or hard-to-reverse work.
- Batch independent questions together. Sequence only dependent questions.
- Natural user confirmation is confirmation; never require magic phrases, IDs, hashes, or
  agent-specific syntax.

## Respect the Project

Map instructions, manifests, lockfiles, exact versions, source boundaries, callers, and tests
before opening broad implementation bodies. In an existing Project, prefer the current stack and
native capabilities when they satisfy the requirement. Do not add upgrades, abstractions,
formatting, or unrelated cleanup without a concrete reason in scope.

For greenfield work or an explicitly requested stack change, compare two or three current
candidates against the same explicit criteria. Criteria come from the product and operating
context—such as interaction model, performance, deployment, team familiarity, ecosystem,
accessibility, maintenance, and asset pipeline—not from the agent's favorite stack.

## Scale the process

- Small: proceed after a bounded inspection and a reversible assumption when no consequential
  question remains.
- Medium: keep a compact working spec in the conversation before implementation.
- Large: align requirements, research current options, obtain the user's product/architecture
  choice, then implement tracer-bullet vertical slices.

Keep claims tied to paths, exact versions, primary sources, commands, diffs, observed UI, or
measurements. Expand exploration only along evidence-backed references.
