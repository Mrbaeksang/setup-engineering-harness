<!-- engineering-harness:installer-owned -->
# Compact specs and vertical slices

Do not re-interview the user after the conversation already establishes an answer. Synthesize the
current conversation and repository evidence into the smallest plan that makes implementation
safe.

For medium work, keep a compact spec in the conversation:

- outcome and observable acceptance;
- exclusions and explicit assumptions;
- affected behavior and boundaries;
- exact stack/version facts and researched API decisions;
- verification seams.

For large multi-context work, split the spec into tracer-bullet vertical slices. Each slice should
deliver a thin end-to-end piece of user-visible behavior, include its own verification, and leave
the Project coherent. Prefer slices such as “one playable loop from input to saved result” over
horizontal tickets such as “build all models” or “build all UI.”

Create repository documents or external tickets only when the work must survive context changes,
cross people or systems, or be scheduled independently. Show the proposed slices and obtain user
agreement before publishing tickets or making a hard-to-reverse architecture choice.
