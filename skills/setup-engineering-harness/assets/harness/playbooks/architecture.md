<!-- engineering-harness:installer-owned -->
# Proportional architecture

Start from the Project's established architecture. Use domain modeling, cohesive modules,
ports/adapters, functional core/imperative shell, data-oriented design, or another pattern only
when its tradeoffs fit the actual problem.

- Reuse canonical domain terms and locate invariants with the concept that owns them.
- Separate capabilities that change for different reasons; expose the smallest stable contract.
- Isolate databases, filesystems, networks, clocks, queues, and vendors when they are genuine
  external or volatile boundaries.
- Prefer a plain function or the existing module when it expresses the behavior clearly.
- Do not invent aggregates, repositories, services, interfaces, or layers for trivial movement
  of data.
- Respect existing boundaries unless requested behavior and evidence justify changing them.

For consequential cross-boundary work, identify terms, invariants, affected modules, dependency
direction, compatibility, migration, failure behavior, and contract tests. Record an ADR only
when the decision is durable, meaningfully traded off, and useful to future maintainers.
