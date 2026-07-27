<!-- engineering-harness:installer-owned -->
# Proportional architecture

Use DDD language, cohesive modules, and ports/adapters as default reasoning tools, not mandatory
folder ceremony.

- Reuse canonical domain terms and locate business invariants with the concept that owns them.
- Separate capabilities that change for different reasons; expose the smallest stable contract.
- Point domain decisions inward. Isolate databases, filesystems, networks, clocks, queues, and
  vendors only when they are genuine external or volatile boundaries.
- Prefer a plain function or existing module when it expresses the behavior clearly.
- Do not invent aggregates, repositories, services, value objects, interfaces, or layers for
  trivial data movement.
- Respect existing boundaries unless the requested behavior and evidence justify a change.

For consequential cross-boundary work, identify domain terms, invariants, affected modules,
dependency direction, compatibility, migration, failure behavior, and contract tests. Update an
existing decision record only when the choice is durable and meaningfully traded off.
