# Engineering Harness

## Language

**Coding Agent**:
The single AI the user talks to while working in a configured Project.

**Engineering Harness**:
The installed project behavior that guides the Coding Agent from conversation
through verified completion and applies only narrow configured safety
constraints.

**Setup Skill**:
The one-shot, idempotent skill that inspects a Project, asks only unresolved
project decisions, installs or repairs the Engineering Harness, and proves the
installation.
_Avoid_: Runtime agent, project generator

**Project**:
The source repository being configured by the Setup Skill.
_Avoid_: Session, task

**Task**:
One current user request handled by the Coding Agent from understanding through
verification.
_Avoid_: Project, chat session

**Managed Bridge**:
The small provider-discovered instruction block that routes the Coding Agent to
the relevant installed Playbooks.
_Avoid_: Full policy document

**Playbook**:
A focused procedure loaded only when the current Task matches its trigger.
_Avoid_: Always-loaded prompt, project history

**Gate**:
A mechanically enforced prerequisite controlling a specifically protected
action. In default assistive mode this is narrow; strict mode can opt into a
scoped write lifecycle.
_Avoid_: Reminder, suggestion, checklist

**Evidence**:
A provenance-bearing observation such as an exact version, source location,
command result, diff, or browser result that supports or refutes a claim.
_Avoid_: Agent assertion, unsupported summary

**Project Profile**:
Regenerable facts detected from repository manifests, lockfiles, scripts,
configuration, instructions, and structure.
_Avoid_: User preference, permanent documentation

**Context Pack**:
The bounded set of fresh, task-relevant facts, source slices, rules, and open
questions supplied to the Coding Agent.
_Avoid_: Repository dump, full session history

**Override**:
An explicit, scoped, expiring user authorization to bypass a non-safety Gate,
recorded with its reason.
_Avoid_: Environment-variable escape hatch, silent bypass
