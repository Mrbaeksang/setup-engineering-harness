"""Pure Gate state parsing and authorization policy.

The caller supplies already-resolved path facts and the current time.  This
module performs no filesystem, environment, clock, or process access.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import PurePath
from typing import Any


SCHEMA_VERSION = 1
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_WRITE_PHASES = frozenset({"ready-to-write", "implementing"})
_LEASE_PHASES = frozenset({"ready-to-write", "implementing", "verifying"})
VERIFICATION_BROKER_RELATIVE_PATH = PurePath(
    ".agent-harness/bin/run_verification.py"
)
MINIMUM_PROTECTED_GLOBS = (
    ".env*",
    "**/.env*",
    ".git",
    ".git/**",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/credentials",
    "**/credentials.json",
    "**/credentials.yaml",
    "**/credentials.yml",
    "**/credentials.toml",
    "**/secrets.json",
    "**/secrets.yaml",
    "**/secrets.yml",
    "**/secrets.toml",
    "**/tokens.json",
    "**/auth.json",
    "**/service-account.json",
    "**/.netrc",
    "**/.npmrc",
    "**/.pypirc",
    "**/id_rsa",
    "**/id_ed25519",
    "**/*private-key*.txt",
    "**/*private_key*.txt",
    "**/*private-key*.json",
    "**/*private_key*.json",
    "**/*private-key*.yaml",
    "**/*private_key*.yaml",
    "**/*private-key*.yml",
    "**/*private_key*.yml",
    ".agent-harness",
    ".agent-harness/**",
    "node_modules",
    "node_modules/**",
    "**/node_modules",
    "**/node_modules/**",
    "vendor",
    "vendor/**",
    "**/vendor",
    "**/vendor/**",
    ".venv",
    ".venv/**",
    "**/.venv",
    "**/.venv/**",
    "site-packages",
    "site-packages/**",
    "**/site-packages",
    "**/site-packages/**",
    "dist-packages",
    "dist-packages/**",
    "**/dist-packages",
    "**/dist-packages/**",
    "package.json",
    "**/package.json",
    "package-lock.json",
    "**/package-lock.json",
    "npm-shrinkwrap.json",
    "**/npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "**/pnpm-lock.yaml",
    "yarn.lock",
    "**/yarn.lock",
    "bun.lock",
    "**/bun.lock",
    "bun.lockb",
    "**/bun.lockb",
    "pyproject.toml",
    "**/pyproject.toml",
    "requirements.txt",
    "**/requirements.txt",
    "uv.lock",
    "**/uv.lock",
    "poetry.lock",
    "**/poetry.lock",
    "Pipfile.lock",
    "**/Pipfile.lock",
    "Cargo.toml",
    "**/Cargo.toml",
    "Cargo.lock",
    "**/Cargo.lock",
    "go.mod",
    "**/go.mod",
    "go.sum",
    "**/go.sum",
    "Gemfile",
    "**/Gemfile",
    "Gemfile.lock",
    "**/Gemfile.lock",
    "pom.xml",
    "**/pom.xml",
    "build.gradle",
    "**/build.gradle",
    "build.gradle.kts",
    "**/build.gradle.kts",
)
_ALL_PHASES = frozenset(
    {
        "received",
        "discovery",
        "discovery-locked",
        "decision-required",
        "research-required",
        "ready-to-write",
        "implementing",
        "verifying",
        "complete",
        "blocked",
        "overridden",
    }
)


class StateValidationError(ValueError):
    """The authoritative host state is absent from the policy due to bad data."""


class ActionKind(Enum):
    READ_BROKER = "read-broker"
    READ_ONLY_RESEARCH = "read-only-research"
    LEASE_REQUEST = "lease-request"
    NATIVE_WRITE = "native-write"
    VERIFICATION_COMMAND = "verification-command"
    SHELL_EXECUTION = "shell-execution"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EvidenceHash:
    id: str
    kind: str
    source_path: str
    content_hash: str


@dataclass(frozen=True, slots=True)
class WriteLease:
    id: str
    task_id: str
    project_id: str
    base_tree_hash: str
    acceptance_hash: str
    issued_for_evidence_hash: str
    issued_for_state_hash: str
    issued_at: datetime
    expires_at: datetime
    allowed_globs: tuple[str, ...]
    allowed_commands: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GateState:
    task_id: str
    project_id: str
    project_root: PurePath
    read_broker_python_executables: tuple[PurePath, ...]
    protected_globs: tuple[str, ...]
    base_tree_hash: str
    acceptance_hash: str
    phase: str
    evidence: tuple[EvidenceHash, ...]
    pending_decisions: tuple[str, ...]
    write_lease: WriteLease | None


@dataclass(frozen=True, slots=True)
class PathFact:
    """One requested path before and after filesystem canonicalization."""

    requested: str
    lexical_path: PurePath
    resolved_path: PurePath


@dataclass(frozen=True, slots=True)
class GateAction:
    tool_name: str
    kind: ActionKind
    paths: tuple[PathFact, ...] = ()
    command: str | None = None
    working_directory: PurePath | None = None
    invalid_reason: str | None = None


@dataclass(frozen=True, slots=True)
class GateDecision:
    allowed: bool
    code: str
    reason: str

    @classmethod
    def allow(cls, code: str, reason: str) -> "GateDecision":
        return cls(True, code, reason)

    @classmethod
    def deny(cls, code: str, reason: str) -> "GateDecision":
        return cls(False, code, reason)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise StateValidationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def parse_gate_state(raw: bytes | str) -> GateState:
    """Parse the complete versioned host-state contract or reject it."""

    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    except UnicodeDecodeError as error:
        raise StateValidationError("state is not UTF-8") from error

    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, StateValidationError) as error:
        raise StateValidationError(f"state is not valid JSON: {error}") from error

    root = _mapping(value, "state")
    _exact_keys(
        root,
        {
            "schemaVersion",
            "taskId",
            "projectId",
            "projectRoot",
            "readBrokerPythonExecutables",
            "protectedGlobs",
            "baseTreeHash",
            "acceptanceHash",
            "phase",
            "evidence",
            "pendingDecisions",
            "writeLease",
        },
        "state",
    )
    schema_version = root["schemaVersion"]
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        raise StateValidationError(
            f"unsupported schemaVersion: {schema_version!r}"
        )

    task_id = _identifier(root["taskId"], "taskId")
    project_id = _identifier(root["projectId"], "projectId")
    project_root = _absolute_path(root["projectRoot"], "projectRoot")
    python_values = _list(
        root["readBrokerPythonExecutables"],
        "readBrokerPythonExecutables",
    )
    read_broker_python_executables = tuple(
        _python_executable(
            item, f"readBrokerPythonExecutables[{index}]"
        )
        for index, item in enumerate(python_values)
    )
    if not read_broker_python_executables:
        raise StateValidationError(
            "readBrokerPythonExecutables must not be empty"
        )
    _unique(
        (str(item) for item in read_broker_python_executables),
        "read broker Python executables",
    )
    protected_values = _list(root["protectedGlobs"], "protectedGlobs")
    protected_globs = tuple(
        _glob(item, f"protectedGlobs[{index}]")
        for index, item in enumerate(protected_values)
    )
    _unique(iter(protected_globs), "protected globs")
    base_tree_hash = _digest(root["baseTreeHash"], "baseTreeHash")
    acceptance_hash = _digest(root["acceptanceHash"], "acceptanceHash")
    phase = _string(root["phase"], "phase")
    if phase not in _ALL_PHASES:
        raise StateValidationError(f"unknown phase: {phase!r}")

    evidence_values = _list(root["evidence"], "evidence")
    evidence = tuple(
        _parse_evidence(item, index) for index, item in enumerate(evidence_values)
    )
    _unique((item.id for item in evidence), "evidence ids")

    pending_values = _list(root["pendingDecisions"], "pendingDecisions")
    pending_decisions = tuple(
        _identifier(item, f"pendingDecisions[{index}]")
        for index, item in enumerate(pending_values)
    )
    _unique(iter(pending_decisions), "pending decisions")

    lease_value = root["writeLease"]
    write_lease = (
        None if lease_value is None else _parse_write_lease(lease_value)
    )

    return GateState(
        task_id=task_id,
        project_id=project_id,
        project_root=project_root,
        read_broker_python_executables=read_broker_python_executables,
        protected_globs=protected_globs,
        base_tree_hash=base_tree_hash,
        acceptance_hash=acceptance_hash,
        phase=phase,
        evidence=evidence,
        pending_decisions=pending_decisions,
        write_lease=write_lease,
    )


def evidence_set_hash(evidence: tuple[EvidenceHash, ...]) -> str:
    """Return a stable digest of evidence identity and content."""

    payload = bytearray()
    for item in sorted(evidence, key=lambda candidate: candidate.id):
        payload.extend(item.id.encode("utf-8"))
        payload.extend(b"\0")
        payload.extend(item.kind.encode("utf-8"))
        payload.extend(b"\0")
        payload.extend(item.source_path.encode("utf-8"))
        payload.extend(b"\0")
        payload.extend(item.content_hash.encode("ascii"))
        payload.extend(b"\n")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def lease_state_hash(state: GateState) -> str:
    """Bind a lease to the complete authorization-relevant state."""

    payload = {
        "acceptanceHash": state.acceptance_hash,
        "baseTreeHash": state.base_tree_hash,
        "evidenceHash": evidence_set_hash(state.evidence),
        "pendingDecisions": list(state.pending_decisions),
        "projectId": state.project_id,
        "taskId": state.task_id,
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def validate_safe_glob(value: str) -> str:
    """Validate and normalize one project-relative lease glob."""

    return _glob(value, "allowed scope")


def safe_glob_matches(pattern: str, path: str) -> bool:
    """Match a previously validated project-relative glob."""

    return _glob_matches(pattern, path)


def evaluate_gate(
    state: GateState,
    action: GateAction,
    *,
    now: datetime,
) -> GateDecision:
    """Evaluate a tool action against a valid state snapshot."""

    if now.tzinfo is None or now.utcoffset() is None:
        return GateDecision.deny(
            "invalid-clock", "Gate clock must be timezone-aware."
        )

    if action.invalid_reason is not None:
        return GateDecision.deny(
            "malformed-action",
            f"Tool request could not be validated: {action.invalid_reason}",
        )

    if action.kind is ActionKind.READ_BROKER:
        return GateDecision.allow(
            "read-broker", "Exact read-only broker invocation is allowed."
        )
    if action.kind is ActionKind.READ_ONLY_RESEARCH:
        return GateDecision.allow(
            "read-only-research",
            "Explicitly configured read-only research tool is allowed.",
        )
    if action.kind is ActionKind.LEASE_REQUEST:
        return GateDecision.allow(
            "lease-request",
            "Exact protected lifecycle broker invocation is allowed.",
        )
    if action.kind is ActionKind.UNKNOWN:
        return GateDecision.deny(
            "unknown-tool",
            f"Tool {action.tool_name!r} has no fail-closed Gate policy.",
        )
    if action.kind is ActionKind.SHELL_EXECUTION:
        return GateDecision.deny(
            "unbrokered-execution",
            "Arbitrary shell and interpreter execution is not scope-safe; use a broker.",
        )
    if action.kind is not ActionKind.NATIVE_WRITE:
        if action.kind is not ActionKind.VERIFICATION_COMMAND:
            return GateDecision.deny("unknown-action", "Unknown Gate action kind.")

        lease_decision = evaluate_write_lease(state, now=now)
        if not lease_decision.allowed:
            return lease_decision
        lease = state.write_lease
        if lease is None:
            return GateDecision.deny("write-locked", "Write Lease is unavailable.")
        if action.working_directory != state.project_root:
            return GateDecision.deny(
                "verification-cwd",
                "Verification broker must run from the Project root.",
            )
        if (
            action.command is None
            or action.command not in lease.allowed_commands
            or not is_verification_broker_command(state, action.command)
        ):
            return GateDecision.deny(
                "command-not-allowed",
                "Verification must use an exact trusted broker command from the Write Lease.",
            )
        return GateDecision.allow(
            "verification-command",
            "Exact verification command is covered by the current Write Lease.",
        )

    if state.phase not in _WRITE_PHASES:
        return GateDecision.deny(
            "wrong-phase",
            f"Task phase {state.phase!r} does not permit native writes.",
        )
    lease_decision = evaluate_write_lease(state, now=now)
    if not lease_decision.allowed:
        return lease_decision

    lease = state.write_lease
    if lease is None:  # Narrowing for static analysis; policy above denied it.
        return GateDecision.deny("write-locked", "Write Lease is unavailable.")
    if not action.paths:
        return GateDecision.deny(
            "missing-write-path", "Native write request contains no validated path."
        )

    for path in action.paths:
        path_decision = _evaluate_path(state, lease, path)
        if path_decision is not None:
            return path_decision

    return GateDecision.allow(
        "scoped-write",
        "Native write paths are covered by the current Write Lease.",
    )


def evaluate_write_lease(
    state: GateState,
    *,
    now: datetime,
) -> GateDecision:
    """Report whether the current state has an active, internally valid lease."""

    if now.tzinfo is None or now.utcoffset() is None:
        return GateDecision.deny(
            "invalid-clock", "Gate clock must be timezone-aware."
        )

    lease = state.write_lease
    if lease is None:
        return GateDecision.deny(
            "write-locked", "No Write Lease authorizes repository mutation."
        )
    if state.phase not in _LEASE_PHASES:
        return GateDecision.deny(
            "wrong-phase",
            f"Task phase {state.phase!r} does not permit lease use.",
        )
    if state.pending_decisions:
        return GateDecision.deny(
            "pending-decisions",
            "A Write Lease cannot be used while user decisions remain pending.",
        )
    if not state.evidence:
        return GateDecision.deny(
            "missing-evidence",
            "A Write Lease cannot be used without bound Evidence.",
        )
    if lease.task_id != state.task_id or lease.project_id != state.project_id:
        return GateDecision.deny(
            "stale-lease-identity",
            "Write Lease does not belong to the current Task and Project.",
        )
    if lease.base_tree_hash != state.base_tree_hash:
        return GateDecision.deny(
            "stale-base-tree",
            "Write Lease was issued for a different base-tree hash.",
        )
    if lease.acceptance_hash != state.acceptance_hash:
        return GateDecision.deny(
            "stale-acceptance",
            "Write Lease was issued for a different acceptance contract.",
        )
    if lease.issued_for_evidence_hash != evidence_set_hash(state.evidence):
        return GateDecision.deny(
            "stale-evidence",
            "Write Lease was issued for a different Evidence set.",
        )
    if lease.issued_for_state_hash != lease_state_hash(state):
        return GateDecision.deny(
            "stale-state-binding",
            "Write Lease is not bound to the current Gate state.",
        )
    if now < lease.issued_at:
        return GateDecision.deny(
            "lease-not-active", "Write Lease issue time is in the future."
        )
    if now >= lease.expires_at:
        return GateDecision.deny("expired-lease", "Write Lease has expired.")
    return GateDecision.allow(
        "active-write-lease", "Write Lease is active and bound to current state."
    )


def is_verification_broker_command(state: GateState, command: str) -> bool:
    """Accept only ``python <protected broker> run <verification-id>``.

    A raw project command is not a safe capability even when its string is an
    exact match: its effects can depend on cwd and repository-controlled
    scripts. The trusted broker executes the registered command in isolation.
    """

    if "\0" in command or "\n" in command or "\r" in command:
        return False
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return False
    if len(arguments) != 4 or arguments[2] != "run":
        return False
    try:
        executable = PurePath(arguments[0])
        broker = PurePath(arguments[1])
    except (TypeError, ValueError):
        return False
    if executable not in state.read_broker_python_executables:
        return False
    expected = state.project_root.joinpath(VERIFICATION_BROKER_RELATIVE_PATH)
    if broker != expected:
        return False
    return _IDENTIFIER_PATTERN.fullmatch(arguments[3]) is not None


def _evaluate_path(
    state: GateState,
    lease: WriteLease,
    path: PathFact,
) -> GateDecision | None:
    if ".." in path.lexical_path.parts or ".." in path.resolved_path.parts:
        return GateDecision.deny(
            "path-traversal",
            f"Requested path {path.requested!r} is not normalized.",
        )
    lexical_relative = _relative_to(path.lexical_path, state.project_root)
    if lexical_relative is None:
        return GateDecision.deny(
            "path-traversal",
            f"Requested path {path.requested!r} escapes the Project.",
        )
    resolved_relative = _relative_to(path.resolved_path, state.project_root)
    if resolved_relative is None:
        return GateDecision.deny(
            "symlink-escape",
            f"Resolved path for {path.requested!r} escapes the Project.",
        )
    if not lexical_relative or not resolved_relative:
        return GateDecision.deny(
            "project-root-write", "A Write Lease cannot target the Project root."
        )

    protected_globs = MINIMUM_PROTECTED_GLOBS + state.protected_globs
    lexical_protected = any(
        _glob_matches(pattern.casefold(), lexical_relative.casefold())
        for pattern in protected_globs
    )
    resolved_protected = any(
        _glob_matches(pattern.casefold(), resolved_relative.casefold())
        for pattern in protected_globs
    )
    exact_dependency_approval = (
        _is_dependency_control_path(lexical_relative)
        and _is_dependency_control_path(resolved_relative)
        and lexical_relative == resolved_relative
        and lexical_relative in lease.allowed_globs
    )
    if (lexical_protected or resolved_protected) and not exact_dependency_approval:
        return GateDecision.deny(
            "protected-path",
            f"Path {path.requested!r} is protected from lease writes.",
        )

    lexical_allowed = any(
        _glob_matches(pattern, lexical_relative) for pattern in lease.allowed_globs
    )
    resolved_allowed = any(
        _glob_matches(pattern, resolved_relative) for pattern in lease.allowed_globs
    )
    if not lexical_allowed or not resolved_allowed:
        return GateDecision.deny(
            "out-of-scope",
            f"Path {path.requested!r} is outside the Write Lease globs.",
        )
    return None


def _is_dependency_control_path(path: str) -> bool:
    return PurePath(path).name.casefold() in {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "poetry.lock",
        "pipfile.lock",
        "cargo.toml",
        "cargo.lock",
        "go.mod",
        "go.sum",
        "gemfile",
        "gemfile.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
    }


def _parse_evidence(value: Any, index: int) -> EvidenceHash:
    item = _mapping(value, f"evidence[{index}]")
    _exact_keys(
        item,
        {"id", "kind", "sourcePath", "contentHash"},
        f"evidence[{index}]",
    )
    return EvidenceHash(
        id=_identifier(item["id"], f"evidence[{index}].id"),
        kind=_identifier(item["kind"], f"evidence[{index}].kind"),
        source_path=_relative_path(
            item["sourcePath"], f"evidence[{index}].sourcePath"
        ),
        content_hash=_digest(
            item["contentHash"], f"evidence[{index}].contentHash"
        ),
    )


def _parse_write_lease(value: Any) -> WriteLease:
    lease = _mapping(value, "writeLease")
    _exact_keys(
        lease,
        {
            "id",
            "taskId",
            "projectId",
            "baseTreeHash",
            "acceptanceHash",
            "issuedForEvidenceHash",
            "issuedForStateHash",
            "issuedAt",
            "expiresAt",
            "allowedGlobs",
            "allowedCommands",
        },
        "writeLease",
    )
    issued_at = _timestamp(lease["issuedAt"], "writeLease.issuedAt")
    expires_at = _timestamp(lease["expiresAt"], "writeLease.expiresAt")
    if expires_at <= issued_at:
        raise StateValidationError(
            "writeLease.expiresAt must be later than issuedAt"
        )
    glob_values = _list(lease["allowedGlobs"], "writeLease.allowedGlobs")
    allowed_globs = tuple(
        _glob(item, f"writeLease.allowedGlobs[{index}]")
        for index, item in enumerate(glob_values)
    )
    if not allowed_globs:
        raise StateValidationError("writeLease.allowedGlobs must not be empty")
    _unique(iter(allowed_globs), "write lease globs")
    command_values = _list(
        lease["allowedCommands"], "writeLease.allowedCommands"
    )
    allowed_commands = tuple(
        _command(item, f"writeLease.allowedCommands[{index}]")
        for index, item in enumerate(command_values)
    )
    _unique(iter(allowed_commands), "write lease commands")
    return WriteLease(
        id=_identifier(lease["id"], "writeLease.id"),
        task_id=_identifier(lease["taskId"], "writeLease.taskId"),
        project_id=_identifier(lease["projectId"], "writeLease.projectId"),
        base_tree_hash=_digest(
            lease["baseTreeHash"], "writeLease.baseTreeHash"
        ),
        acceptance_hash=_digest(
            lease["acceptanceHash"], "writeLease.acceptanceHash"
        ),
        issued_for_evidence_hash=_digest(
            lease["issuedForEvidenceHash"],
            "writeLease.issuedForEvidenceHash",
        ),
        issued_for_state_hash=_digest(
            lease["issuedForStateHash"],
            "writeLease.issuedForStateHash",
        ),
        issued_at=issued_at,
        expires_at=expires_at,
        allowed_globs=allowed_globs,
        allowed_commands=allowed_commands,
    )


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StateValidationError(f"{field} must be an object")
    return value


def _list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise StateValidationError(f"{field} must be an array")
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise StateValidationError(f"{field} must be a non-empty string")
    return value


def _identifier(value: Any, field: str) -> str:
    text = _string(value, field)
    if _IDENTIFIER_PATTERN.fullmatch(text) is None:
        raise StateValidationError(f"{field} is not a valid identifier")
    return text


def _digest(value: Any, field: str) -> str:
    text = _string(value, field)
    if _DIGEST_PATTERN.fullmatch(text) is None:
        raise StateValidationError(f"{field} must be a lowercase SHA-256 digest")
    return text


def _absolute_path(value: Any, field: str) -> PurePath:
    text = _string(value, field)
    if "\0" in text:
        raise StateValidationError(f"{field} contains a NUL byte")
    path = PurePath(text)
    if not path.is_absolute() or ".." in path.parts:
        raise StateValidationError(f"{field} must be a normalized absolute path")
    return path


def _python_executable(value: Any, field: str) -> PurePath:
    path = _absolute_path(value, field)
    if re.fullmatch(r"python3(?:\.\d+)?", path.name) is None:
        raise StateValidationError(
            f"{field} must name a Python 3 executable"
        )
    return path


def _timestamp(value: Any, field: str) -> datetime:
    text = _string(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise StateValidationError(f"{field} is not ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise StateValidationError(f"{field} must include a timezone")
    return parsed


def _glob(value: Any, field: str) -> str:
    pattern = _string(value, field).replace("\\", "/")
    parts = pattern.split("/")
    if (
        pattern.startswith("/")
        or pattern.endswith("/")
        or "\0" in pattern
        or any(part in {"", ".", ".."} for part in parts)
        or "[" in pattern
        or "]" in pattern
        or "{" in pattern
        or "}" in pattern
        or "***" in pattern
    ):
        raise StateValidationError(f"{field} is not a safe relative glob")
    return pattern


def _relative_path(value: Any, field: str) -> str:
    path = _string(value, field).replace("\\", "/")
    parts = path.split("/")
    if (
        path.startswith("/")
        or path.endswith("/")
        or "\0" in path
        or any(part in {"", ".", ".."} for part in parts)
        or any(character in path for character in "*?[]{}")
    ):
        raise StateValidationError(f"{field} is not a safe relative path")
    return path


def _command(value: Any, field: str) -> str:
    command = _string(value, field)
    if "\0" in command or not command.strip() or command != command.strip():
        raise StateValidationError(
            f"{field} must be a non-blank exact command"
        )
    return command


def _exact_keys(
    value: dict[str, Any], expected: set[str], field: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise StateValidationError(
            f"{field} keys differ; missing={missing}, extra={extra}"
        )


def _unique(values: Any, field: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise StateValidationError(f"{field} contain duplicate {value!r}")
        seen.add(value)


def _relative_to(path: PurePath, root: PurePath) -> str | None:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return None
    return relative.as_posix()


def _glob_matches(pattern: str, path: str) -> bool:
    """Match a validated slash-separated glob without letting ``*`` cross ``/``."""

    expression: list[str] = ["^"]
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            expression.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            expression.append(".*")
            index += 2
        elif pattern[index] == "*":
            expression.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            expression.append("[^/]")
            index += 1
        else:
            expression.append(re.escape(pattern[index]))
            index += 1
    expression.append("$")
    return re.fullmatch("".join(expression), path) is not None
