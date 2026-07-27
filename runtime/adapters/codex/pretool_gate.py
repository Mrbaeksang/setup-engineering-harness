"""Codex ``PreToolUse`` adapter backed by an authoritative state file.

The state file must live outside the agent-writable Project and be protected by
the host/provider boundary.  Filesystem location alone is not a security
boundary against an agent process running as the same OS user; deployments
must add permissions, sandboxing, or a privileged broker appropriate to their
threat model.  This adapter constrains only tool calls that Codex routes through
``PreToolUse``; provider-exempt or specialized execution paths require their
own equivalent capability boundary.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path, PurePath
from typing import Any, Callable, Mapping, TextIO

from runtime.application.lease_lifecycle import (
    active_lease_attestation,
    is_lease_request_command,
)
from runtime.domain.gate import (
    ActionKind,
    GateAction,
    GateDecision,
    GateState,
    PathFact,
    StateValidationError,
    evaluate_gate,
    is_verification_broker_command,
    parse_gate_state,
)
from runtime.ports.gate_state_source import GateStateReadError, GateStateSource


READ_BROKER_RELATIVE_PATH = Path(".agent-harness/bin/read_context.py")
READ_BROKER_VERBS = frozenset(
    {
        "map",
        "read",
        "search",
        "facts",
        "git-status",
        "git-diff",
        "dependency-read",
        "dependency-search",
    }
)
_SAFE_BROKER_ARGUMENT = re.compile(r"[A-Za-z0-9_./:@%+=,-]+\Z")
STATE_PATH_ENV = "ENGINEERING_HARNESS_GATE_STATE"
READ_ONLY_RESEARCH_TOOLS_ENV = (
    "ENGINEERING_HARNESS_READ_ONLY_RESEARCH_TOOLS"
)
MAX_STATE_BYTES = 1_048_576

_NATIVE_PATH_TOOLS = frozenset({"Edit", "Write", "edit", "write"})
_MULTI_EDIT_TOOLS = frozenset({"MultiEdit", "multi_edit"})
_PATCH_TOOLS = frozenset({"apply_patch", "ApplyPatch"})
_SHELL_TOOLS = frozenset(
    {
        "Bash",
        "Shell",
        "exec",
        "exec_command",
        "local_shell",
        "shell",
        "shell_command",
    }
)
_PATCH_PATH_PREFIXES = (
    "*** Add File: ",
    "*** Update File: ",
    "*** Delete File: ",
    "*** Move to: ",
)
_TOOL_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,200}\Z")
_MUTATING_TOOL_BASENAMES = frozenset(
    {
        "apply_patch",
        "bash",
        "edit",
        "exec",
        "exec_command",
        "local_shell",
        "multi_edit",
        "shell",
        "shell_command",
        "write",
    }
)


@dataclass(frozen=True, slots=True)
class FileGateStateSource:
    path: Path
    max_bytes: int = MAX_STATE_BYTES

    def read(self) -> bytes:
        descriptor: int | None = None
        try:
            if not self.path.is_absolute():
                raise GateStateReadError("Gate state path must be absolute.")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise GateStateReadError("Gate state must be a regular file.")
            if metadata.st_size > self.max_bytes:
                raise GateStateReadError("Gate state exceeds the size limit.")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = None
                payload = stream.read(self.max_bytes + 1)
        except GateStateReadError:
            raise
        except OSError as error:
            raise GateStateReadError(
                f"Gate state is missing or unreadable: {error}"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if len(payload) > self.max_bytes:
            raise GateStateReadError("Gate state exceeds the size limit.")
        return payload


@dataclass(slots=True)
class CodexGateAdapter:
    state_source: GateStateSource
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    read_only_research_tools: frozenset[str] = frozenset()

    def evaluate_payload(self, payload: Any) -> GateDecision:
        try:
            state = load_gate_state(self.state_source)
        except (GateStateReadError, StateValidationError, OSError) as error:
            return GateDecision.deny(
                "invalid-state", f"Gate state is unavailable or invalid: {error}"
            )

        try:
            action = action_from_codex_payload(
                payload,
                state,
                read_only_research_tools=self.read_only_research_tools,
            )
            now = self.clock()
            decision = evaluate_gate(state, action, now=now)
            if (
                decision.allowed
                and action.kind
                in {ActionKind.NATIVE_WRITE, ActionKind.VERIFICATION_COMMAND}
            ):
                drift = active_lease_attestation(
                    state,
                    now=now,
                    state_path=(
                        self.state_source.path
                        if isinstance(
                            self.state_source, FileGateStateSource
                        )
                        else None
                    ),
                )
                if drift is not None:
                    return GateDecision.deny(
                        "runtime-attestation-failed",
                        f"Write Lease no longer matches actual Project state: {drift}.",
                    )
            return decision
        except Exception as error:
            return GateDecision.deny(
                "adapter-failure",
                f"PreToolUse request could not be validated: {type(error).__name__}.",
            )

    def hook_response(self, payload: Any) -> dict[str, Any]:
        decision = self.evaluate_payload(payload)
        if decision.allowed:
            return allow_hook_response()
        return deny_hook_response(decision.reason)


def load_gate_state(state_source: GateStateSource) -> GateState:
    """Load one canonical state snapshot for any Codex hook adapter.

    A ``UserPromptSubmit`` adapter can use this function with
    ``evaluate_write_lease`` to report the same locked/open semantics as this
    ``PreToolUse`` adapter.
    """

    state = parse_gate_state(state_source.read())
    canonical_root = Path(state.project_root).resolve(strict=False)
    if isinstance(state_source, FileGateStateSource):
        lexical_state_path = Path(os.path.abspath(state_source.path))
        canonical_state_path = state_source.path.resolve(strict=False)
        if _is_relative_to(
            lexical_state_path, canonical_root
        ) or _is_relative_to(canonical_state_path, canonical_root):
            raise GateStateReadError(
                "Authoritative Gate state must be outside the writable Project."
            )
    return replace(state, project_root=PurePath(canonical_root))


def action_from_codex_payload(
    payload: Any,
    state: GateState,
    *,
    read_only_research_tools: frozenset[str] = frozenset(),
) -> GateAction:
    if not isinstance(payload, dict):
        return GateAction(
            tool_name="<missing>",
            kind=ActionKind.UNKNOWN,
            invalid_reason="hook payload must be an object",
        )
    if payload.get("hook_event_name") != "PreToolUse":
        return GateAction(
            tool_name="<wrong-event>",
            kind=ActionKind.UNKNOWN,
            invalid_reason="hook_event_name must be exactly PreToolUse",
        )
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    cwd = payload.get("cwd")
    if not isinstance(tool_name, str) or not tool_name:
        return GateAction(
            tool_name="<missing>",
            kind=ActionKind.UNKNOWN,
            invalid_reason="tool_name must be a non-empty string",
        )
    if not isinstance(tool_input, dict):
        return GateAction(
            tool_name=tool_name,
            kind=ActionKind.UNKNOWN,
            invalid_reason="tool_input must be an object",
        )
    if not isinstance(cwd, str) or not cwd or "\0" in cwd:
        return GateAction(
            tool_name=tool_name,
            kind=ActionKind.UNKNOWN,
            invalid_reason="cwd must be a non-empty path",
        )

    project_root = Path(state.project_root).resolve(strict=False)
    working_directory = Path(cwd).resolve(strict=False)
    if not _is_relative_to(working_directory, project_root):
        return GateAction(
            tool_name=tool_name,
            kind=ActionKind.UNKNOWN,
            invalid_reason="hook cwd is outside the Project",
        )

    if tool_name in _SHELL_TOOLS:
        command_field = "cmd" if tool_name == "exec_command" else "command"
        command = tool_input.get(command_field)
        if (
            len(tool_input) == 1
            and isinstance(command, str)
            and is_read_broker_command(command, state)
        ):
            return GateAction(tool_name=tool_name, kind=ActionKind.READ_BROKER)
        if (
            len(tool_input) == 1
            and isinstance(command, str)
            and is_lease_request_command(command, state)
        ):
            return GateAction(
                tool_name=tool_name, kind=ActionKind.LEASE_REQUEST
            )
        if (
            len(tool_input) == 1
            and isinstance(command, str)
            and state.write_lease is not None
            and command in state.write_lease.allowed_commands
            and working_directory == project_root
            and is_verification_broker_command(state, command)
        ):
            return GateAction(
                tool_name=tool_name,
                kind=ActionKind.VERIFICATION_COMMAND,
                command=command,
                working_directory=PurePath(working_directory),
            )
        return GateAction(tool_name=tool_name, kind=ActionKind.SHELL_EXECUTION)

    if tool_name in _NATIVE_PATH_TOOLS:
        path_value = _one_path_value(tool_input)
        if path_value is None:
            return GateAction(
                tool_name=tool_name,
                kind=ActionKind.NATIVE_WRITE,
                invalid_reason="native write has no single string path",
            )
        return GateAction(
            tool_name=tool_name,
            kind=ActionKind.NATIVE_WRITE,
            paths=(_path_fact(path_value, working_directory),),
        )

    if tool_name in _MULTI_EDIT_TOOLS:
        edits = tool_input.get("edits")
        if not isinstance(edits, list) or not edits:
            return GateAction(
                tool_name=tool_name,
                kind=ActionKind.NATIVE_WRITE,
                invalid_reason="multi-edit has no edits",
            )
        top_level_path = _one_path_value(tool_input)
        paths: list[PathFact] = []
        item_paths: list[str] = []
        for edit in edits:
            if not isinstance(edit, dict):
                return GateAction(
                    tool_name=tool_name,
                    kind=ActionKind.NATIVE_WRITE,
                    invalid_reason="multi-edit item is not an object",
                )
            item_path = _one_path_value(edit)
            if item_path is not None:
                item_paths.append(item_path)
        if top_level_path is not None and item_paths:
            return GateAction(
                tool_name=tool_name,
                kind=ActionKind.NATIVE_WRITE,
                invalid_reason="multi-edit has ambiguous top-level and item paths",
            )
        if top_level_path is not None:
            paths.append(_path_fact(top_level_path, working_directory))
        elif len(item_paths) == len(edits):
            paths.extend(
                _path_fact(path, working_directory) for path in item_paths
            )
        else:
            return GateAction(
                tool_name=tool_name,
                kind=ActionKind.NATIVE_WRITE,
                invalid_reason="multi-edit paths are incomplete",
            )
        return GateAction(
            tool_name=tool_name,
            kind=ActionKind.NATIVE_WRITE,
            paths=tuple(paths),
        )

    if tool_name in _PATCH_TOOLS:
        patch_fields = [
            value
            for key in ("command", "patch")
            if isinstance((value := tool_input.get(key)), str)
        ]
        patch = patch_fields[0] if len(patch_fields) == 1 else None
        if not isinstance(patch, str):
            return GateAction(
                tool_name=tool_name,
                kind=ActionKind.NATIVE_WRITE,
                invalid_reason="patch payload is missing",
            )
        requested_paths = _extract_patch_paths(patch)
        if not requested_paths:
            return GateAction(
                tool_name=tool_name,
                kind=ActionKind.NATIVE_WRITE,
                invalid_reason="patch contains no recognized file path",
            )
        return GateAction(
            tool_name=tool_name,
            kind=ActionKind.NATIVE_WRITE,
            paths=tuple(
                _path_fact(path, working_directory) for path in requested_paths
            ),
        )

    if tool_name in read_only_research_tools:
        return GateAction(
            tool_name=tool_name,
            kind=ActionKind.READ_ONLY_RESEARCH,
        )

    return GateAction(tool_name=tool_name, kind=ActionKind.UNKNOWN)


def allow_hook_response() -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}


def deny_hook_response(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def build_read_broker_command(
    state: GateState,
    verb: str,
    *arguments: str,
    python_executable: PurePath | None = None,
) -> str:
    """Build the sole canonical shell shape accepted for the read broker."""

    if verb not in READ_BROKER_VERBS:
        raise ValueError(f"unsupported read broker verb: {verb!r}")
    if any(_SAFE_BROKER_ARGUMENT.fullmatch(item) is None for item in arguments):
        raise ValueError("read broker arguments must be shell-inert tokens")
    executable = python_executable or state.read_broker_python_executables[0]
    if executable not in state.read_broker_python_executables:
        raise ValueError("Python executable is not host-state approved")
    broker = state.project_root.joinpath(READ_BROKER_RELATIVE_PATH)
    return shlex.join(
        [str(executable), str(broker), verb, *arguments]
    )


def is_read_broker_command(command: str, state: GateState) -> bool:
    """Recognize only canonical broker argv with no shell interpretation."""

    if "\0" in command or "\n" in command or "\r" in command:
        return False
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return False
    if len(arguments) < 3:
        return False
    try:
        executable = PurePath(arguments[0])
        broker = PurePath(arguments[1])
    except (TypeError, ValueError):
        return False
    if executable not in state.read_broker_python_executables:
        return False
    expected_broker = state.project_root.joinpath(READ_BROKER_RELATIVE_PATH)
    if broker != expected_broker:
        return False
    if arguments[2] not in READ_BROKER_VERBS:
        return False
    if any(
        _SAFE_BROKER_ARGUMENT.fullmatch(item) is None
        for item in arguments[3:]
    ):
        return False
    return command == shlex.join(arguments)


def _extract_patch_paths(patch: str) -> tuple[str, ...]:
    paths: list[str] = []
    for line in patch.splitlines():
        for prefix in _PATCH_PATH_PREFIXES:
            if line.startswith(prefix):
                path = line.removeprefix(prefix)
                if not path or "\0" in path or path != path.strip():
                    return ()
                paths.append(path)
                break
    return tuple(paths)


def _one_path_value(tool_input: dict[str, Any]) -> str | None:
    values = [
        value
        for key in ("file_path", "path")
        if isinstance((value := tool_input.get(key)), str)
    ]
    return values[0] if len(values) == 1 else None


def _path_fact(requested: str, cwd: Path) -> PathFact:
    if not requested or "\0" in requested:
        raise ValueError("write path is empty or contains NUL")
    candidate = Path(requested)
    lexical = (
        Path(os.path.abspath(candidate))
        if candidate.is_absolute()
        else Path(os.path.abspath(cwd / candidate))
    )
    resolved = lexical.resolve(strict=False)
    return PathFact(
        requested=requested,
        lexical_path=PurePath(lexical),
        resolved_path=PurePath(resolved),
    )


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _load_stdin(stream: TextIO) -> Any:
    try:
        return json.load(stream)
    except (json.JSONDecodeError, UnicodeError) as error:
        return {"_malformed_hook_input": str(error)}


def configured_read_only_research_tools(
    environ: Mapping[str, str],
) -> frozenset[str]:
    raw = environ.get(READ_ONLY_RESEARCH_TOOLS_ENV, "[]")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(
            "read-only research tool allowlist is invalid JSON"
        ) from error
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError(
            "read-only research tool allowlist must be a bounded array"
        )
    result: set[str] = set()
    for item in value:
        if (
            not isinstance(item, str)
            or _TOOL_NAME.fullmatch(item) is None
            or item in result
        ):
            raise ValueError(
                "read-only research tool allowlist contains an invalid name"
            )
        basename = re.split(r"__|\.", item)[-1].casefold()
        if basename in _MUTATING_TOOL_BASENAMES:
            raise ValueError(
                "mutating or execution tools cannot be research-allowlisted"
            )
        result.add(item)
    return frozenset(result)


def main(
    *,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    environ: Mapping[str, str] = os.environ,
) -> int:
    payload = _load_stdin(stdin)
    state_path = environ.get(STATE_PATH_ENV)
    try:
        research_tools = configured_read_only_research_tools(environ)
    except ValueError as error:
        response = deny_hook_response(
            f"Read-only research tool configuration is invalid: {error}."
        )
    else:
        response = None
    if response is not None:
        pass
    elif not state_path:
        response = deny_hook_response(
            f"{STATE_PATH_ENV} is missing; Gate fails closed."
        )
    else:
        adapter = CodexGateAdapter(
            FileGateStateSource(Path(state_path)),
            read_only_research_tools=research_tools,
        )
        response = adapter.hook_response(payload)
    json.dump(response, stdout, separators=(",", ":"), sort_keys=True)
    stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
