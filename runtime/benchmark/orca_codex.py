"""Orca terminal adapter for live Codex benchmark executions.

Orca starts Codex in a fresh host-managed terminal. The benchmark never copies,
mounts, reads, or forwards provider credentials.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import threading
from typing import Any, Mapping, Sequence
import uuid


_LIVE_ROOT_PREFIX = "engineering-harness-live-"
_DISABLED_FEATURES = frozenset(
    {"apps", "multi_agent", "multi_agent_v2", "plugins", "skill_search"}
)
_FORBIDDEN_OPTIONS = frozenset(
    {
        "--add-dir",
        "--dangerously-bypass-approvals-and-sandbox",
        "--full-auto",
        "--output-last-message",
        "--output-schema",
        "--search",
    }
)
_MAX_PROVIDER_CAPTURE_BYTES = 1_000_000


class OrcaCodexError(RuntimeError):
    """Raised when Orca cannot preserve the benchmark execution boundary."""


@dataclass(frozen=True, slots=True)
class _RootCapability:
    device: int
    inode: int
    owner: int


@dataclass(frozen=True, slots=True)
class OrcaCodexExecutor:
    """Callable Codex executor using a supervised Orca terminal."""

    orca_binary: Path | str = "orca-ide"
    worktree_selector: str = "active"
    _authorized_roots: dict[Path, _RootCapability] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _authorization_lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        binary = Path(self.orca_binary)
        if binary.parent == Path("."):
            discovered = shutil.which(str(binary))
            if discovered is None:
                raise ValueError("Orca executable is not installed")
            binary = Path(discovered)
        binary = binary.expanduser().resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError("orca_binary must be an executable file")
        if not self.worktree_selector:
            raise ValueError("worktree_selector cannot be empty")
        object.__setattr__(self, "orca_binary", binary)

    def authorize_temporary_root(self, root: Path) -> None:
        if root.is_symlink():
            raise OrcaCodexError("benchmark temporary root cannot be a symlink")
        try:
            resolved = root.resolve(strict=True)
            status = resolved.stat()
        except OSError as error:
            raise OrcaCodexError(
                "benchmark temporary root must already exist"
            ) from error
        if (
            not resolved.is_dir()
            or not resolved.name.startswith(_LIVE_ROOT_PREFIX)
            or resolved.parent != Path(tempfile.gettempdir()).resolve()
            or status.st_uid != os.getuid()
        ):
            raise OrcaCodexError(
                "benchmark temporary root is not an owned adapter root"
            )
        capability = _RootCapability(
            device=status.st_dev,
            inode=status.st_ino,
            owner=status.st_uid,
        )
        with self._authorization_lock:
            self._authorized_roots[resolved] = capability

    def _workspace(self, cwd: Path) -> tuple[Path, Path]:
        try:
            resolved = cwd.resolve(strict=True)
            temporary_root = resolved.parent
            status = temporary_root.stat()
        except OSError as error:
            raise OrcaCodexError("benchmark workspace no longer exists") from error
        if resolved.name not in {"workspace", "provider-canary"}:
            raise OrcaCodexError("unexpected live benchmark workspace name")
        with self._authorization_lock:
            capability = self._authorized_roots.get(temporary_root)
        if capability is None or capability != _RootCapability(
            device=status.st_dev,
            inode=status.st_ino,
            owner=status.st_uid,
        ):
            raise OrcaCodexError("benchmark root lacks a valid host capability")
        return resolved, temporary_root

    @staticmethod
    def _fixed_provider_command(
        command: Sequence[str], *, cwd: Path, prompt: str
    ) -> list[str]:
        if (
            len(command) < 3
            or Path(command[0]).name != "codex"
            or command[1] != "exec"
            or command[-1] != "-"
            or command.count("-") != 1
        ):
            raise OrcaCodexError("expected fixed Codex exec stdin command")
        if any(option in command for option in _FORBIDDEN_OPTIONS):
            raise OrcaCodexError("unsafe Codex option is forbidden")
        required_switches = {"--json", "--ephemeral"}
        if not required_switches.issubset(command):
            raise OrcaCodexError("Codex command is missing benchmark switches")
        pairs: dict[str, list[str]] = {}
        index = 2
        disabled: set[str] = set()
        while index < len(command) - 1:
            option = command[index]
            if option in {"--json", "--ephemeral", "--dangerously-bypass-hook-trust"}:
                index += 1
                continue
            if index + 1 >= len(command) - 1:
                raise OrcaCodexError(f"missing value for Codex option: {option}")
            value = command[index + 1]
            pairs.setdefault(option, []).append(value)
            if option == "--disable":
                disabled.add(value)
            index += 2
        try:
            command_cwd = Path(pairs["--cd"][0]).resolve(strict=True)
        except (KeyError, IndexError, OSError) as error:
            raise OrcaCodexError("Codex --cd is missing or invalid") from error
        if (
            command_cwd != cwd
            or pairs.get("--sandbox") != ["workspace-write"]
            or pairs.get("--color") != ["never"]
            or pairs.get("--config", []).count(
                'shell_environment_policy.inherit="none"'
            )
            != 1
            or disabled != _DISABLED_FEATURES
        ):
            raise OrcaCodexError("Codex command changed a fixed benchmark control")
        allowed_options = {
            "--cd",
            "--color",
            "--config",
            "--disable",
            "--model",
            "--sandbox",
        }
        if any(option not in allowed_options for option in pairs):
            raise OrcaCodexError("Codex command contains an unsupported option")
        for config in pairs.get("--config", []):
            if not (
                config == 'shell_environment_policy.inherit="none"'
                or config.startswith("shell_environment_policy.set.PATH=")
            ):
                raise OrcaCodexError("Codex config override is not benchmark-owned")
        if "--dangerously-bypass-hook-trust" in command and not (
            cwd / ".codex" / "hooks.json"
        ).is_file():
            raise OrcaCodexError("hook trust bypass requires installed hooks")
        return [*command[:-1], prompt]

    def _orca(
        self, arguments: Sequence[str], *, timeout: int
    ) -> Mapping[str, Any]:
        result = subprocess.run(
            [str(self.orca_binary), *arguments, "--json"],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env={
                key: value
                for key, value in os.environ.items()
                if key
                in {
                    "HOME",
                    "LANG",
                    "LC_ALL",
                    "ORCA_CLI_COMMAND",
                    "ORCA_DEV_REPO_ROOT",
                    "PATH",
                    "TERM",
                    "TZ",
                }
            },
        )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise OrcaCodexError(
                f"Orca returned non-JSON output for {arguments[0]}"
            ) from error
        if not isinstance(payload, Mapping):
            raise OrcaCodexError("Orca response is not an object")
        return payload

    @staticmethod
    def _require_ok(payload: Mapping[str, Any], operation: str) -> Mapping[str, Any]:
        if payload.get("ok") is not True:
            error = payload.get("error")
            detail = (
                str(error.get("message", "unknown error"))
                if isinstance(error, Mapping)
                else "unknown error"
            )
            raise OrcaCodexError(f"Orca {operation} failed: {detail}")
        result = payload.get("result")
        if not isinstance(result, Mapping):
            raise OrcaCodexError(f"Orca {operation} omitted its result")
        return result

    @staticmethod
    def _bounded_read(path: Path) -> str:
        try:
            with path.open("rb") as handle:
                payload = handle.read(_MAX_PROVIDER_CAPTURE_BYTES + 1)
        except OSError:
            return ""
        if len(payload) > _MAX_PROVIDER_CAPTURE_BYTES:
            payload = payload[:_MAX_PROVIDER_CAPTURE_BYTES]
        return payload.decode("utf-8", errors="replace")

    def environment_identity(self) -> Mapping[str, Any]:
        binary = Path(self.orca_binary)
        return {
            "kind": "orca-host-terminal",
            "binary": binary.name,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "worktree_selector": self.worktree_selector,
            "credential_handling": "orca-host-authority",
            "host_isolation_attested": False,
        }

    def __call__(
        self,
        command: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        prompt: str,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        del env
        workspace, temporary_root = self._workspace(cwd)
        provider_command = self._fixed_provider_command(
            command, cwd=workspace, prompt=prompt
        )
        run_id = uuid.uuid4().hex
        stdout_path = temporary_root / f".orca-provider-{run_id}.stdout"
        stderr_path = temporary_root / f".orca-provider-{run_id}.stderr"
        status_path = temporary_root / f".orca-provider-{run_id}.status"
        title = f"STACK-CHIEF-BENCH-{run_id[:8]}"
        shell_command = (
            f"cd {shlex.quote(str(workspace))} && "
            f"{shlex.join(provider_command)} "
            f">{shlex.quote(str(stdout_path))} "
            f"2>{shlex.quote(str(stderr_path))}; "
            "_stack_chief_status=$?; "
            f"printf '%s' \"$_stack_chief_status\" "
            f">{shlex.quote(str(status_path))}; "
            'exit "$_stack_chief_status"'
        )
        created = self._require_ok(
            self._orca(
                [
                    "terminal",
                    "create",
                    "--worktree",
                    self.worktree_selector,
                    "--title",
                    title,
                    "--command",
                    shell_command,
                ],
                timeout=30,
            ),
            "terminal create",
        )
        terminal = created.get("terminal")
        handle = terminal.get("handle") if isinstance(terminal, Mapping) else None
        if not isinstance(handle, str) or not handle:
            raise OrcaCodexError("Orca terminal create omitted its handle")
        timed_out = False
        try:
            waited = self._orca(
                [
                    "terminal",
                    "wait",
                    "--terminal",
                    handle,
                    "--for",
                    "exit",
                    "--timeout-ms",
                    str(timeout * 1000),
                ],
                timeout=timeout + 10,
            )
            if waited.get("ok") is not True:
                error = waited.get("error")
                timed_out = (
                    isinstance(error, Mapping)
                    and error.get("code") == "timeout"
                )
                if not timed_out:
                    self._require_ok(waited, "terminal wait")
        finally:
            if timed_out:
                self._orca(
                    [
                        "terminal",
                        "send",
                        "--terminal",
                        handle,
                        "--interrupt",
                    ],
                    timeout=10,
                )
                self._orca(
                    ["terminal", "close", "--terminal", handle],
                    timeout=10,
                )

        stdout = self._bounded_read(stdout_path)
        stderr = self._bounded_read(stderr_path)
        try:
            exit_status = int(status_path.read_text(encoding="utf-8").strip())
        except (OSError, UnicodeError, ValueError):
            exit_status = 124 if timed_out else 1
        for path in (stdout_path, stderr_path, status_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        if timed_out:
            raise subprocess.TimeoutExpired(
                command, timeout, output=stdout, stderr=stderr
            )
        return subprocess.CompletedProcess(
            args=list(command),
            returncode=exit_status,
            stdout=stdout,
            stderr=stderr,
        )
