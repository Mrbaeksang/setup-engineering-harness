#!/usr/bin/env python3
# engineering-harness:installer-owned
"""Run one registered verification command by exact stable identifier."""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import platform
import re
import resource
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import Any

IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
PROFILE = ".agent-harness/repo-profile.json"
MAX_SNAPSHOT_FILES = 100_000
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_CREATED_FILE_BYTES = 512 * 1024 * 1024
MAX_ADDRESS_SPACE_BYTES = 8 * 1024 * 1024 * 1024
MAX_ADDITIONAL_PROCESSES = 256
VERIFICATION_TIMEOUT_SECONDS = 600
_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_ADD_RULE = 445
_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_RET_K = 0x06
_SECCOMP_DATA_NR_OFFSET = 0
_SECCOMP_DATA_ARG0_OFFSET = 16
_AF_UNIX = 1

# Landlock ABI 1 write/topology rights. Read and execute are deliberately not
# handled: verification tools may read their runtimes, but can only mutate the
# disposable verification hierarchy.
_LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
_LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
_LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
_LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
_LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
_LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
_LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
_LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
_LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
_LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
_LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
_LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
_LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
_LANDLOCK_ACCESS_FS_REFER = 1 << 13
_LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
_LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0
_LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1
_LANDLOCK_READS = (
    _LANDLOCK_ACCESS_FS_EXECUTE
    | _LANDLOCK_ACCESS_FS_READ_FILE
    | _LANDLOCK_ACCESS_FS_READ_DIR
)
_LANDLOCK_ABI1_WRITES = (
    _LANDLOCK_ACCESS_FS_WRITE_FILE
    | _LANDLOCK_ACCESS_FS_REMOVE_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_FILE
    | _LANDLOCK_ACCESS_FS_MAKE_CHAR
    | _LANDLOCK_ACCESS_FS_MAKE_DIR
    | _LANDLOCK_ACCESS_FS_MAKE_REG
    | _LANDLOCK_ACCESS_FS_MAKE_SOCK
    | _LANDLOCK_ACCESS_FS_MAKE_FIFO
    | _LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | _LANDLOCK_ACCESS_FS_MAKE_SYM
)


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    ]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


def _linux_landlock_abi() -> int:
    if platform.system() != "Linux":
        return 0
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(
        _LANDLOCK_CREATE_RULESET,
        ctypes.c_void_p(),
        ctypes.c_size_t(0),
        ctypes.c_uint(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    if result < 0:
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL}:
            return 0
        raise OSError(error, os.strerror(error))
    return int(result)


def _install_linux_write_confinement(
    writable_root: Path,
    *,
    abi: int,
    readable_paths: tuple[Path, ...],
) -> None:
    """Allow reads from explicit runtime roots and writes only in the snapshot."""

    handled = _LANDLOCK_ABI1_WRITES | _LANDLOCK_READS
    if abi >= 2:
        handled |= _LANDLOCK_ACCESS_FS_REFER
    if abi >= 3:
        handled |= _LANDLOCK_ACCESS_FS_TRUNCATE
    libc = ctypes.CDLL(None, use_errno=True)
    handled_net = (
        _LANDLOCK_ACCESS_NET_BIND_TCP | _LANDLOCK_ACCESS_NET_CONNECT_TCP
        if abi >= 4
        else 0
    )
    ruleset = _LandlockRulesetAttr(
        handled_access_fs=handled,
        handled_access_net=handled_net,
    )
    ruleset_fd = libc.syscall(
        _LANDLOCK_CREATE_RULESET,
        ctypes.byref(ruleset),
        ctypes.sizeof(ruleset),
        ctypes.c_uint(0),
    )
    if ruleset_fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    try:
        def add_path(path: Path, allowed: int) -> None:
            path_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                path_rule = _LandlockPathBeneathAttr(
                    allowed_access=allowed,
                    parent_fd=path_fd,
                )
                if (
                    libc.syscall(
                        _LANDLOCK_ADD_RULE,
                        ruleset_fd,
                        _LANDLOCK_RULE_PATH_BENEATH,
                        ctypes.byref(path_rule),
                        ctypes.c_uint(0),
                    )
                    < 0
                ):
                    error = ctypes.get_errno()
                    raise OSError(error, os.strerror(error))
            finally:
                os.close(path_fd)

        add_path(writable_root, handled)
        for readable in readable_paths:
            allowed = (
                _LANDLOCK_READS
                if readable.is_dir()
                else (
                    _LANDLOCK_ACCESS_FS_EXECUTE
                    | _LANDLOCK_ACCESS_FS_READ_FILE
                )
            )
            add_path(readable, allowed)
        for device in (Path("/dev/null"), Path("/dev/urandom"), Path("/dev/random")):
            if device.exists():
                add_path(
                    device,
                    _LANDLOCK_ACCESS_FS_READ_FILE
                    | _LANDLOCK_ACCESS_FS_WRITE_FILE,
                )
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        if libc.syscall(_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    finally:
        os.close(ruleset_fd)


def _install_linux_socket_filter() -> None:
    """Allow local Unix sockets, deny creation of Internet sockets."""

    socket_syscalls = {
        "x86_64": 41,
        "amd64": 41,
        "aarch64": 198,
        "arm64": 198,
    }
    machine = platform.machine().lower()
    socket_syscall = socket_syscalls.get(machine)
    if socket_syscall is None:
        raise OSError(
            errno.EOPNOTSUPP,
            f"no verified socket syscall mapping for {machine}",
        )
    instructions = (_SockFilter * 6)(
        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_NR_OFFSET),
        _SockFilter(_BPF_JMP_JEQ_K, 0, 3, socket_syscall),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, _AF_UNIX),
        _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM),
        _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW),
    )
    program = _SockFprog(
        length=len(instructions),
        filter=ctypes.cast(instructions, ctypes.POINTER(_SockFilter)),
    )
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _validate_snapshot_symlinks(root: Path) -> None:
    resolved_root = root.resolve(strict=True)
    files = 0
    total_bytes = 0
    for path in root.rglob("*"):
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            raise ValueError(
                f"snapshot entry is unreadable: {path.relative_to(root)}"
            ) from error
        if stat.S_ISREG(mode):
            files += 1
            total_bytes += path.lstat().st_size
            if files > MAX_SNAPSHOT_FILES or total_bytes > MAX_SNAPSHOT_BYTES:
                raise ValueError("snapshot exceeds the verification size budget")
        elif not (
            stat.S_ISDIR(mode) or stat.S_ISLNK(mode)
        ):
            raise ValueError(
                f"snapshot contains a special file: {path.relative_to(root)}"
            )
        if not path.is_symlink():
            continue
        if path.readlink().is_absolute():
            raise ValueError(
                f"snapshot contains an absolute symlink: {path.relative_to(root)}"
            )
        try:
            relative_target = path.resolve(strict=True).relative_to(resolved_root)
        except (OSError, ValueError) as error:
            raise ValueError(
                f"snapshot contains an external or broken symlink: "
                f"{path.relative_to(root)}"
            ) from error
        if _snapshot_path_is_protected(relative_target):
            raise ValueError(
                f"snapshot symlink targets protected content: "
                f"{path.relative_to(root)}"
            )


def _snapshot_path_is_protected(relative: Path) -> bool:
    denied_parts = {
        ".git",
        ".agent-harness",
        ".ssh",
        ".aws",
        ".gnupg",
        ".env-store",
    }
    denied_names = {
        "credentials",
        "credentials.json",
        "credentials.yaml",
        "credentials.yml",
        "credentials.toml",
        "secrets.json",
        "secrets.yaml",
        "secrets.yml",
        "secrets.toml",
        "tokens.json",
        "auth.json",
        "service-account.json",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "id_rsa",
        "id_ed25519",
    }
    lowered = tuple(part.lower() for part in relative.parts)
    if any(part in denied_parts for part in lowered):
        return True
    name = lowered[-1] if lowered else ""
    private_key_artifact = (
        "private-key" in name or "private_key" in name
    ) and Path(name).suffix in {"", ".txt", ".json", ".yaml", ".yml"}
    return (
        any(part.startswith(".env") for part in lowered)
        or private_key_artifact
        or any(
        part in denied_names
        or part.endswith((".pem", ".key", ".p12", ".pfx"))
        for part in lowered
        )
    )


def _copy_project_snapshot(root: Path, destination: Path) -> None:
    _validate_snapshot_symlinks(root)

    def ignored(directory: str, names: list[str]) -> set[str]:
        base = Path(directory)
        omitted: set[str] = set()
        for name in names:
            candidate = base / name
            relative = candidate.relative_to(root)
            if (
                _snapshot_path_is_protected(relative)
                or name == "__pycache__"
                or name.endswith(".pyc")
            ):
                omitted.add(name)
        return omitted

    shutil.copytree(
        root,
        destination,
        symlinks=True,
        ignore=ignored,
    )


def _verification_environment(isolation_root: Path) -> dict[str, str]:
    home = isolation_root / "home"
    temporary = isolation_root / "tmp"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        in {
            "COMSPEC",
            "LANG",
            "LC_ALL",
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "SystemRoot",
            "TZ",
        }
    }
    environment.update(
        {
            "CI": "1",
            "HOME": str(home),
            "NO_COLOR": "1",
            "TMPDIR": str(temporary),
            "TEMP": str(temporary),
            "TMP": str(temporary),
            "npm_config_offline": "true",
            "PIP_NO_INDEX": "1",
            "CARGO_NET_OFFLINE": "true",
        }
    )
    return environment


def _linux_readable_runtime_paths(
    arguments: list[str],
    environment: dict[str, str],
) -> tuple[Path, ...]:
    candidates = [
        Path(value)
        for value in (
            "/bin",
            "/sbin",
            "/usr",
            "/lib",
            "/lib64",
            "/nix/store",
            "/snap",
        )
    ]
    candidates.extend(
        Path(value)
        for value in (
            "/etc/ld.so.cache",
            "/etc/localtime",
            "/etc/nsswitch.conf",
            "/etc/passwd",
            "/etc/group",
            "/etc/ssl/openssl.cnf",
        )
    )
    python_paths = sysconfig.get_paths()
    candidates.extend(
        Path(value)
        for key in ("stdlib", "platstdlib", "purelib", "platlib")
        if (value := python_paths.get(key))
    )
    executable_names = {
        arguments[0],
        "bash",
        "bun",
        "cargo",
        "git",
        "go",
        "make",
        "node",
        "npm",
        "npx",
        "pnpm",
        "python",
        "python3",
        "pytest",
        "rustc",
        "sh",
        "yarn",
    }
    for name in executable_names:
        executable = shutil.which(name, path=environment.get("PATH"))
        if not executable:
            continue
        resolved = Path(executable).resolve()
        candidates.append(resolved)
        parts = resolved.parts
        for marker, depth in (
            (".nvm", 4),
            ("fnm", 3),
            (".pyenv", 3),
            (".rustup", 3),
        ):
            if marker not in parts:
                continue
            marker_index = parts.index(marker)
            end = min(len(parts) - 1, marker_index + depth)
            candidates.append(Path(*parts[: end + 1]))
            break
    unique: dict[str, Path] = {}
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        unique[str(resolved)] = resolved
    return tuple(unique[key] for key in sorted(unique))


def _linux_uid_task_count(
    *,
    proc_root: Path = Path("/proc"),
    uid: int | None = None,
) -> int:
    """Count Linux tasks for the real UID used by RLIMIT_NPROC."""

    target_uid = os.getuid() if uid is None else uid
    try:
        processes = tuple(proc_root.iterdir())
    except OSError as error:
        raise ValueError(
            "cannot measure current UID tasks for process confinement"
        ) from error
    total = 0
    for process in processes:
        if not process.name.isdigit():
            continue
        try:
            if process.stat().st_uid != target_uid:
                continue
            tasks = tuple((process / "task").iterdir())
        except FileNotFoundError:
            # Processes may exit between discovery and observation.
            continue
        except OSError as error:
            raise ValueError(
                "cannot measure current UID tasks for process confinement"
            ) from error
        total += sum(task.name.isdigit() for task in tasks)
    if total < 1:
        raise ValueError(
            "cannot measure current UID tasks for process confinement"
        )
    return total


def _linux_uid_process_limit() -> int:
    """Reserve bounded headroom without treating a UID-global count as local."""

    current_tasks = _linux_uid_task_count()
    _soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    desired = current_tasks + MAX_ADDITIONAL_PROCESSES
    bounded = desired if hard == resource.RLIM_INFINITY else min(desired, hard)
    if bounded <= current_tasks:
        raise ValueError("UID process hard limit leaves no verification headroom")
    return bounded


def _install_resource_limits(*, process_limit: int | None = None) -> None:
    resource.setrlimit(
        resource.RLIMIT_CPU,
        (VERIFICATION_TIMEOUT_SECONDS, VERIFICATION_TIMEOUT_SECONDS + 5),
    )
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_CREATED_FILE_BYTES, MAX_CREATED_FILE_BYTES),
    )
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    if hasattr(resource, "RLIMIT_AS"):
        _set_soft_resource_cap(resource.RLIMIT_AS, MAX_ADDRESS_SPACE_BYTES)
    if hasattr(resource, "RLIMIT_NPROC") and process_limit is not None:
        _set_soft_resource_cap(resource.RLIMIT_NPROC, process_limit)


def _set_soft_resource_cap(resource_id: int, cap: int) -> None:
    _soft, hard = resource.getrlimit(resource_id)
    bounded = cap if hard == resource.RLIM_INFINITY else min(cap, hard)
    resource.setrlimit(resource_id, (bounded, hard))


def _emit_bounded(path: Path, *, destination: Any) -> None:
    with path.open("rb") as handle:
        payload = handle.read(MAX_OUTPUT_BYTES + 1)
    truncated = len(payload) > MAX_OUTPUT_BYTES
    text = payload[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    print(text, end="" if not text or text.endswith("\n") else "\n", file=destination)
    if truncated:
        print(
            f"verification broker: output truncated at {MAX_OUTPUT_BYTES} bytes",
            file=destination,
        )


def _run_bounded_process(
    command: list[str],
    *,
    workspace: Path,
    isolation_root: Path,
    environment: dict[str, str],
    preexec_fn: Any,
) -> int:
    stdout_path = isolation_root / "stdout.log"
    stderr_path = isolation_root / "stderr.log"
    with stdout_path.open("w+b") as stdout_file, stderr_path.open(
        "w+b"
    ) as stderr_file:
        process = subprocess.Popen(
            command,
            cwd=workspace,
            env=environment,
            stdout=stdout_file,
            stderr=stderr_file,
            preexec_fn=preexec_fn,
            start_new_session=True,
        )
        try:
            returncode = process.wait(timeout=VERIFICATION_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            returncode = 124
            print(
                "verification broker: command timed out and its process group "
                "was terminated",
                file=sys.stderr,
            )
    _emit_bounded(stdout_path, destination=sys.stdout)
    _emit_bounded(stderr_path, destination=sys.stderr)
    return returncode


def _run_isolated(
    root: Path,
    arguments: list[str],
    managed: dict[str, Any] | None,
) -> tuple[int, str | None]:
    """Run in a disposable snapshot; fail closed without an OS write isolator."""

    with tempfile.TemporaryDirectory(
        prefix="engineering-harness-verification-"
    ) as raw:
        isolation_root = Path(raw).resolve(strict=True)
        workspace = isolation_root / "workspace"
        _copy_project_snapshot(root, workspace)
        implementation_hash, source_input_hash = _snapshot_hashes(
            workspace, managed
        )
        environment = _verification_environment(isolation_root)
        system = platform.system()
        if system == "Linux":
            abi = _linux_landlock_abi()
            if abi < 3:
                raise ValueError(
                    "Linux Landlock ABI >= 3 write confinement is unavailable"
                )
            process_limit = _linux_uid_process_limit()
            readable_paths = _linux_readable_runtime_paths(
                arguments,
                environment,
            )
            returncode = _run_bounded_process(
                arguments,
                workspace=workspace,
                isolation_root=isolation_root,
                environment=environment,
                preexec_fn=lambda: (
                    _install_resource_limits(process_limit=process_limit),
                    _install_linux_write_confinement(
                        isolation_root,
                        abi=abi,
                        readable_paths=readable_paths,
                    ),
                    _install_linux_socket_filter(),
                ),
            )
        elif system == "Darwin":
            sandbox_exec = shutil.which("sandbox-exec")
            if sandbox_exec is None:
                raise ValueError("macOS sandbox-exec is unavailable")
            escaped = str(isolation_root).replace("\\", "\\\\").replace('"', '\\"')
            read_roots = [
                "/System",
                "/Library",
                "/usr",
                "/bin",
                "/sbin",
                "/private/etc",
                "/dev",
                "/opt/homebrew",
                escaped,
            ]
            read_rules = "".join(
                f'(allow file-read* (subpath "{value}"))'
                for value in read_roots
                if value == escaped or Path(value).exists()
            )
            profile = (
                "(version 1)"
                "(deny default)"
                "(allow process*)"
                "(allow sysctl-read)"
                f"{read_rules}"
                f'(allow file-write* (subpath "{escaped}"))'
                '(allow file-write-data (literal "/dev/null"))'
            )
            returncode = _run_bounded_process(
                [sandbox_exec, "-p", profile, *arguments],
                workspace=workspace,
                isolation_root=isolation_root,
                environment=environment,
                # RLIMIT_NPROC is UID-global on macOS too. Without a trusted
                # host-side UID task count, retain the child-local limits and
                # omit this false-failure-prone limit.
                preexec_fn=_install_resource_limits,
            )
        else:
            raise ValueError(
                f"no verified write isolator for {system or 'unknown platform'}"
            )
        if returncode == 0 and managed is not None:
            _post_implementation_hash, post_source_input_hash = (
                _snapshot_hashes(workspace, managed)
            )
            if (
                source_input_hash is None
                or post_source_input_hash != source_input_hash
            ):
                raise ValueError(
                    "verification mutated source-controlled snapshot inputs"
                )
        return returncode, implementation_hash


def load_commands(root: Path) -> dict[str, list[str]]:
    profile = root / PROFILE
    if profile.is_symlink() or not profile.is_file():
        raise ValueError("repository profile is missing or unsafe")
    try:
        value: Any = json.loads(profile.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"repository profile is invalid: {error}") from error
    candidates = value.get("candidate_commands") if isinstance(value, dict) else None
    if not isinstance(candidates, list):
        raise ValueError("candidate command registry is malformed")
    commands: dict[str, list[str]] = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("candidate command entry is malformed")
        identifier = candidate.get("id")
        command = candidate.get("command")
        executed = candidate.get("executed")
        if (
            not isinstance(identifier, str)
            or IDENTIFIER.fullmatch(identifier) is None
            or not isinstance(command, str)
            or not command
            or executed is not False
            or identifier in commands
        ):
            raise ValueError("candidate command entry is invalid")
        try:
            arguments = shlex.split(command, posix=True)
        except ValueError as error:
            raise ValueError(f"candidate {identifier!r} is not valid argv") from error
        if not arguments or shlex.join(arguments) != command:
            raise ValueError(
                f"candidate {identifier!r} is not a canonical exact command"
            )
        commands[identifier] = arguments
    return commands


def _managed_verification_context(
    root: Path,
) -> dict[str, Any] | None:
    manifest_path = root / ".agent-harness" / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        return None
    bin_directory = Path(__file__).resolve(strict=True).parent
    sys.path.insert(0, str(bin_directory))
    try:
        from request_write_lease import load_manifest, trusted_runtime

        manifest = load_manifest(root)
        runtime_root, state_path = trusted_runtime(root, manifest)
        try:
            state_value = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("authoritative state is unavailable") from error
        if (
            not isinstance(state_value, dict)
            or state_value.get("writeLease") is None
        ):
            # Direct user smoke runs remain useful, but cannot create a receipt
            # or complete a Task without a Gate-issued lease.
            return None
        lease = state_value["writeLease"]
        scopes = lease.get("allowedGlobs") if isinstance(lease, dict) else None
        if (
            not isinstance(scopes, list)
            or not scopes
            or not all(isinstance(item, str) for item in scopes)
        ):
            raise ValueError("active lease scopes are invalid")
        return {
            "allowed_globs": tuple(scopes),
            "runtime_root": runtime_root,
            "state_path": state_path,
        }
    finally:
        sys.path.remove(str(bin_directory))


def _snapshot_hashes(
    workspace: Path,
    managed: dict[str, Any] | None,
) -> tuple[str | None, str | None]:
    if managed is None:
        return None, None
    runtime_root = managed["runtime_root"]
    sys.path.insert(0, str(runtime_root))
    try:
        from engineering_harness_gate.lifecycle import (
            observe_outside_scope_tree,
            observe_scope_tree,
        )

        return (
            observe_scope_tree(
                workspace, managed["allowed_globs"]
            ),
            observe_outside_scope_tree(workspace, ()),
        )
    finally:
        sys.path.remove(str(runtime_root))


def _record_successful_receipt(
    root: Path,
    verification_id: str,
    *,
    managed: dict[str, Any],
    expected_implementation_hash: str,
) -> None:
    """Bind success to the exact disposable snapshot that was tested."""

    runtime_root = managed["runtime_root"]
    sys.path.insert(0, str(runtime_root))
    try:
        from engineering_harness_gate.lifecycle import (
            record_verification_receipt,
        )

        record_verification_receipt(
            verification_id=verification_id,
            repo=root,
            state_path=managed["state_path"],
            profile_path=root / PROFILE,
            expected_implementation_hash=expected_implementation_hash,
        )
    finally:
        sys.path.remove(str(runtime_root))


def main() -> int:
    # The broker imports a Project-local launcher to discover the trusted host
    # runtime. A cold import must not create __pycache__ inside the live
    # Project after the Write Lease captured its outside-scope tree.
    sys.dont_write_bytecode = True
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("verification_id")
    args = parser.parse_args()
    root = Path(__file__).resolve(strict=True).parents[2]
    if Path.cwd().resolve(strict=True) != root:
        print("verification broker: Project-root cwd required", file=sys.stderr)
        return 2
    try:
        commands = load_commands(root)
        arguments = commands.get(args.verification_id)
        if arguments is None:
            raise ValueError("verification id is not registered")
    except (OSError, ValueError) as error:
        print(f"verification broker: denied ({error})", file=sys.stderr)
        return 2
    try:
        managed = _managed_verification_context(root)
        returncode, input_hash = _run_isolated(
            root, arguments, managed
        )
        if returncode == 0 and managed is not None:
            if input_hash is None:
                raise ValueError(
                    "managed verification input hash is unavailable"
                )
            _record_successful_receipt(
                root,
                args.verification_id,
                managed=managed,
                expected_implementation_hash=input_hash,
            )
        return returncode
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"verification broker: denied ({error})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
