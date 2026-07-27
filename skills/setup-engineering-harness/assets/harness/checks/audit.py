#!/usr/bin/env python3
# engineering-harness:installer-owned
"""Audit installed Engineering Harness integrity and enforcement readiness."""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timedelta, timezone
import errno
import hashlib
import json
import os
import platform
import shutil
import sys
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST_RELATIVE = ".agent-harness/manifest.json"
RUNTIME_CONTRACT_RELATIVE = ".agent-harness/runtime/runtime-contract.json"
PROVIDER_VERIFICATION_TTL = timedelta(hours=24)
_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LINUX_SECCOMP_SOCKET_ARCHITECTURES = {
    "aarch64",
    "amd64",
    "arm64",
    "x86_64",
}
_MINIMUM_LANDLOCK_ABI = 3


def digest_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def canonical_digest(value: Any) -> str:
    return digest_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _linux_landlock_abi() -> int:
    """Return the active kernel's Landlock ABI, or zero when unavailable."""

    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(
        _LANDLOCK_CREATE_RULESET,
        ctypes.c_void_p(),
        ctypes.c_size_t(0),
        ctypes.c_uint(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    if result < 0:
        error = ctypes.get_errno()
        if error in {
            errno.EINVAL,
            errno.ENOSYS,
            errno.EOPNOTSUPP,
            errno.EPERM,
        }:
            return 0
        return 0
    return int(result)


def verification_isolator_capability() -> tuple[bool, str]:
    """Check the OS primitives required by the verification broker."""

    system = platform.system()
    if system == "Linux":
        machine = platform.machine().lower()
        if machine not in _LINUX_SECCOMP_SOCKET_ARCHITECTURES:
            return (
                False,
                "verification isolation has no reviewed Linux socket filter "
                f"for architecture {machine or 'unknown'}",
            )
        abi = _linux_landlock_abi()
        if abi < _MINIMUM_LANDLOCK_ABI:
            return (
                False,
                "verification isolation requires Linux Landlock ABI >= 3 "
                f"(detected {abi})",
            )
        return True, f"Linux Landlock ABI {abi} with reviewed socket filter"
    if system == "Darwin":
        if shutil.which("sandbox-exec") is None:
            return False, "verification isolation requires macOS sandbox-exec"
        return True, "macOS sandbox-exec is available"
    return (
        False,
        "verification isolation has no reviewed backend for "
        f"{system or 'unknown platform'}",
    )


def load_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def relative(value: Any) -> PurePosixPath | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    result = PurePosixPath(value)
    if result.is_absolute() or any(part in {"", ".", ".."} for part in result.parts):
        return None
    return result


def project_path(root: Path, value: Any) -> Path | None:
    rel = relative(value)
    if rel is None:
        return None
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            return None
    return current


def hook_command(entry: Any) -> str:
    if not isinstance(entry, dict):
        return ""
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        return ""
    commands: list[str] = []
    for hook in hooks:
        if isinstance(hook, dict) and isinstance(hook.get("command"), str):
            commands.append(hook["command"])
    return "\n".join(commands)


def managed_hook_entries(data: dict[str, Any], event: str, hook_id: str) -> list[Any]:
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return []
    entries = hooks.get(event)
    if not isinstance(entries, list):
        return []
    needle = f"ENGINEERING_HARNESS_HOOK_ID={hook_id}"
    return [entry for entry in entries if needle in hook_command(entry)]


def audit(root: Path) -> tuple[list[str], list[str], int]:
    issues: list[str] = []
    incomplete: list[str] = []
    checked = 0
    manifest_path = project_path(root, MANIFEST_RELATIVE)
    if manifest_path is None or not manifest_path.is_file():
        return [f"{MANIFEST_RELATIVE}: missing or unsafe"], incomplete, checked
    try:
        manifest = load_object(manifest_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        return [f"{MANIFEST_RELATIVE}: invalid ({error})"], incomplete, checked
    if manifest.get("_managed_by") != "engineering-harness":
        issues.append(f"{MANIFEST_RELATIVE}: unexpected manager")
    if manifest.get("schema_version") != 1:
        issues.append(f"{MANIFEST_RELATIVE}: unsupported schema")
    expected_manifest_checksum = manifest.get("manifest_checksum")
    manifest_body = dict(manifest)
    manifest_body.pop("manifest_checksum", None)
    if (
        not isinstance(expected_manifest_checksum, str)
        or canonical_digest(manifest_body) != expected_manifest_checksum
    ):
        issues.append(f"{MANIFEST_RELATIVE}: manifest checksum mismatch")

    blocks = manifest.get("managed_blocks")
    if not isinstance(blocks, list) or len(blocks) != 1:
        issues.append(f"{MANIFEST_RELATIVE}: expected one managed bridge")
    else:
        block = blocks[0]
        if not isinstance(block, dict):
            issues.append(f"{MANIFEST_RELATIVE}: malformed managed bridge")
        else:
            path = project_path(root, block.get("path"))
            start = block.get("start")
            end = block.get("end")
            expected = block.get("sha256")
            if path is None or not all(
                isinstance(item, str) for item in (start, end, expected)
            ):
                issues.append(f"{MANIFEST_RELATIVE}: invalid bridge fields")
            else:
                try:
                    content = path.read_bytes()
                    start_bytes = start.encode("utf-8")
                    end_bytes = end.encode("utf-8")
                    if content.count(start_bytes) != 1 or content.count(end_bytes) != 1:
                        raise ValueError("markers must occur exactly once")
                    begin = content.index(start_bytes)
                    finish = content.index(end_bytes, begin) + len(end_bytes)
                    if digest_bytes(content[begin:finish]) != expected:
                        raise ValueError("managed bridge drift")
                except (OSError, ValueError) as error:
                    issues.append(f"AGENTS.md: {error}")
                checked += 1

    owned = manifest.get("owned_files")
    if not isinstance(owned, list):
        issues.append(f"{MANIFEST_RELATIVE}: owned_files must be an array")
    else:
        seen: set[str] = set()
        for entry in owned:
            if not isinstance(entry, dict):
                issues.append(f"{MANIFEST_RELATIVE}: malformed owned file")
                continue
            name = entry.get("path")
            path = project_path(root, name)
            expected = entry.get("sha256")
            if (
                not isinstance(name, str)
                or path is None
                or not isinstance(expected, str)
                or name in seen
            ):
                issues.append(f"{MANIFEST_RELATIVE}: invalid or duplicate owned path")
                continue
            seen.add(name)
            try:
                if digest_bytes(path.read_bytes()) != expected:
                    raise ValueError("installer-owned content drift")
            except (OSError, ValueError) as error:
                issues.append(f"{name}: {error}")
            checked += 1

    seeded = manifest.get("seeded_files")
    if not isinstance(seeded, list):
        issues.append(f"{MANIFEST_RELATIVE}: seeded_files must be an array")
    else:
        for entry in seeded:
            path = project_path(root, entry.get("path") if isinstance(entry, dict) else None)
            name = entry.get("path") if isinstance(entry, dict) else "?"
            if path is None or not path.is_file():
                issues.append(f"{name}: missing or unsafe user-owned seed")
                continue
            if name == ".agent-harness/config.json":
                try:
                    config = load_object(path)
                    if config.get("schema_version") != 1:
                        raise ValueError("unsupported schema")
                    adaptive = config.get("adaptive_task_context")
                    if not isinstance(adaptive, dict) or not isinstance(
                        adaptive.get("enabled"), bool
                    ):
                        raise ValueError("adaptive_task_context.enabled must be boolean")
                    write_gate = config.get("write_gate")
                    if write_gate is not None:
                        if not isinstance(write_gate, dict):
                            raise ValueError("write_gate must be an object")
                        if not isinstance(
                            write_gate.get("auto_approve_reversible_lite"),
                            bool,
                        ):
                            raise ValueError(
                                "write_gate.auto_approve_reversible_lite must be boolean"
                            )
                        maximum = write_gate.get("max_auto_scope_globs")
                        minutes = write_gate.get("lease_minutes")
                        if (
                            type(maximum) is not int
                            or not 1 <= maximum <= 16
                            or type(minutes) is not int
                            or not 5 <= minutes <= 60
                        ):
                            raise ValueError("write_gate limits are invalid")
                except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
                    issues.append(f"{name}: invalid ({error})")
            checked += 1

    contract_path = project_path(root, RUNTIME_CONTRACT_RELATIVE)
    runtime_capabilities: dict[str, Any] = {}
    if contract_path is None:
        issues.append(f"{RUNTIME_CONTRACT_RELATIVE}: unsafe path")
    else:
        try:
            contract = load_object(contract_path)
            capabilities = contract.get("capabilities")
            if not isinstance(capabilities, dict):
                raise ValueError("capabilities must be an object")
            runtime_capabilities = capabilities
            for capability, message in (
                (
                    "scoped_write_lease",
                    "installed runtime does not implement scoped Write Leases",
                ),
                (
                    "provider_trust_verification",
                    "installed runtime cannot attest provider hook trust",
                ),
                (
                    "write_canary_verification",
                    "installed runtime cannot attest a write-deny canary",
                ),
            ):
                if capabilities.get(capability) is not True:
                    incomplete.append(message)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            issues.append(f"{RUNTIME_CONTRACT_RELATIVE}: invalid ({error})")
            checked += 1

    isolator_ready, isolator_detail = verification_isolator_capability()
    if not isolator_ready:
        incomplete.append(isolator_detail)
    checked += 1

    hook_file = project_path(root, manifest.get("provider_hooks", {}).get("path"))
    hook_data: dict[str, Any] = {}
    if hook_file is None:
        issues.append("provider hook path is invalid")
    else:
        try:
            hook_data = load_object(hook_file)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            issues.append(f".codex/hooks.json: invalid ({error})")
    managed_hooks = manifest.get("provider_hooks", {}).get("managed_entries")
    if not isinstance(managed_hooks, list):
        issues.append(f"{MANIFEST_RELATIVE}: managed hook entries are malformed")
    else:
        for spec in managed_hooks:
            if not isinstance(spec, dict):
                issues.append(f"{MANIFEST_RELATIVE}: malformed hook specification")
                continue
            event = spec.get("event")
            hook_id = spec.get("id")
            expected = spec.get("sha256")
            if not all(isinstance(item, str) for item in (event, hook_id, expected)):
                issues.append(f"{MANIFEST_RELATIVE}: invalid hook specification")
                continue
            entries = managed_hook_entries(hook_data, event, hook_id)
            if len(entries) != 1:
                issues.append(f".codex/hooks.json: expected one managed {event} {hook_id}")
            elif canonical_digest(entries[0]) != expected:
                issues.append(f".codex/hooks.json: managed {event} {hook_id} drift")
            checked += 1

    host = manifest.get("host_runtime")
    if not isinstance(host, dict):
        issues.append(f"{MANIFEST_RELATIVE}: host_runtime is malformed")
    else:
        files = host.get("owned_files")
        if not isinstance(files, list):
            issues.append(f"{MANIFEST_RELATIVE}: host runtime file list is malformed")
        else:
            for entry in files:
                path_value = entry.get("path") if isinstance(entry, dict) else None
                expected = entry.get("sha256") if isinstance(entry, dict) else None
                if not isinstance(path_value, str) or not isinstance(expected, str):
                    issues.append(f"{MANIFEST_RELATIVE}: invalid host runtime file")
                    continue
                path = Path(path_value)
                try:
                    if path.is_symlink() or digest_bytes(path.read_bytes()) != expected:
                        raise ValueError("missing, unsafe, or drifted")
                except (OSError, ValueError) as error:
                    issues.append(f"{path}: {error}")
                checked += 1
        state_value = host.get("state_path")
        if not isinstance(state_value, str):
            issues.append(f"{MANIFEST_RELATIVE}: state_path is invalid")
        else:
            try:
                state = load_object(Path(state_value))
                expected_keys = {
                    "acceptanceHash",
                    "schemaVersion",
                    "taskId",
                    "projectId",
                    "projectRoot",
                    "readBrokerPythonExecutables",
                    "protectedGlobs",
                    "baseTreeHash",
                    "phase",
                    "evidence",
                    "pendingDecisions",
                    "writeLease",
                }
                if set(state) != expected_keys:
                    raise ValueError("state keys do not match Gate v1")
                if state.get("schemaVersion") != 1:
                    raise ValueError("unsupported Gate state schema")
                if state.get("projectRoot") != str(root):
                    raise ValueError("state belongs to another Project")
                if state.get("writeLease") is not None:
                    incomplete.append("audit does not attest an active scoped Write Lease")
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
                issues.append(f"{state_value}: invalid host Gate state ({error})")
            checked += 1
        status_value = host.get("status_path")
        if not isinstance(status_value, str):
            issues.append(f"{MANIFEST_RELATIVE}: status_path is invalid")
        else:
            try:
                status = load_object(Path(status_value))
                if status.get("projectRoot") != str(root):
                    raise ValueError("status belongs to another Project")
                broker = root / ".agent-harness" / "bin" / "read_context.py"
                if status.get("contextBrokerSha256") != digest_bytes(broker.read_bytes()):
                    raise ValueError("context broker digest mismatch")
                if (
                    status.get("runtimeReady") is not True
                    or runtime_capabilities.get("scoped_write_lease") is not True
                ):
                    incomplete.append("trusted scoped-lease runtime is not synchronized")
                if (
                    status.get("hookTrustVerified") is not True
                    or runtime_capabilities.get("provider_trust_verification") is not True
                    or status.get("verifiedManifestChecksum")
                    != manifest.get("manifest_checksum")
                    or not provider_receipt_is_current(status)
                ):
                    incomplete.append("provider hook trust is not verified")
                if (
                    status.get("writeCanaryVerified") is not True
                    or runtime_capabilities.get("write_canary_verification") is not True
                    or not isinstance(
                        status.get("verificationEvidenceSha256"), str
                    )
                    or len(status["verificationEvidenceSha256"]) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in status["verificationEvidenceSha256"]
                    )
                ):
                    incomplete.append("write-deny canary is not verified")
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
                issues.append(f"{status_value}: invalid host setup status ({error})")
            checked += 1

    return sorted(set(issues)), sorted(set(incomplete)), checked


def provider_receipt_is_current(status: dict[str, Any]) -> bool:
    binary_value = status.get("providerBinary")
    digest = status.get("providerBinarySha256")
    version = status.get("providerVersion")
    verified_at = status.get("verifiedAt")
    receipt = status.get("providerReceipt")
    evidence_digest = status.get("verificationEvidenceSha256")
    if not (
        isinstance(binary_value, str)
        and binary_value
        and isinstance(digest, str)
        and len(digest) == 64
        and isinstance(version, str)
        and version
        and isinstance(verified_at, str)
        and verified_at
        and isinstance(receipt, dict)
        and isinstance(evidence_digest, str)
        and canonical_digest(receipt) == evidence_digest
        and receipt.get("providerBinary") == binary_value
        and receipt.get("providerBinarySha256") == digest
        and receipt.get("providerVersion") == version
        and receipt.get("verifiedAt") == verified_at
        and receipt.get("manifestChecksum")
        == status.get("verifiedManifestChecksum")
    ):
        return False
    current = shutil.which("codex")
    if not current:
        return False
    try:
        binary = Path(binary_value).resolve(strict=True)
        if Path(current).resolve(strict=True) != binary:
            return False
        if digest_bytes(binary.read_bytes()) != digest:
            return False
        observed = datetime.fromisoformat(verified_at)
    except (OSError, ValueError):
        return False
    if observed.tzinfo is None:
        return False
    age = datetime.now(timezone.utc) - observed.astimezone(timezone.utc)
    return timedelta(0) <= age <= PROVIDER_VERIFICATION_TTL


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo", type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = args.repo.expanduser().resolve()
    if not root.is_dir():
        print(f"error: Project is not a directory: {root}", file=sys.stderr)
        return 2
    issues, incomplete, checked = audit(root)
    status = "fail" if issues else ("incomplete" if incomplete else "pass")
    if args.json:
        print(
            json.dumps(
                {
                    "checked": checked,
                    "incomplete": incomplete,
                    "issues": issues,
                    "status": status,
                },
                indent=2,
                sort_keys=True,
            )
        )
    elif issues:
        print(f"Harness audit: FAIL ({len(issues)} issue(s), {checked} checked)")
        for issue in issues:
            print(f"- {issue}")
    elif incomplete:
        print(
            f"Harness audit: INCOMPLETE "
            f"({len(incomplete)} enforcement prerequisite(s), {checked} checked)"
        )
        for item in incomplete:
            print(f"- {item}")
    else:
        print(f"Harness audit: PASS ({checked} checked)")
    if issues:
        return 1
    return 3 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
