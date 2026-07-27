#!/usr/bin/env python3
# engineering-harness:installer-owned
"""Protected launcher for the host-controlled Write Lease lifecycle."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def canonical_digest(value: Any) -> str:
    return digest(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    )


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / ".agent-harness" / "manifest.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("ownership manifest is missing or unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("_managed_by") != "engineering-harness":
        raise ValueError("ownership manifest is invalid")
    expected = value.get("manifest_checksum")
    body = dict(value)
    body.pop("manifest_checksum", None)
    if not isinstance(expected, str) or canonical_digest(body) != expected:
        raise ValueError("ownership manifest checksum mismatch")
    return value


def trusted_runtime(
    root: Path, manifest: dict[str, Any]
) -> tuple[Path, Path]:
    host = manifest.get("host_runtime")
    if not isinstance(host, dict):
        raise ValueError("host runtime manifest is invalid")
    state_value = host.get("state_path")
    files = host.get("owned_files")
    if not isinstance(state_value, str) or not isinstance(files, list):
        raise ValueError("host runtime paths are invalid")
    state_path = Path(state_value)
    if not state_path.is_absolute():
        raise ValueError("authoritative state path must be absolute")
    try:
        state_path.resolve(strict=False).relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("authoritative state cannot be inside the Project")
    lifecycle_path: Path | None = None
    expected_digest: str | None = None
    for entry in files:
        if not isinstance(entry, dict):
            continue
        path_value = entry.get("path")
        if (
            isinstance(path_value, str)
            and path_value.endswith(
                "/runtime/engineering_harness_gate/lifecycle.py"
            )
        ):
            lifecycle_path = Path(path_value)
            expected_digest = entry.get("sha256")
            break
    if (
        lifecycle_path is None
        or not isinstance(expected_digest, str)
        or lifecycle_path.is_symlink()
        or not lifecycle_path.is_file()
        or digest(lifecycle_path.read_bytes()) != expected_digest
    ):
        raise ValueError("trusted lifecycle runtime is missing or drifted")
    runtime_root = lifecycle_path.parents[1]
    return runtime_root, state_path


def main() -> int:
    try:
        sys.dont_write_bytecode = True
        root = Path(__file__).resolve(strict=True).parents[2]
        manifest = load_manifest(root)
        runtime_root, state_path = trusted_runtime(root, manifest)
        sys.path.insert(0, str(runtime_root))
        from engineering_harness_gate.lifecycle import lifecycle_main

        return lifecycle_main(
            sys.argv[1:],
            repo=root,
            state_path=state_path,
            config_path=root / ".agent-harness" / "config.json",
            profile_path=root / ".agent-harness" / "repo-profile.json",
        )
    except (
        ImportError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        print(
            json.dumps(
                {"reason": str(error), "status": "denied"},
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
