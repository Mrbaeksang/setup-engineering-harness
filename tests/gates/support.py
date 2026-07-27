from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from runtime.domain.gate import (
    EvidenceHash,
    evidence_set_hash,
    lease_state_hash,
    parse_gate_state,
)


NOW = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)
DIGEST_A = f"sha256:{'a' * 64}"
EVIDENCE_CONTENT = b"bounded evidence\n"
DIGEST_B = f"sha256:{hashlib.sha256(EVIDENCE_CONTENT).hexdigest()}"
ACCEPTANCE_HASH = f"sha256:{hashlib.sha256(b'accepted task').hexdigest()}"


def state_payload(
    project_root: Path,
    *,
    locked: bool = False,
    phase: str = "implementing",
    pending_decisions: list[str] | None = None,
    allowed_globs: list[str] | None = None,
    allowed_commands: list[str] | None = None,
    expires_at: datetime | None = None,
    base_tree_hash: str = DIGEST_A,
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    verification_command = (
        f"/usr/bin/python3 "
        f"{root / '.agent-harness/bin/run_verification.py'} run test"
    )
    evidence = [
        {
            "id": "EVIDENCE-1",
            "kind": "repository-fact",
            "sourcePath": "evidence.txt",
            "contentHash": DIGEST_B,
        }
    ]
    evidence_hash = evidence_set_hash(
        (
            EvidenceHash(
                id="EVIDENCE-1",
                kind="repository-fact",
                source_path="evidence.txt",
                content_hash=DIGEST_B,
            ),
        )
    )
    payload: dict[str, Any] = {
        "schemaVersion": 1,
        "taskId": "TASK-1",
        "projectId": "PROJECT-1",
        "projectRoot": str(root),
        "readBrokerPythonExecutables": [
            "/usr/bin/python3",
            "/usr/bin/python3.12",
        ],
        "protectedGlobs": [],
        "baseTreeHash": base_tree_hash,
        "acceptanceHash": ACCEPTANCE_HASH,
        "phase": phase,
        "evidence": evidence,
        "pendingDecisions": pending_decisions or [],
        "writeLease": None,
    }
    if not locked:
        binding = lease_state_hash(parse_gate_state(json.dumps(payload)))
        payload["writeLease"] = {
            "id": "LEASE-1",
            "taskId": "TASK-1",
            "projectId": "PROJECT-1",
            "baseTreeHash": base_tree_hash,
            "acceptanceHash": ACCEPTANCE_HASH,
            "issuedForEvidenceHash": evidence_hash,
            "issuedForStateHash": binding,
            "issuedAt": (NOW - timedelta(minutes=1)).isoformat(),
            "expiresAt": (
                expires_at or NOW + timedelta(minutes=10)
            ).isoformat(),
            "allowedGlobs": (
                ["src/**"] if allowed_globs is None else allowed_globs
            ),
            "allowedCommands": (
                [verification_command]
                if allowed_commands is None
                else allowed_commands
            ),
        }
    return payload


def state_bytes(project_root: Path, **kwargs: Any) -> bytes:
    return json.dumps(state_payload(project_root, **kwargs)).encode("utf-8")


class MemoryStateSource:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def read(self) -> bytes:
        return self.payload
