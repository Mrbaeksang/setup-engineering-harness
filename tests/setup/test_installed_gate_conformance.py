from __future__ import annotations

import importlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from runtime.application.lease_lifecycle import observe_outside_scope_tree
from runtime.adapters.codex.pretool_gate import CodexGateAdapter as CanonicalAdapter
from runtime.domain.gate import (
    EvidenceHash,
    evidence_set_hash,
    lease_state_hash,
    parse_gate_state,
)
from tests.gates.support import (
    ACCEPTANCE_HASH,
    DIGEST_B as EVIDENCE_DIGEST,
    EVIDENCE_CONTENT,
)

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "skills" / "setup-engineering-harness" / "scripts" / "setup_harness.py"
class MemoryState:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self.payload


class InstalledGateConformanceTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="installed-gate-conformance-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / "project"
        self.repo.mkdir()
        (self.repo / "src").mkdir()
        (self.repo / "tests").mkdir()
        (self.repo / "evidence.txt").write_bytes(EVIDENCE_CONTENT)
        (self.repo / "package.json").write_text(
            json.dumps(
                {
                    "packageManager": "npm@10.8.0",
                    "scripts": {"test": "node --test"},
                }
            )
            + "\n"
        )
        (self.repo / "package-lock.json").write_text("{}\n")
        self.state_home = self.base / "state"
        environment = os.environ.copy()
        environment["XDG_STATE_HOME"] = str(self.state_home)
        installed = subprocess.run(
            [sys.executable, str(SCRIPT), "install", "--repo", str(self.repo)],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(installed.returncode, 3, installed.stdout + installed.stderr)
        self.manifest = json.loads(
            (self.repo / ".agent-harness" / "manifest.json").read_text()
        )
        self.host = self.manifest["host_runtime"]
        self.runtime_dir = Path(self.host["state_path"]).parent / "runtime"
        sys.path.insert(0, str(self.runtime_dir))
        self.addCleanup(sys.path.remove, str(self.runtime_dir))
        self.bundle = importlib.import_module("engineering_harness_gate.codex")
        self.addCleanup(self._unload_bundle)
        self.now = datetime.now(timezone.utc)
        self.python = str(Path(sys.executable).resolve())
        self.read_broker = shlex.join(
            [
                self.python,
                str(self.repo / ".agent-harness" / "bin" / "read_context.py"),
                "map",
            ]
        )
        self.verification = shlex.join(
            [
                self.python,
                str(self.repo / ".agent-harness" / "bin" / "run_verification.py"),
                "run",
                "test",
            ]
        )

    @staticmethod
    def _unload_bundle() -> None:
        for name in tuple(sys.modules):
            if name == "engineering_harness_gate" or name.startswith(
                "engineering_harness_gate."
            ):
                del sys.modules[name]

    def state(
        self,
        *,
        locked: bool = False,
        phase: str = "implementing",
        evidence: list[dict[str, str]] | None = None,
        pending: list[str] | None = None,
        allowed_globs: list[str] | None = None,
        allowed_commands: list[str] | None = None,
        base_tree: str | None = None,
        lease_tree: str | None = None,
        expires_at: datetime | None = None,
        evidence_hash: str | None = None,
    ) -> dict[str, Any]:
        evidence_items = (
            [
                {
                    "id": "EVIDENCE-1",
                    "kind": "repository-fact",
                    "sourcePath": "evidence.txt",
                    "contentHash": EVIDENCE_DIGEST,
                }
            ]
            if evidence is None
            else evidence
        )
        canonical_evidence = tuple(
            EvidenceHash(
                id=item["id"],
                kind=item["kind"],
                source_path=item["sourcePath"],
                content_hash=item["contentHash"],
            )
            for item in evidence_items
        )
        globs = ["src/**"] if allowed_globs is None else allowed_globs
        actual_base = observe_outside_scope_tree(self.repo, globs)
        state_base = base_tree or actual_base
        state: dict[str, Any] = {
            "acceptanceHash": ACCEPTANCE_HASH,
            "baseTreeHash": state_base,
            "evidence": evidence_items,
            "pendingDecisions": pending or [],
            "phase": phase,
            "projectId": "PROJECT-1",
            "projectRoot": str(self.repo),
            "protectedGlobs": [],
            "readBrokerPythonExecutables": [self.python],
            "schemaVersion": 1,
            "taskId": "TASK-1",
            "writeLease": None,
        }
        if not locked:
            binding = lease_state_hash(
                parse_gate_state(json.dumps(state))
            )
            state["writeLease"] = {
                "acceptanceHash": ACCEPTANCE_HASH,
                "allowedCommands": [self.verification]
                if allowed_commands is None
                else allowed_commands,
                "allowedGlobs": globs,
                "baseTreeHash": lease_tree or state_base,
                "expiresAt": (
                    expires_at or self.now + timedelta(minutes=10)
                ).isoformat(),
                "id": "LEASE-1",
                "issuedAt": (self.now - timedelta(minutes=1)).isoformat(),
                "issuedForEvidenceHash": evidence_hash
                or evidence_set_hash(canonical_evidence),
                "issuedForStateHash": binding,
                "projectId": "PROJECT-1",
                "taskId": "TASK-1",
            }
        return state

    def payload(
        self,
        tool: str,
        tool_input: dict[str, Any],
        *,
        cwd: Path | None = None,
    ) -> dict[str, Any]:
        return {
            "cwd": str(cwd or self.repo),
            "hook_event_name": "PreToolUse",
            "tool_input": tool_input,
            "tool_name": tool,
        }

    def compare(
        self, name: str, state: dict[str, Any], payload: dict[str, Any]
    ) -> tuple[bool, str]:
        canonical = CanonicalAdapter(
            MemoryState(state), clock=lambda: self.now
        ).evaluate_payload(payload)
        bundled = self.bundle.CodexGateAdapter(
            MemoryState(state), clock=lambda: self.now
        ).evaluate_payload(payload)
        self.assertEqual(
            (bundled.allowed, bundled.code),
            (canonical.allowed, canonical.code),
            name,
        )
        return bundled.allowed, bundled.code

    def test_common_attack_vectors_match_canonical_gate(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        (self.repo / "src" / "escape").symlink_to(outside, target_is_directory=True)
        valid = self.state()
        cases = [
            (
                "write",
                valid,
                self.payload("Write", {"path": "src/a.py", "content": "x"}),
                (True, "scoped-write"),
            ),
            (
                "edit",
                valid,
                self.payload("Edit", {"file_path": "src/a.py", "new_string": "x"}),
                (True, "scoped-write"),
            ),
            (
                "multi-edit",
                valid,
                self.payload(
                    "MultiEdit",
                    {
                        "edits": [
                            {"path": "src/a.py"},
                            {"path": "src/b.py"},
                        ]
                    },
                ),
                (True, "scoped-write"),
            ),
            (
                "patch",
                valid,
                self.payload(
                    "apply_patch",
                    {
                        "patch": "*** Begin Patch\n*** Update File: src/a.py\n@@\n-x\n+y\n*** End Patch\n"
                    },
                ),
                (True, "scoped-write"),
            ),
            (
                "out-of-scope",
                valid,
                self.payload("Write", {"path": "tests/a.py"}),
                (False, "out-of-scope"),
            ),
            (
                "protected",
                self.state(allowed_globs=["**"]),
                self.payload("Write", {"path": ".env"}),
                (False, "protected-path"),
            ),
            (
                "protected-case-alias",
                self.state(allowed_globs=["**"]),
                self.payload("Write", {"path": ".ENV"}),
                (False, "protected-path"),
            ),
            (
                "traversal",
                self.state(allowed_globs=["**"]),
                self.payload("Write", {"path": "../outside.py"}),
                (False, "path-traversal"),
            ),
            (
                "symlink",
                valid,
                self.payload("Write", {"path": "src/escape/a.py"}),
                (False, "symlink-escape"),
            ),
            (
                "unknown",
                valid,
                self.payload("mcp__future__write", {}),
                (False, "unknown-tool"),
            ),
            (
                "read-broker",
                valid,
                self.payload("Bash", {"command": self.read_broker}),
                (True, "read-broker"),
            ),
            (
                "read-broker-injection",
                valid,
                self.payload("Bash", {"command": self.read_broker + " > leak"}),
                (False, "unbrokered-execution"),
            ),
            (
                "verification",
                valid,
                self.payload("Bash", {"command": self.verification}),
                (True, "verification-command"),
            ),
            (
                "raw-verification",
                self.state(allowed_commands=["npm run test"]),
                self.payload("Bash", {"command": "npm run test"}),
                (False, "unbrokered-execution"),
            ),
            (
                "locked",
                self.state(locked=True),
                self.payload("Write", {"path": "src/a.py"}),
                (False, "write-locked"),
            ),
            (
                "empty-evidence",
                self.state(evidence=[], evidence_hash=evidence_set_hash(())),
                self.payload("Write", {"path": "src/a.py"}),
                (False, "missing-evidence"),
            ),
            (
                "pending",
                self.state(pending=["DECISION-1"]),
                self.payload("Write", {"path": "src/a.py"}),
                (False, "pending-decisions"),
            ),
            (
                "phase",
                self.state(phase="verifying"),
                self.payload("Write", {"path": "src/a.py"}),
                (False, "wrong-phase"),
            ),
            (
                "tree",
                self.state(lease_tree=f"sha256:{'c' * 64}"),
                self.payload("Write", {"path": "src/a.py"}),
                (False, "stale-base-tree"),
            ),
            (
                "expired",
                self.state(expires_at=self.now),
                self.payload("Write", {"path": "src/a.py"}),
                (False, "expired-lease"),
            ),
        ]
        for name, state, payload, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(self.compare(name, state, payload), expected)

        wrong_event = self.payload(
            "Write", {"path": "src/a.py", "content": "x"}
        )
        wrong_event["hook_event_name"] = "PostToolUse"
        self.assertEqual(
            self.compare("wrong-event", valid, wrong_event),
            (False, "malformed-action"),
        )

    def test_installed_launcher_uses_full_scoped_lease(self) -> None:
        state_path = Path(self.host["state_path"])
        state_path.write_text(json.dumps(self.state()) + "\n")
        launcher = self.runtime_dir / "pretool_gate.py"
        arguments = [
            self.python,
            str(launcher),
            "--state",
            str(state_path),
            "--status",
            self.host["status_path"],
            "--repo",
            str(self.repo),
        ]
        allowed = subprocess.run(
            arguments,
            input=json.dumps(
                self.payload("Write", {"path": "src/launcher.py"})
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        self.assertNotIn(
            "permissionDecision",
            json.loads(allowed.stdout)["hookSpecificOutput"],
        )
        denied = subprocess.run(
            arguments,
            input=json.dumps(
                self.payload("Bash", {"command": "npm run test"})
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            json.loads(denied.stdout)["hookSpecificOutput"]["permissionDecision"],
            "deny",
        )

    def test_verification_broker_runs_only_registered_id_from_project_root(self) -> None:
        profile_path = self.repo / ".agent-harness" / "repo-profile.json"
        profile = json.loads(profile_path.read_text())
        profile["candidate_commands"] = [
            {
                "command": shlex.join([self.python, "-c", "pass"]),
                "evidence": "synthetic conformance fixture",
                "executed": False,
                "id": "test",
                "kind": "test",
            }
        ]
        profile_path.write_text(json.dumps(profile) + "\n")
        broker = self.repo / ".agent-harness" / "bin" / "run_verification.py"
        command = [self.python, str(broker), "run", "test"]
        allowed = subprocess.run(
            command,
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        wrong_cwd = subprocess.run(
            command,
            cwd=self.repo / "src",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(wrong_cwd.returncode, 2)
        unknown = subprocess.run(
            [self.python, str(broker), "run", "not-registered"],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(unknown.returncode, 2)


if __name__ == "__main__":
    unittest.main()
