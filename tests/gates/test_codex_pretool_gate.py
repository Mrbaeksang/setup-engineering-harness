from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from runtime.application.lease_lifecycle import (
    EvidenceSpec,
    LeaseRequest,
    build_lease_request_command,
    observe_outside_scope_tree,
)
from runtime.adapters.codex.pretool_gate import (
    READ_ONLY_RESEARCH_TOOLS_ENV,
    STATE_PATH_ENV,
    CodexGateAdapter,
    FileGateStateSource,
    build_read_broker_command,
    main,
)
from runtime.domain.gate import parse_gate_state
from runtime.ports.gate_state_source import GateStateReadError
from tests.gates.support import (
    ACCEPTANCE_HASH,
    EVIDENCE_CONTENT,
    NOW,
    MemoryStateSource,
    state_bytes,
)


class BrokenStateSource:
    def read(self) -> bytes:
        raise GateStateReadError("simulated unreadable state")


class CodexAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name, "project").resolve()
        self.root.mkdir()
        Path(self.root, "src").mkdir()
        Path(self.root, "evidence.txt").write_bytes(EVIDENCE_CONTENT)
        state = parse_gate_state(state_bytes(self.root, locked=True))
        self.read_broker_command = build_read_broker_command(state, "map")

    def adapter(self, **state_options: object) -> CodexGateAdapter:
        scopes = state_options.get("allowed_globs")
        allowed_globs = ["src/**"] if scopes is None else scopes
        if not isinstance(allowed_globs, list):
            raise TypeError("test allowed_globs must be a list")
        state_options.setdefault(
            "base_tree_hash",
            observe_outside_scope_tree(self.root, allowed_globs),
        )
        return CodexGateAdapter(
            MemoryStateSource(state_bytes(self.root, **state_options)),
            clock=lambda: NOW,
        )

    def payload(
        self,
        tool_name: str,
        tool_input: dict[str, object],
        *,
        cwd: Path | None = None,
    ) -> dict[str, object]:
        return {
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "cwd": str(cwd or self.root),
        }

    def test_locked_gate_denies_apply_patch_with_current_codex_json(self) -> None:
        response = self.adapter(locked=True).hook_response(
            self.payload(
                "apply_patch",
                {
                    "command": (
                        "*** Begin Patch\n"
                        "*** Add File: src/new.py\n"
                        "+value = 1\n"
                        "*** End Patch\n"
                    )
                },
            )
        )

        self.assertEqual(
            response["hookSpecificOutput"]["hookEventName"], "PreToolUse"
        )
        self.assertEqual(
            response["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn(
            "Write Lease",
            response["hookSpecificOutput"]["permissionDecisionReason"],
        )

    def test_exact_read_broker_shape_is_only_locked_execution_allowed(self) -> None:
        adapter = self.adapter(locked=True)
        exact = adapter.evaluate_payload(
            self.payload("Bash", {"command": self.read_broker_command})
        )
        with_extra_field = adapter.evaluate_payload(
            self.payload(
                "Bash",
                {"command": self.read_broker_command, "timeout": 1000},
            )
        )
        with_suffix = adapter.evaluate_payload(
            self.payload(
                "Bash",
                {"command": f"{self.read_broker_command}; touch escaped"},
            )
        )

        self.assertTrue(exact.allowed)
        self.assertEqual(with_extra_field.code, "unbrokered-execution")
        self.assertEqual(with_suffix.code, "unbrokered-execution")

    def test_exact_lease_request_is_allowed_but_shell_variants_are_denied(
        self,
    ) -> None:
        state = parse_gate_state(state_bytes(self.root, locked=True))
        request = LeaseRequest(
            acceptance_hash=ACCEPTANCE_HASH,
            allowed_globs=("src/calculate.py",),
            verification_ids=("test",),
            evidence=(
                EvidenceSpec(
                    kind="repository-fact",
                    source_path="evidence.txt",
                ),
            ),
        )
        command = build_lease_request_command(state, request)
        adapter = self.adapter(locked=True)

        exact = adapter.evaluate_payload(
            self.payload("Bash", {"command": command})
        )
        variants = (
            command + " > result.json",
            command + "; touch escaped",
            "env X=1 " + command,
            command.replace(" request ", " approve ", 1),
        )

        self.assertTrue(exact.allowed)
        self.assertEqual(exact.code, "lease-request")
        for variant in variants:
            with self.subTest(variant=variant):
                denied = adapter.evaluate_payload(
                    self.payload("Bash", {"command": variant})
                )
                self.assertFalse(denied.allowed)
                self.assertEqual(denied.code, "unbrokered-execution")

    def test_shell_redirection_sed_and_python_write_are_always_denied(self) -> None:
        adapter = self.adapter()
        commands = (
            "printf x > src/a.py",
            "sed -i 's/a/b/' src/a.py",
            "python3 -c \"open('src/a.py','w').write('x')\"",
        )

        for command in commands:
            with self.subTest(command=command):
                decision = adapter.evaluate_payload(
                    self.payload("Bash", {"command": command})
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.code, "unbrokered-execution")

    def test_exact_verification_commands_require_an_active_lease(self) -> None:
        command = (
            f"/usr/bin/python3 "
            f"{self.root / '.agent-harness/bin/run_verification.py'} run test"
        )
        active = self.adapter(allowed_commands=[command])
        bash = active.evaluate_payload(
            self.payload("Bash", {"command": command})
        )
        exec_command = active.evaluate_payload(
            self.payload("exec_command", {"cmd": command})
        )
        locked = self.adapter(
            locked=True, allowed_commands=[command]
        ).evaluate_payload(
            self.payload("Bash", {"command": command})
        )
        expired = self.adapter(
            expires_at=NOW, allowed_commands=[command]
        ).evaluate_payload(
            self.payload("Bash", {"command": command})
        )
        wrong_cwd = active.evaluate_payload(
            self.payload(
                "Bash",
                {"command": command},
                cwd=self.root / "src",
            )
        )

        self.assertTrue(bash.allowed)
        self.assertTrue(exec_command.allowed)
        self.assertFalse(locked.allowed)
        self.assertFalse(expired.allowed)
        self.assertEqual(expired.code, "expired-lease")
        self.assertEqual(wrong_cwd.code, "unbrokered-execution")

    def test_verification_command_variants_and_arrays_are_denied(self) -> None:
        command = (
            f"/usr/bin/python3 "
            f"{self.root / '.agent-harness/bin/run_verification.py'} run test"
        )
        adapter = self.adapter(allowed_commands=[command])
        inputs = (
            {"command": f"{command} extra"},
            {"command": f"env CI=1 {command}"},
            {"command": f"{command} > result.txt"},
            {"command": f"{command}; touch escaped"},
            {"command": command.split()},
            {"command": command.replace(" run test", " run build")},
            {"command": command, "timeout": 1000},
            {"command": "npm test"},
        )

        for tool_input in inputs:
            with self.subTest(tool_input=tool_input):
                decision = adapter.evaluate_payload(
                    self.payload("Bash", tool_input)
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.code, "unbrokered-execution")

    def test_read_broker_rejects_wrong_interpreter_path_and_shell_syntax(
        self,
    ) -> None:
        adapter = self.adapter(locked=True)
        state = parse_gate_state(state_bytes(self.root, locked=True))
        commands = (
            build_read_broker_command(state, "map").replace(
                "/usr/bin/python3", "/bin/sh", 1
            ),
            build_read_broker_command(state, "map").replace(
                "read_context.py", "other.py", 1
            ),
            f"{build_read_broker_command(state, 'map')} | cat",
            f"{build_read_broker_command(state, 'map')} $(touch escaped)",
            build_read_broker_command(state, "map").replace(" map", " deploy"),
        )

        for command in commands:
            with self.subTest(command=command):
                decision = adapter.evaluate_payload(
                    self.payload("Bash", {"command": command})
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.code, "unbrokered-execution")

    def test_native_write_scope_and_patch_move_are_enforced(self) -> None:
        adapter = self.adapter()
        allowed = adapter.evaluate_payload(
            self.payload("Write", {"file_path": "src/new.py", "content": "x"})
        )
        outside = adapter.evaluate_payload(
            self.payload("Write", {"file_path": "tests/new.py", "content": "x"})
        )
        patch_move = adapter.evaluate_payload(
            self.payload(
                "apply_patch",
                {
                    "command": (
                        "*** Begin Patch\n"
                        "*** Update File: src/a.py\n"
                        "*** Move to: tests/a.py\n"
                        "@@\n-x\n+y\n"
                        "*** End Patch\n"
                    )
                },
            )
        )

        self.assertTrue(allowed.allowed)
        self.assertEqual(outside.code, "out-of-scope")
        self.assertEqual(patch_move.code, "out-of-scope")

    def test_actual_outside_scope_and_evidence_drift_fail_closed(self) -> None:
        adapter = self.adapter()
        first = adapter.evaluate_payload(
            self.payload("Write", {"file_path": "src/new.py", "content": "x"})
        )
        self.assertTrue(first.allowed)

        Path(self.root, "src", "new.py").write_text("first authorized write\n")
        second = adapter.evaluate_payload(
            self.payload("Write", {"file_path": "src/second.py", "content": "x"})
        )
        self.assertTrue(second.allowed)

        outside = Path(self.root, "outside.txt")
        outside.write_text("external drift\n")
        drifted = adapter.evaluate_payload(
            self.payload("Write", {"file_path": "src/third.py", "content": "x"})
        )
        self.assertFalse(drifted.allowed)
        self.assertEqual(drifted.code, "runtime-attestation-failed")

        outside.unlink()
        Path(self.root, "evidence.txt").write_text("changed evidence\n")
        evidence_drift = adapter.evaluate_payload(
            self.payload("Write", {"file_path": "src/fourth.py", "content": "x"})
        )
        self.assertFalse(evidence_drift.allowed)
        self.assertEqual(
            evidence_drift.code, "runtime-attestation-failed"
        )

    def test_real_symlink_and_traversal_resolution_are_denied(self) -> None:
        outside = Path(self.temp.name, "outside")
        outside.mkdir()
        os.symlink(outside, Path(self.root, "src", "link"))
        adapter = self.adapter()

        symlink = adapter.evaluate_payload(
            self.payload(
                "Write",
                {"file_path": "src/link/escape.py", "content": "x"},
            )
        )
        traversal = adapter.evaluate_payload(
            self.payload(
                "Write", {"file_path": "../escape.py", "content": "x"}
            )
        )

        self.assertEqual(symlink.code, "symlink-escape")
        self.assertEqual(traversal.code, "path-traversal")

    def test_unknown_tool_and_malformed_action_are_denied(self) -> None:
        unknown = self.adapter().evaluate_payload(
            self.payload("mcp__surprise__write", {"path": "src/a.py"})
        )
        malformed = self.adapter().evaluate_payload(
            {"tool_name": "Write", "tool_input": {"path": "src/a.py"}}
        )

        self.assertEqual(unknown.code, "unknown-tool")
        self.assertEqual(malformed.code, "malformed-action")

        ambiguous_path = self.adapter().evaluate_payload(
            self.payload(
                "Write",
                {
                    "file_path": "src/allowed.py",
                    "path": "../outside.py",
                    "content": "x",
                },
            )
        )
        self.assertEqual(ambiguous_path.code, "malformed-action")

        wrong_event_payload = self.payload(
            "Write", {"path": "src/a.py", "content": "x"}
        )
        wrong_event_payload["hook_event_name"] = "PostToolUse"
        wrong_event = self.adapter().evaluate_payload(wrong_event_payload)
        self.assertFalse(wrong_event.allowed)
        self.assertEqual(wrong_event.code, "malformed-action")

    def test_only_exact_configured_read_only_research_tool_is_allowed(
        self,
    ) -> None:
        configured_name = "mcp__context7__query-docs"
        adapter = CodexGateAdapter(
            MemoryStateSource(state_bytes(self.root, locked=True)),
            clock=lambda: NOW,
            read_only_research_tools=frozenset({configured_name}),
        )

        allowed = adapter.evaluate_payload(
            self.payload(
                configured_name,
                {"libraryId": "/reactjs/react.dev", "query": "use"},
            )
        )
        unknown = adapter.evaluate_payload(
            self.payload(
                "mcp__context7__other",
                {"query": "use"},
            )
        )
        write = CodexGateAdapter(
            MemoryStateSource(state_bytes(self.root, locked=True)),
            clock=lambda: NOW,
            read_only_research_tools=frozenset({"Write"}),
        ).evaluate_payload(
            self.payload(
                "Write",
                {"file_path": "src/a.py", "content": "x"},
            )
        )

        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.code, "read-only-research")
        self.assertEqual(unknown.code, "unknown-tool")
        self.assertFalse(write.allowed)
        self.assertEqual(write.code, "write-locked")

    def test_missing_malformed_and_unreadable_state_deny(self) -> None:
        malformed = CodexGateAdapter(
            MemoryStateSource(b"{"),
            clock=lambda: NOW,
        ).evaluate_payload(
            self.payload("Bash", {"command": self.read_broker_command})
        )
        unreadable = CodexGateAdapter(
            BrokenStateSource(),
            clock=lambda: NOW,
        ).evaluate_payload(
            self.payload("Bash", {"command": self.read_broker_command})
        )
        missing = FileGateStateSource(
            Path(self.temp.name, "missing.json")
        )
        missing_decision = CodexGateAdapter(
            missing, clock=lambda: NOW
        ).evaluate_payload(
            self.payload("Bash", {"command": self.read_broker_command})
        )

        for decision in (malformed, unreadable, missing_decision):
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.code, "invalid-state")

    def test_state_file_inside_project_is_not_authoritative(self) -> None:
        state_path = Path(self.root, "state.json")
        state_path.write_bytes(state_bytes(self.root))
        decision = CodexGateAdapter(
            FileGateStateSource(state_path), clock=lambda: NOW
        ).evaluate_payload(
            self.payload("Bash", {"command": self.read_broker_command})
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "invalid-state")
        self.assertIn("outside the writable Project", decision.reason)

    def test_state_source_rejects_symlinks_and_non_regular_files(self) -> None:
        external_state = Path(self.temp.name, "external-state.json")
        external_state.write_bytes(state_bytes(self.root))
        symlink_state = Path(self.temp.name, "state-link.json")
        symlink_state.symlink_to(external_state)

        for path in (symlink_state, Path(self.temp.name)):
            with self.subTest(path=path):
                decision = CodexGateAdapter(
                    FileGateStateSource(path), clock=lambda: NOW
                ).evaluate_payload(
                    self.payload(
                        "Bash", {"command": self.read_broker_command}
                    )
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.code, "invalid-state")

    def test_expired_lease_denies_native_write(self) -> None:
        decision = self.adapter(expires_at=NOW).evaluate_payload(
            self.payload("Write", {"file_path": "src/a.py", "content": "x"})
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "expired-lease")


class CodexCliTests(unittest.TestCase):
    def test_cli_reads_stdin_and_emits_fail_closed_hook_json(self) -> None:
        stdin = io.StringIO(
            json.dumps(
                {
                    "tool_name": "Write",
                    "tool_input": {"file_path": "src/a.py"},
                    "cwd": "/tmp/project",
                }
            )
        )
        stdout = io.StringIO()

        result = main(stdin=stdin, stdout=stdout, environ={})
        payload = json.loads(stdout.getvalue())

        self.assertEqual(result, 0)
        self.assertEqual(
            payload,
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        f"{STATE_PATH_ENV} is missing; Gate fails closed."
                    ),
                }
            },
        )

    def test_cli_rejects_malformed_or_mutating_research_allowlist(
        self,
    ) -> None:
        payload = json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__context7__query-docs",
                "tool_input": {"query": "use"},
                "cwd": "/tmp/project",
            }
        )
        for allowlist in ('{"not":"a-list"}', '["exec_command"]'):
            with self.subTest(allowlist=allowlist):
                stdout = io.StringIO()
                result = main(
                    stdin=io.StringIO(payload),
                    stdout=stdout,
                    environ={
                        READ_ONLY_RESEARCH_TOOLS_ENV: allowlist,
                    },
                )
                response = json.loads(stdout.getvalue())
                self.assertEqual(result, 0)
                self.assertEqual(
                    response["hookSpecificOutput"][
                        "permissionDecision"
                    ],
                    "deny",
                )
                self.assertIn(
                    "research tool configuration",
                    response["hookSpecificOutput"][
                        "permissionDecisionReason"
                    ],
                )


if __name__ == "__main__":
    unittest.main()
