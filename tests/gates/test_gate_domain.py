from __future__ import annotations

import json
import unittest
from datetime import timedelta
from pathlib import PurePath

from runtime.domain.gate import (
    ActionKind,
    GateAction,
    PathFact,
    StateValidationError,
    evidence_set_hash,
    evaluate_gate,
    evaluate_write_lease,
    parse_gate_state,
)
from tests.gates.support import DIGEST_A, NOW, state_payload


class GateStateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = PurePath("/workspace/project")

    def parse(self, **changes: object):
        payload = state_payload(self.root)
        payload.update(changes)
        return parse_gate_state(json.dumps(payload))

    def test_contract_contains_task_project_tree_evidence_decisions_and_lease(
        self,
    ) -> None:
        state = self.parse()

        self.assertEqual(state.task_id, "TASK-1")
        self.assertEqual(state.project_id, "PROJECT-1")
        self.assertEqual(state.base_tree_hash, DIGEST_A)
        self.assertEqual(len(state.evidence), 1)
        self.assertEqual(state.pending_decisions, ())
        self.assertEqual(state.write_lease.allowed_globs, ("src/**",))
        self.assertEqual(
            state.write_lease.allowed_commands,
            (
                "/usr/bin/python3 "
                "/workspace/project/.agent-harness/bin/run_verification.py "
                "run test",
            ),
        )

    def test_malformed_and_incomplete_state_are_rejected(self) -> None:
        with self.assertRaises(StateValidationError):
            parse_gate_state(b"{not-json")

        payload = state_payload(self.root)
        del payload["baseTreeHash"]
        with self.assertRaises(StateValidationError):
            parse_gate_state(json.dumps(payload))

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaises(StateValidationError):
            parse_gate_state(
                '{"schemaVersion":1,"schemaVersion":1}'
            )

    def test_unsafe_and_empty_allowed_globs_are_rejected(self) -> None:
        for globs in ([], ["../src/**"], ["/src/**"], ["src/[ab].py"]):
            with self.subTest(globs=globs):
                payload = state_payload(self.root, allowed_globs=globs)
                with self.assertRaises(StateValidationError):
                    parse_gate_state(json.dumps(payload))

    def test_allowed_commands_are_exact_non_empty_and_unique(self) -> None:
        for commands in (
            [""],
            ["   "],
            ["npm test", "npm test"],
            [None],
        ):
            with self.subTest(commands=commands):
                payload = state_payload(
                    self.root, allowed_commands=commands
                )
                with self.assertRaises(StateValidationError):
                    parse_gate_state(json.dumps(payload))


class PureGatePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = PurePath("/workspace/project")

    def state(self, **kwargs: object):
        return parse_gate_state(
            json.dumps(state_payload(self.root, **kwargs))
        )

    def write(
        self,
        requested: str,
        *,
        lexical: str | None = None,
        resolved: str | None = None,
    ) -> GateAction:
        absolute = f"/workspace/project/{requested}"
        return GateAction(
            tool_name="Write",
            kind=ActionKind.NATIVE_WRITE,
            paths=(
                PathFact(
                    requested=requested,
                    lexical_path=PurePath(lexical or absolute),
                    resolved_path=PurePath(resolved or absolute),
                ),
            ),
        )

    def test_locked_state_denies_native_write(self) -> None:
        decision = evaluate_gate(
            self.state(locked=True), self.write("src/a.py"), now=NOW
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "write-locked")

    def test_valid_lease_allows_only_scoped_native_paths(self) -> None:
        allowed = evaluate_gate(
            self.state(), self.write("src/nested/a.py"), now=NOW
        )
        denied = evaluate_gate(
            self.state(), self.write("tests/a.py"), now=NOW
        )

        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.code, "scoped-write")
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.code, "out-of-scope")

    def test_write_lease_status_is_reusable_without_a_tool_path(self) -> None:
        active = evaluate_write_lease(self.state(), now=NOW)
        locked = evaluate_write_lease(self.state(locked=True), now=NOW)

        self.assertTrue(active.allowed)
        self.assertEqual(active.code, "active-write-lease")
        self.assertFalse(locked.allowed)
        self.assertEqual(locked.code, "write-locked")

    def test_empty_evidence_cannot_authorize_a_bound_lease(self) -> None:
        payload = state_payload(self.root)
        payload["evidence"] = []
        payload["writeLease"]["issuedForEvidenceHash"] = evidence_set_hash(())

        decision = evaluate_write_lease(
            parse_gate_state(json.dumps(payload)),
            now=NOW,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "missing-evidence")

    def test_path_traversal_and_symlink_escape_are_denied(self) -> None:
        traversal = evaluate_gate(
            self.state(),
            self.write(
                "../outside.py",
                lexical="/workspace/outside.py",
                resolved="/workspace/outside.py",
            ),
            now=NOW,
        )
        symlink = evaluate_gate(
            self.state(),
            self.write(
                "src/link/escape.py",
                resolved="/workspace/outside/escape.py",
            ),
            now=NOW,
        )

        self.assertEqual(traversal.code, "path-traversal")
        self.assertEqual(symlink.code, "symlink-escape")

        unnormalized = evaluate_gate(
            self.state(),
            self.write(
                "src/../outside.py",
                lexical="/workspace/project/src/../outside.py",
                resolved="/workspace/project/outside.py",
            ),
            now=NOW,
        )
        self.assertEqual(unnormalized.code, "path-traversal")

    def test_symlink_alias_cannot_bypass_allowed_glob(self) -> None:
        decision = evaluate_gate(
            self.state(allowed_globs=["src/public/**"]),
            self.write(
                "src/public/link.py",
                resolved="/workspace/project/src/private/secret.py",
            ),
            now=NOW,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "out-of-scope")

    def test_minimum_protected_paths_override_a_global_write_glob(self) -> None:
        paths = (
            ".env",
            ".ENV",
            "nested/.env.local",
            "nested/.Env.Local",
            ".git",
            ".git/config",
            "certs/server.pem",
            "keys/my-private-key.txt",
            ".agent-harness",
            ".agent-harness/config.json",
            "PACKAGE.JSON",
        )

        for path in paths:
            with self.subTest(path=path):
                decision = evaluate_gate(
                    self.state(allowed_globs=["**"]),
                    self.write(path),
                    now=NOW,
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.code, "protected-path")

    def test_expired_future_and_stale_leases_are_denied(self) -> None:
        expired = evaluate_gate(
            self.state(expires_at=NOW), self.write("src/a.py"), now=NOW
        )

        future_payload = state_payload(self.root)
        future_payload["writeLease"]["issuedAt"] = (
            NOW + timedelta(minutes=1)
        ).isoformat()
        future_payload["writeLease"]["expiresAt"] = (
            NOW + timedelta(minutes=2)
        ).isoformat()
        future = evaluate_gate(
            parse_gate_state(json.dumps(future_payload)),
            self.write("src/a.py"),
            now=NOW,
        )

        stale_tree_payload = state_payload(self.root)
        stale_tree_payload["writeLease"]["baseTreeHash"] = (
            f"sha256:{'c' * 64}"
        )
        stale_tree = evaluate_gate(
            parse_gate_state(json.dumps(stale_tree_payload)),
            self.write("src/a.py"),
            now=NOW,
        )

        stale_evidence_payload = state_payload(self.root)
        stale_evidence_payload["evidence"][0]["contentHash"] = (
            f"sha256:{'d' * 64}"
        )
        stale_evidence = evaluate_gate(
            parse_gate_state(json.dumps(stale_evidence_payload)),
            self.write("src/a.py"),
            now=NOW,
        )

        self.assertEqual(expired.code, "expired-lease")
        self.assertEqual(future.code, "lease-not-active")
        self.assertEqual(stale_tree.code, "stale-base-tree")
        self.assertEqual(stale_evidence.code, "stale-evidence")

    def test_pending_decision_and_wrong_phase_deny_write(self) -> None:
        pending = evaluate_gate(
            self.state(pending_decisions=["DECISION-1"]),
            self.write("src/a.py"),
            now=NOW,
        )
        verifying = evaluate_gate(
            self.state(phase="verifying"),
            self.write("src/a.py"),
            now=NOW,
        )

        self.assertEqual(pending.code, "pending-decisions")
        self.assertEqual(verifying.code, "wrong-phase")

    def test_unknown_and_shell_actions_fail_closed(self) -> None:
        unknown = evaluate_gate(
            self.state(),
            GateAction("mcp__new__write", ActionKind.UNKNOWN),
            now=NOW,
        )
        shell = evaluate_gate(
            self.state(), GateAction("Bash", ActionKind.SHELL_EXECUTION), now=NOW
        )

        self.assertEqual(unknown.code, "unknown-tool")
        self.assertEqual(shell.code, "unbrokered-execution")

    def test_verification_command_requires_active_lease_and_exact_command(
        self,
    ) -> None:
        command = (
            "/usr/bin/python3 "
            "/workspace/project/.agent-harness/bin/run_verification.py run test"
        )
        exact = evaluate_gate(
            self.state(),
            GateAction(
                "Bash",
                ActionKind.VERIFICATION_COMMAND,
                command=command,
                working_directory=self.root,
            ),
            now=NOW,
        )
        unknown = evaluate_gate(
            self.state(),
            GateAction(
                "Bash",
                ActionKind.VERIFICATION_COMMAND,
                command="npm run build",
                working_directory=self.root,
            ),
            now=NOW,
        )
        wrong_cwd = evaluate_gate(
            self.state(),
            GateAction(
                "Bash",
                ActionKind.VERIFICATION_COMMAND,
                command=command,
                working_directory=PurePath("/workspace/project/src"),
            ),
            now=NOW,
        )

        self.assertTrue(exact.allowed)
        self.assertEqual(exact.code, "verification-command")
        self.assertFalse(unknown.allowed)
        self.assertEqual(wrong_cwd.code, "verification-cwd")
        self.assertEqual(unknown.code, "command-not-allowed")


if __name__ == "__main__":
    unittest.main()
