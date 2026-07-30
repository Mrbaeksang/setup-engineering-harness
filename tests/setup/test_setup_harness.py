from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "setup-engineering-harness"
SCRIPT = SKILL / "scripts" / "setup_harness.py"
BRIDGE_START = b"<!-- engineering-harness:bridge:start -->"
BRIDGE_END = b"<!-- engineering-harness:bridge:end -->"


def load_installer():
    spec = importlib.util.spec_from_file_location("setup_harness_under_test", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load installer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SetupHarnessTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="engineering-harness-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.repo = self.base / "project"
        self.repo.mkdir()
        self.state_home = self.base / "state"
        self.env = os.environ.copy()
        self.env["XDG_STATE_HOME"] = str(self.state_home)

    def run_setup(
        self,
        command: str,
        *,
        as_json: bool = False,
        provider: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [sys.executable, str(SCRIPT), command, "--repo", str(self.repo)]
        if provider is not None:
            arguments.extend(["--provider", provider])
        if as_json:
            arguments.append("--json")
        return subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            env=self.env,
        )

    @staticmethod
    def snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
        if not root.exists():
            return {}
        return {
            path.relative_to(root).as_posix(): (
                path.read_bytes(),
                stat.S_IMODE(path.stat().st_mode),
            )
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def seed_javascript_project(self) -> bytes:
        original = b"# Existing instructions\r\n\r\nKeep these bytes exactly.\r\nNo final newline"
        (self.repo / "AGENTS.md").write_bytes(original)
        (self.repo / "package.json").write_text(
            json.dumps(
                {
                    "packageManager": "npm@10.8.0",
                    "scripts": {
                        "build": "example build",
                        "test": "example test",
                        "typecheck": "example typecheck",
                    },
                }
            ),
            encoding="utf-8",
        )
        (self.repo / "package-lock.json").write_text("{}\n", encoding="utf-8")
        return original

    def test_plan_is_read_only_and_deterministic(self) -> None:
        self.seed_javascript_project()
        before = self.snapshot(self.repo)
        first = self.run_setup("plan", as_json=True)
        second = self.run_setup("plan", as_json=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(self.snapshot(self.repo), before)
        self.assertFalse(self.state_home.exists())
        payload = json.loads(first.stdout)
        self.assertEqual(payload["status"], "ready")
        self.assertTrue(payload["mutations"])
        commands = payload["profile"]["candidate_commands"]
        self.assertTrue(commands)
        self.assertTrue(all(item["executed"] is False for item in commands))

    def test_plan_detects_bounded_stdlib_unittest_discovery(self) -> None:
        tests = self.repo / "tests"
        tests.mkdir()
        (tests / "__init__.py").write_text("", encoding="utf-8")
        (tests / "test_example.py").write_text(
            "import unittest\n"
            "class ExampleTest(unittest.TestCase):\n"
            "    def test_true(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )

        result = self.run_setup("plan", as_json=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        profile = json.loads(result.stdout)["profile"]
        commands = profile["candidate_commands"]
        unittest_commands = [
            item
            for item in commands
            if item["command"] == "python -m unittest discover"
        ]
        self.assertEqual(len(unittest_commands), 1)
        self.assertEqual(unittest_commands[0]["kind"], "test")
        self.assertFalse(unittest_commands[0]["executed"])

    def test_claude_plan_targets_claude_instruction_and_hook_files(self) -> None:
        original_agents = self.seed_javascript_project()
        original_claude = b"# Existing Claude instructions\n\nKeep this."
        (self.repo / "CLAUDE.md").write_bytes(original_claude)

        planned = self.run_setup(
            "plan", as_json=True, provider="claude-code"
        )

        self.assertEqual(planned.returncode, 0, planned.stderr)
        payload = json.loads(planned.stdout)
        mutation_paths = {
            mutation["path"] for mutation in payload["mutations"]
        }
        self.assertIn("CLAUDE.md", mutation_paths)
        self.assertIn(".claude/settings.json", mutation_paths)
        self.assertNotIn("AGENTS.md", mutation_paths)
        self.assertNotIn(".codex/hooks.json", mutation_paths)
        self.assertEqual((self.repo / "AGENTS.md").read_bytes(), original_agents)
        self.assertEqual((self.repo / "CLAUDE.md").read_bytes(), original_claude)

    def test_claude_install_audit_and_uninstall_are_provider_bound(self) -> None:
        original_agents = self.seed_javascript_project()
        original_claude = b"# Existing Claude instructions\n"
        (self.repo / "CLAUDE.md").write_bytes(original_claude)

        installed = self.run_setup("install", provider="claude-code")

        self.assertEqual(installed.returncode, 3, installed.stdout + installed.stderr)
        self.assertEqual((self.repo / "AGENTS.md").read_bytes(), original_agents)
        claude = (self.repo / "CLAUDE.md").read_bytes()
        self.assertTrue(claude.startswith(original_claude))
        self.assertEqual(claude.count(BRIDGE_START), 1)
        settings = json.loads(
            (self.repo / ".claude" / "settings.json").read_text()
        )
        self.assertEqual(
            settings["hooks"]["PreToolUse"][0]["matcher"], "*"
        )
        manifest = json.loads(
            (self.repo / ".agent-harness" / "manifest.json").read_text()
        )
        self.assertEqual(
            manifest["provider_hooks"]["provider"], "claude-code"
        )
        self.assertEqual(
            manifest["provider_hooks"]["path"], ".claude/settings.json"
        )
        status = json.loads(
            Path(manifest["host_runtime"]["status_path"]).read_text()
        )
        self.assertEqual(status["providerId"], "claude-code")
        repository_after_install = self.snapshot(self.repo)
        state_after_install = self.snapshot(self.state_home)

        repeated = self.run_setup("install", provider="claude-code")
        self.assertEqual(
            repeated.returncode, 3, repeated.stdout + repeated.stderr
        )
        self.assertIn("already current", repeated.stdout)
        self.assertEqual(self.snapshot(self.repo), repository_after_install)
        self.assertEqual(self.snapshot(self.state_home), state_after_install)

        wrong_provider = self.run_setup("plan", provider="codex")
        self.assertEqual(wrong_provider.returncode, 2)
        self.assertIn("installed provider is claude-code", wrong_provider.stdout)

        removed = self.run_setup("uninstall")
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assertEqual((self.repo / "CLAUDE.md").read_bytes(), original_claude)
        self.assertEqual((self.repo / "AGENTS.md").read_bytes(), original_agents)
        self.assertFalse((self.repo / ".claude" / "settings.json").exists())

    def test_legacy_codex_install_is_bound_to_explicit_provider(self) -> None:
        self.seed_javascript_project()
        self.assertEqual(self.run_setup("install").returncode, 3)
        module = load_installer()
        manifest_path = (
            self.repo / ".agent-harness" / "manifest.json"
        )
        manifest = json.loads(manifest_path.read_text())
        manifest["provider_hooks"].pop("provider")
        manifest = module.seal_manifest(manifest)
        manifest_path.write_bytes(module.json_bytes(manifest))
        status_path = Path(manifest["host_runtime"]["status_path"])
        status = json.loads(status_path.read_text())
        status.pop("providerId")
        status_path.write_bytes(module.json_bytes(status))

        migrated = self.run_setup("install")

        self.assertEqual(migrated.returncode, 3, migrated.stdout + migrated.stderr)
        migrated_manifest = json.loads(manifest_path.read_text())
        migrated_status = json.loads(status_path.read_text())
        self.assertEqual(
            migrated_manifest["provider_hooks"]["provider"], "codex"
        )
        self.assertEqual(migrated_status["providerId"], "codex")
        self.assertFalse(migrated_status["hookTrustVerified"])

    def test_plan_registers_direct_node_test_without_guessing_package_manager(
        self,
    ) -> None:
        (self.repo / "package.json").write_text(
            json.dumps(
                {
                    "scripts": {
                        "build": "vite build",
                        "test": "node --test",
                    }
                }
            ),
            encoding="utf-8",
        )

        result = self.run_setup("plan", as_json=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        profile = json.loads(result.stdout)["profile"]
        self.assertEqual(
            [
                (item["command"], item["kind"])
                for item in profile["candidate_commands"]
            ],
            [("node --test", "test")],
        )
        self.assertTrue(
            any(
                "no package manager selection was required" in note
                for note in profile["notes"]
            )
        )
        self.assertTrue(
            any(
                "script 'build'" in note and "package manager is ambiguous" in note
                for note in profile["notes"]
            )
        )

    def test_plan_rejects_shell_composition_as_direct_node_test(self) -> None:
        (self.repo / "package.json").write_text(
            json.dumps({"scripts": {"test": "node --test && echo unsafe"}}),
            encoding="utf-8",
        )

        result = self.run_setup("plan", as_json=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        profile = json.loads(result.stdout)["profile"]
        self.assertEqual(profile["candidate_commands"], [])
        self.assertTrue(
            any("package manager is ambiguous" in note for note in profile["notes"])
        )

    def test_authoritative_state_cannot_be_placed_inside_repository(self) -> None:
        self.seed_javascript_project()
        before = self.snapshot(self.repo)
        self.env["XDG_STATE_HOME"] = str(self.repo / ".state")

        result = self.run_setup("install")

        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "authoritative Harness state must be outside",
            result.stderr,
        )
        self.assertEqual(self.snapshot(self.repo), before)

    def test_install_preserves_bytes_seeds_once_and_is_idempotent(self) -> None:
        original = self.seed_javascript_project()
        first = self.run_setup("install")
        self.assertEqual(first.returncode, 3, first.stdout + first.stderr)
        self.assertIn("Harness audit: INCOMPLETE", first.stdout)
        agents = (self.repo / "AGENTS.md").read_bytes()
        self.assertTrue(agents.startswith(original))
        self.assertEqual(agents.count(BRIDGE_START), 1)
        self.assertEqual(agents.count(BRIDGE_END), 1)
        self.assertIn(
            b"audit.py` after Harness or instruction changes",
            agents,
        )
        self.assertIn(b"not ordinary\napplication-code changes", agents)

        config_path = self.repo / ".agent-harness" / "config.json"
        config = json.loads(config_path.read_text())
        config["project"]["constraints"].append("user-owned")
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        local_path = self.repo / ".agent-harness" / "local.md"
        local_path.write_text("# Local\n\nKeep me.\n", encoding="utf-8")

        project_before = self.snapshot(self.repo)
        host_before = self.snapshot(self.state_home)
        second = self.run_setup("install")
        self.assertEqual(second.returncode, 3, second.stdout + second.stderr)
        self.assertIn("already current", second.stdout)
        self.assertEqual(self.snapshot(self.repo), project_before)
        self.assertEqual(self.snapshot(self.state_home), host_before)
        self.assertIn("user-owned", config_path.read_text())
        self.assertEqual(local_path.read_text(), "# Local\n\nKeep me.\n")

        profile = json.loads(
            (self.repo / ".agent-harness" / "repo-profile.json").read_text()
        )
        self.assertTrue(
            all(item["executed"] is False for item in profile["candidate_commands"])
        )
        manifest = json.loads(
            (self.repo / ".agent-harness" / "manifest.json").read_text()
        )
        state = Path(manifest["host_runtime"]["state_path"])
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)
        self.assertEqual(
            stat.S_IMODE(Path(manifest["host_runtime"]["status_path"]).stat().st_mode),
            0o600,
        )

    def test_drift_refusal_and_explicit_repair_with_recovery(self) -> None:
        original = self.seed_javascript_project()
        installed = self.run_setup("install")
        self.assertEqual(installed.returncode, 3, installed.stdout + installed.stderr)
        router = self.repo / ".agent-harness" / "router.md"
        router.write_text(router.read_text() + "\nuser drift\n", encoding="utf-8")
        agents = self.repo / "AGENTS.md"
        agents.write_bytes(
            agents.read_bytes().replace(
                b"## Engineering Harness", b"## Drifted Engineering Harness"
            )
        )
        config_path = self.repo / ".agent-harness" / "config.json"
        config = json.loads(config_path.read_text())
        config["project"]["constraints"].append("preserve-this")
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        before = self.snapshot(self.repo)

        refused = self.run_setup("install")
        self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)
        self.assertIn("no files changed", refused.stdout)
        self.assertEqual(self.snapshot(self.repo), before)

        repaired = self.run_setup("repair")
        self.assertEqual(repaired.returncode, 3, repaired.stdout + repaired.stderr)
        self.assertNotIn("user drift", router.read_text())
        repaired_agents = agents.read_bytes()
        self.assertTrue(repaired_agents.startswith(original))
        self.assertIn(b"## Engineering Harness", repaired_agents)
        self.assertIn("preserve-this", config_path.read_text())
        recovery = list((self.repo / ".agent-harness" / "recovery").iterdir())
        self.assertGreaterEqual(len(recovery), 2)
        audit = self.run_setup("audit")
        self.assertEqual(audit.returncode, 3, audit.stdout + audit.stderr)
        self.assertNotIn("FAIL", audit.stdout)

    def test_hook_merge_preserves_unrelated_entries_and_both_hooks(self) -> None:
        self.seed_javascript_project()
        hooks_path = self.repo / ".codex" / "hooks.json"
        hooks_path.parent.mkdir()
        unrelated_pre = {
            "matcher": "^Bash$",
            "hooks": [{"type": "command", "command": "echo existing"}],
        }
        unrelated_prompt = {
            "hooks": [{"type": "command", "command": "echo prompt-existing"}]
        }
        unrelated_stop = {"hooks": [{"type": "command", "command": "echo stop"}]}
        hooks_path.write_text(
            json.dumps(
                {
                    "description": "keep",
                    "hooks": {
                        "PreToolUse": [unrelated_pre],
                        "Stop": [unrelated_stop],
                        "UserPromptSubmit": [unrelated_prompt],
                    },
                    "other": {"keep": True},
                },
                indent=4,
            )
            + "\n"
        )
        installed = self.run_setup("install")
        self.assertEqual(installed.returncode, 3, installed.stdout + installed.stderr)
        data = json.loads(hooks_path.read_text())
        self.assertEqual(data["description"], "keep")
        self.assertEqual(data["other"], {"keep": True})
        self.assertIn(unrelated_pre, data["hooks"]["PreToolUse"])
        self.assertIn(unrelated_prompt, data["hooks"]["UserPromptSubmit"])
        self.assertEqual(data["hooks"]["Stop"], [unrelated_stop])

        def managed(event: str, hook_id: str) -> list[dict]:
            return [
                entry
                for entry in data["hooks"][event]
                if hook_id
                in "\n".join(
                    hook.get("command", "") for hook in entry.get("hooks", [])
                )
            ]

        pre = managed("PreToolUse", "ENGINEERING_HARNESS_HOOK_ID=pretool-v1")
        prompt = managed(
            "UserPromptSubmit", "ENGINEERING_HARNESS_HOOK_ID=userprompt-v1"
        )
        self.assertEqual(len(pre), 1)
        self.assertEqual(len(prompt), 1)
        pre_command = pre[0]["hooks"][0]["command"]
        self.assertIn("--state", pre_command)
        self.assertIn("--status", pre_command)
        self.assertNotIn("ENGINEERING_HARNESS_GATE_STATE", pre_command)

        before = self.snapshot(self.repo)
        again = self.run_setup("install")
        self.assertEqual(again.returncode, 3, again.stdout + again.stderr)
        self.assertEqual(self.snapshot(self.repo), before)

    def test_adaptive_prompt_toggle_and_locked_hook_boundary(self) -> None:
        self.seed_javascript_project()
        self.assertEqual(self.run_setup("install").returncode, 3)
        manifest = json.loads(
            (self.repo / ".agent-harness" / "manifest.json").read_text()
        )
        host = manifest["host_runtime"]
        runtime_dir = Path(host["state_path"]).parent / "runtime"
        prompt_script = runtime_dir / "userprompt_context.py"
        gate_script = runtime_dir / "pretool_gate.py"
        payload = json.dumps(
            {"user_prompt": "Upgrade this SDK and use its library option."}
        )
        prompt_result = subprocess.run(
            [
                sys.executable,
                str(prompt_script),
                "--state",
                host["state_path"],
                "--repo",
                str(self.repo),
            ],
            input=payload,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(prompt_result.returncode, 0, prompt_result.stderr)
        context = json.loads(prompt_result.stdout)["hookSpecificOutput"][
            "additionalContext"
        ]
        self.assertIn("Dependency signal detected", context)
        self.assertIn(str(Path(sys.executable).resolve()), context)
        self.assertIn(
            str(self.repo / ".agent-harness" / "bin" / "read_context.py"),
            context,
        )
        self.assertLessEqual(len(context), 1800)
        self.assertNotIn("package.json", context)
        self.assertIn("hyphenated single-token", context)
        self.assertIn("registered proof kind/ID", context)
        self.assertIn("Obtain the lease before brokered baseline", context)

        ambiguous = subprocess.run(
            [
                sys.executable,
                str(prompt_script),
                "--state",
                host["state_path"],
                "--repo",
                str(self.repo),
            ],
            input=json.dumps(
                {
                    "user_prompt": (
                        "Add real-time customer-support chat. "
                        "Choose the stack and start implementing."
                    )
                }
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        ambiguity_context = json.loads(ambiguous.stdout)["hookSpecificOutput"][
            "additionalContext"
        ]
        self.assertIn("Ambiguity Gate", ambiguity_context)
        self.assertIn("stop after the questions", ambiguity_context)
        self.assertIn("do not retry tools", ambiguity_context)

        config_path = self.repo / ".agent-harness" / "config.json"
        config = json.loads(config_path.read_text())
        config["adaptive_task_context"]["enabled"] = False
        config_path.write_text(json.dumps(config) + "\n")
        disabled = subprocess.run(
            [
                sys.executable,
                str(prompt_script),
                "--state",
                host["state_path"],
                "--repo",
                str(self.repo),
            ],
            input=payload,
            capture_output=True,
            text=True,
            check=False,
        )
        base_context = json.loads(disabled.stdout)["hookSpecificOutput"][
            "additionalContext"
        ]
        self.assertIn("Locked-read bootstrap", base_context)
        self.assertIn("git-status", base_context)
        self.assertIn("git-diff", base_context)
        self.assertIn("use `git-diff` before completion", base_context)
        self.assertIn(".agent-harness/router.md", base_context)
        self.assertNotIn("Dependency signal detected", base_context)
        self.assertNotIn("Restate the requested outcome", base_context)

        status = host["status_path"]
        denied = subprocess.run(
            [
                sys.executable,
                str(gate_script),
                "--state",
                host["state_path"],
                "--status",
                status,
                "--repo",
                str(self.repo),
            ],
            input=json.dumps({"tool_name": "apply_patch", "tool_input": {}}),
            capture_output=True,
            text=True,
            check=False,
        )
        decision = json.loads(denied.stdout)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")
        denied_read = subprocess.run(
            [
                sys.executable,
                str(gate_script),
                "--state",
                host["state_path"],
                "--status",
                status,
                "--repo",
                str(self.repo),
            ],
            input=json.dumps(
                {"tool_name": "Read", "tool_input": {"path": ".env"}}
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            json.loads(denied_read.stdout)["hookSpecificOutput"][
                "permissionDecision"
            ],
            "deny",
        )

        broker = self.repo / ".agent-harness" / "bin" / "read_context.py"
        python_executable = str(Path(sys.executable).resolve())
        readable = subprocess.run(
            [
                python_executable,
                str(broker),
                "read",
                ".agent-harness/router.md",
                "--lines",
                "3",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(readable.returncode, 0, readable.stderr)
        self.assertIn("Engineering Harness router", readable.stdout)
        (self.repo / ".env").write_text("SECRET=do-not-read\n")
        protected = subprocess.run(
            [python_executable, str(broker), "read", ".env"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(protected.returncode, 2)
        self.assertNotIn("do-not-read", protected.stdout + protected.stderr)
        (self.repo / ".env-store").mkdir()
        (self.repo / ".env-store" / "value.txt").write_text("nested-secret\n")
        for protected_path in (
            ".env-store/value.txt",
            ".agent-harness/manifest.json",
        ):
            with self.subTest(protected_path=protected_path):
                denied = subprocess.run(
                    [python_executable, str(broker), "read", protected_path],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(denied.returncode, 2)
                self.assertNotIn("nested-secret", denied.stdout + denied.stderr)
        broker_command = f"{python_executable} {broker} map"
        allowed = subprocess.run(
            [
                sys.executable,
                str(gate_script),
                "--state",
                host["state_path"],
                "--status",
                status,
                "--repo",
                str(self.repo),
            ],
            input=json.dumps(
                {
                    "cwd": str(self.repo),
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": broker_command},
                }
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotIn(
            "permissionDecision", json.loads(allowed.stdout)["hookSpecificOutput"]
        )
        injected = subprocess.run(
            [
                sys.executable,
                str(gate_script),
                "--state",
                host["state_path"],
                "--status",
                status,
                "--repo",
                str(self.repo),
            ],
            input=json.dumps(
                {
                    "cwd": str(self.repo),
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": broker_command + " > stolen.txt"},
                }
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            json.loads(injected.stdout)["hookSpecificOutput"]["permissionDecision"],
            "deny",
        )

    def test_gate_state_matches_runtime_schema(self) -> None:
        self.seed_javascript_project()
        self.assertEqual(self.run_setup("install").returncode, 3)
        manifest = json.loads(
            (self.repo / ".agent-harness" / "manifest.json").read_text()
        )
        state = Path(manifest["host_runtime"]["state_path"]).read_bytes()
        from runtime.domain.gate import MINIMUM_PROTECTED_GLOBS, parse_gate_state

        parsed = parse_gate_state(state)
        self.assertEqual(str(parsed.project_root), str(self.repo))
        self.assertEqual(parsed.phase, "received")
        self.assertIsNone(parsed.write_lease)
        self.assertTrue(
            set(MINIMUM_PROTECTED_GLOBS).issubset(parsed.protected_globs)
        )
        self.assertIn(".codex/hooks.json", parsed.protected_globs)
        self.assertIn(".claude/settings.json", parsed.protected_globs)
        self.assertEqual(
            tuple(map(str, parsed.read_broker_python_executables)),
            (str(Path(sys.executable).resolve()),),
        )

    def test_status_booleans_without_manifest_bound_evidence_cannot_pass(self) -> None:
        self.seed_javascript_project()
        self.assertEqual(self.run_setup("install").returncode, 3)
        manifest = json.loads(
            (self.repo / ".agent-harness" / "manifest.json").read_text()
        )
        status_path = Path(manifest["host_runtime"]["status_path"])
        status = json.loads(status_path.read_text())
        status.update(
            {
                "runtimeReady": True,
                "hookTrustVerified": True,
                "writeCanaryVerified": True,
            }
        )
        status_path.write_text(json.dumps(status) + "\n")

        audited = self.run_setup("audit")

        self.assertEqual(audited.returncode, 3)
        self.assertIn("provider hook trust", audited.stdout)
        self.assertIn("write-deny canary", audited.stdout)

    def test_provider_verification_binds_normal_hook_denial_to_manifest(self) -> None:
        self.seed_javascript_project()
        self.assertEqual(self.run_setup("install").returncode, 3)
        module = load_installer()
        fake_bin = self.base / "bin"
        fake_bin.mkdir()
        fake_codex = fake_bin / "codex"
        fake_codex.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_codex.chmod(0o755)
        self.env["PATH"] = (
            str(fake_bin) + os.pathsep + self.env.get("PATH", "")
        )

        def fake_run(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            if any(str(item).endswith("audit.py") for item in command):
                return subprocess.run(command, **kwargs)
            if command[-1] == "--version":
                return subprocess.CompletedProcess(
                    command, 0, stdout="codex-cli 1.2.3\n", stderr=""
                )
            self.assertNotIn("--dangerously-bypass-hook-trust", command)
            self.assertIn("workspace-write", command)
            event = {
                "type": "hook.completed",
                "hook": "PreToolUse",
                "permissionDecision": "deny",
                "tool_name": "apply_patch",
                "tool_call_id": "provider-canary-write",
            }
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(event) + "\n",
                stderr="",
            )

        with mock.patch.dict(os.environ, self.env, clear=False):
            result = module.verify_provider(
                self.repo.resolve(),
                run_process=fake_run,
                find_binary=lambda _name: str(fake_codex),
            )

        self.assertEqual(result, 0)
        manifest = json.loads(
            (self.repo / ".agent-harness" / "manifest.json").read_text()
        )
        status = json.loads(
            Path(manifest["host_runtime"]["status_path"]).read_text()
        )
        self.assertTrue(status["hookTrustVerified"])
        self.assertTrue(status["writeCanaryVerified"])
        self.assertEqual(
            status["verifiedManifestChecksum"],
            manifest["manifest_checksum"],
        )
        self.assertRegex(status["verificationEvidenceSha256"], r"^[0-9a-f]{64}$")
        audited = self.run_setup("audit")
        self.assertEqual(audited.returncode, 0, audited.stdout + audited.stderr)
        self.assertIn("Harness audit: PASS", audited.stdout)

        fake_codex.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        stale = self.run_setup("audit")
        self.assertEqual(stale.returncode, 3, stale.stdout + stale.stderr)
        self.assertIn("provider hook trust is not verified", stale.stdout)

    def test_current_codex_pretool_denial_is_recognized(self) -> None:
        module = load_installer()

        self.assertTrue(
            module._provider_canary_denied(
                module.provider_spec("codex"),
                "",
                (
                    "ERROR codex_core::tools::router: "
                    "error=Command blocked by PreToolUse hook: "
                    "Task phase 'discovery-locked' does not permit native writes."
                ),
            )
        )

    def test_claude_provider_verification_uses_constrained_write_canary(self) -> None:
        self.seed_javascript_project()
        self.assertEqual(
            self.run_setup("install", provider="claude-code").returncode,
            3,
        )
        module = load_installer()
        fake_bin = self.base / "bin"
        fake_bin.mkdir()
        fake_claude = fake_bin / "claude"
        fake_claude.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_claude.chmod(0o755)
        self.env["PATH"] = (
            str(fake_bin) + os.pathsep + self.env.get("PATH", "")
        )

        def fake_run(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            if any(str(item).endswith("audit.py") for item in command):
                return subprocess.run(command, **kwargs)
            if command[-1] == "--version":
                return subprocess.CompletedProcess(
                    command, 0, stdout="2.1.215 (Claude Code)\n", stderr=""
                )
            self.assertIn("--include-hook-events", command)
            self.assertIn("--tools", command)
            self.assertIn("Write", command)
            self.assertIn("--permission-mode", command)
            self.assertIn("acceptEdits", command)
            self.assertNotIn("--dangerously-skip-permissions", command)
            event = {
                "type": "hook_response",
                "hook_event_name": "PreToolUse",
                "output": {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            "Engineering Harness: writing is locked"
                        ),
                    }
                },
            }
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(event) + "\n",
                stderr="",
            )

        with mock.patch.dict(os.environ, self.env, clear=False):
            result = module.verify_provider(
                self.repo.resolve(),
                provider=module.provider_spec("claude-code"),
                run_process=fake_run,
                find_binary=lambda _name: str(fake_claude),
            )

        self.assertEqual(result, 0)
        manifest = json.loads(
            (self.repo / ".agent-harness" / "manifest.json").read_text()
        )
        status = json.loads(
            Path(manifest["host_runtime"]["status_path"]).read_text()
        )
        self.assertEqual(status["providerId"], "claude-code")
        self.assertEqual(
            status["providerReceipt"]["providerId"], "claude-code"
        )

    def test_atomic_failure_rolls_back_project_and_host(self) -> None:
        original = self.seed_javascript_project()
        module = load_installer()
        with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(self.state_home)}):
            plan = module.plan_setup(self.repo.resolve(), "install")
        self.assertFalse(plan.conflicts)
        real_atomic = module.atomic_write
        calls = 0

        def fail_once(path: Path, content: bytes, mode: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("injected transaction failure")
            real_atomic(path, content, mode)

        module.atomic_write = fail_once
        self.addCleanup(setattr, module, "atomic_write", real_atomic)
        with self.assertRaisesRegex(OSError, "injected"):
            module.apply_transaction(plan.mutations)
        self.assertEqual((self.repo / "AGENTS.md").read_bytes(), original)
        self.assertEqual(
            set(self.snapshot(self.repo)),
            {"AGENTS.md", "package-lock.json", "package.json"},
        )
        self.assertEqual(self.snapshot(self.state_home), {})

    def test_post_apply_security_failure_rolls_back_project_and_host(self) -> None:
        original = self.seed_javascript_project()
        module = load_installer()
        with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(self.state_home)}):
            plan = module.plan_setup(self.repo.resolve(), "install")
        self.assertFalse(plan.conflicts)

        def fail_security_step() -> None:
            raise OSError("injected host security failure")

        with self.assertRaisesRegex(OSError, "host security"):
            module.apply_transaction(
                plan.mutations, after_apply=fail_security_step
            )

        self.assertEqual((self.repo / "AGENTS.md").read_bytes(), original)
        self.assertEqual(
            set(self.snapshot(self.repo)),
            {"AGENTS.md", "package-lock.json", "package.json"},
        )
        self.assertEqual(self.snapshot(self.state_home), {})

    def test_uninstall_preserves_user_owned_and_unrelated_content(self) -> None:
        original = self.seed_javascript_project()
        hooks_path = self.repo / ".codex" / "hooks.json"
        hooks_path.parent.mkdir()
        unrelated = {
            "hooks": {
                "Stop": [
                    {"hooks": [{"type": "command", "command": "echo still-here"}]}
                ]
            },
            "owner": "user",
        }
        hooks_path.write_text(json.dumps(unrelated) + "\n")
        self.assertEqual(self.run_setup("install").returncode, 3)
        manifest = json.loads(
            (self.repo / ".agent-harness" / "manifest.json").read_text()
        )
        state_directory = Path(manifest["host_runtime"]["state_path"]).parent
        config_path = self.repo / ".agent-harness" / "config.json"
        config = json.loads(config_path.read_text())
        config["project"]["constraints"].append("survive-uninstall")
        config_path.write_text(json.dumps(config) + "\n")
        unknown = self.repo / ".agent-harness" / "user-note.txt"
        unknown.write_text("keep\n")

        removed = self.run_setup("uninstall")
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assertEqual((self.repo / "AGENTS.md").read_bytes(), original)
        self.assertEqual(json.loads(hooks_path.read_text()), unrelated)
        self.assertIn("survive-uninstall", config_path.read_text())
        self.assertEqual(unknown.read_text(), "keep\n")
        self.assertTrue((self.repo / ".agent-harness" / "local.md").is_file())
        self.assertFalse((self.repo / ".agent-harness" / "manifest.json").exists())
        self.assertFalse((self.repo / ".agent-harness" / "router.md").exists())
        self.assertFalse(state_directory.exists())

    def test_uninstall_rejects_resealed_manifest_with_foreign_host_path(self) -> None:
        self.seed_javascript_project()
        self.assertEqual(self.run_setup("install").returncode, 3)
        manifest_path = self.repo / ".agent-harness" / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        foreign = self.base / "must-survive.txt"
        foreign.write_text("user-owned\n")
        module = load_installer()
        manifest["host_runtime"]["owned_files"].append(
            {
                "path": str(foreign),
                "sha256": module.sha256(foreign.read_bytes()),
                "source": "attacker-controlled",
            }
        )
        manifest_path.write_bytes(module.json_bytes(module.seal_manifest(manifest)))

        removed = self.run_setup("uninstall")

        self.assertEqual(removed.returncode, 2)
        self.assertIn("host ownership set is not installer-owned", removed.stdout)
        self.assertEqual(foreign.read_text(), "user-owned\n")
        self.assertTrue(manifest_path.exists())


if __name__ == "__main__":
    unittest.main()
