from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from runtime.benchmark.orca_codex import (
    OrcaCodexError,
    OrcaCodexExecutor,
)


class OrcaCodexExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(
            tempfile.mkdtemp(prefix="engineering-harness-live-")
        )
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.binary = self.root / "orca-ide"
        self.binary.write_text("#!/bin/sh\n", encoding="utf-8")
        self.binary.chmod(0o755)
        self.executor = OrcaCodexExecutor(orca_binary=self.binary)
        self.executor.authorize_temporary_root(self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _command(self) -> list[str]:
        result = [
            "codex",
            "exec",
            "--json",
            "--ephemeral",
            "--color",
            "never",
            "--sandbox",
            "workspace-write",
            "--cd",
            str(self.workspace),
            "--config",
            'shell_environment_policy.inherit="none"',
        ]
        for name in (
            "apps",
            "multi_agent",
            "multi_agent_v2",
            "plugins",
            "skill_search",
        ):
            result.extend(["--disable", name])
        result.append("-")
        return result

    def test_fixed_command_replaces_stdin_with_prompt(self) -> None:
        transformed = self.executor._fixed_provider_command(
            self._command(), cwd=self.workspace, prompt="exact prompt"
        )
        self.assertEqual("exact prompt", transformed[-1])
        self.assertNotIn("-", transformed)

    def test_forbidden_options_fail_closed(self) -> None:
        command = self._command()
        for unsafe in (
            ["--dangerously-bypass-approvals-and-sandbox"],
            ["--add-dir", "/tmp"],
            ["--config", "sandbox_workspace_write.network_access=true"],
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(
                OrcaCodexError
            ):
                self.executor._fixed_provider_command(
                    [*command[:-1], *unsafe, "-"],
                    cwd=self.workspace,
                    prompt="prompt",
                )

    def test_unissued_root_fails_closed(self) -> None:
        other = Path(
            tempfile.mkdtemp(prefix="engineering-harness-live-")
        )
        try:
            workspace = other / "workspace"
            workspace.mkdir()
            with self.assertRaisesRegex(
                OrcaCodexError, "valid host capability"
            ):
                self.executor._workspace(workspace)
        finally:
            shutil.rmtree(other)

    def test_capture_comes_from_host_files_not_terminal_tail(self) -> None:
        command = self._command()

        def fake_run(
            argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            if argv[1:3] == ["terminal", "create"]:
                shell = argv[argv.index("--command") + 1]
                stdout_target = shell.split(" >")[1].split(" 2>")[0]
                stderr_target = shell.split(" 2>")[1].split(";")[0]
                Path(stdout_target.strip("'")).write_text(
                    '{"type":"turn.completed"}\n', encoding="utf-8"
                )
                Path(stderr_target.strip("'")).write_text("", encoding="utf-8")
                status = shell.split(
                    "printf '%s' \"$_stack_chief_status\" >"
                )[1].split(";")[0]
                Path(status.strip("'")).write_text("0", encoding="utf-8")
                payload = {
                    "ok": True,
                    "result": {"terminal": {"handle": "term_exact"}},
                }
            elif argv[1:3] == ["terminal", "wait"]:
                payload = {"ok": True, "result": {"condition": "exit"}}
            else:
                self.fail(f"unexpected Orca argv: {argv}")
            return subprocess.CompletedProcess(
                argv, 0, stdout=json.dumps(payload), stderr=""
            )

        with patch("subprocess.run", side_effect=fake_run):
            result = self.executor(
                command, self.workspace, {}, "prompt", 30
            )
        self.assertEqual(0, result.returncode)
        self.assertEqual('{"type":"turn.completed"}\n', result.stdout)


if __name__ == "__main__":
    unittest.main()
