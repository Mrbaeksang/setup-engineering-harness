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

ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "setup-engineering-harness"
SCRIPT = SKILL / "scripts" / "setup_harness.py"


def load_installer():
    spec = importlib.util.spec_from_file_location(
        "provider_verification_installer_under_test",
        SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load installer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ProviderVerificationFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(
            prefix="provider-verification-test-"
        )
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / "project"
        self.repo.mkdir()
        (self.repo / "package.json").write_text(
            json.dumps(
                {
                    "scripts": {
                        "test": "node --test",
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.state_home = self.base / "state"
        environment = os.environ.copy()
        environment["XDG_STATE_HOME"] = str(self.state_home)
        installed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "install",
                "--repo",
                str(self.repo),
            ],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
        )
        self.assertEqual(
            installed.returncode,
            3,
            installed.stdout + installed.stderr,
        )
        self.manifest = json.loads(
            (self.repo / ".agent-harness" / "manifest.json").read_text()
        )
        self.state_path = Path(self.manifest["host_runtime"]["state_path"])
        self.state_directory = self.state_path.parent
        self.fake_codex = self.base / "codex"
        self.fake_codex.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.fake_codex.chmod(0o755)
        self.installer = load_installer()

    @staticmethod
    def snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
        return {
            path.relative_to(root).as_posix(): (
                path.read_bytes(),
                stat.S_IMODE(path.stat().st_mode),
            )
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def passthrough_audit(
        self,
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str] | None:
        if any(str(item).endswith("audit.py") for item in command):
            return subprocess.run(command, **kwargs)
        return None

    def test_missing_hook_denial_restores_all_host_sidecars(self) -> None:
        before = self.snapshot(self.state_directory)

        def fake_run(
            command: list[str],
            **kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            audited = self.passthrough_audit(command, **kwargs)
            if audited is not None:
                return audited
            if command[-1] == "--version":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="codex-cli 1.2.3\n",
                    stderr="",
                )
            (self.state_directory / "task-contract.json").write_text(
                '{"forged":true}\n',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                command,
                0,
                stdout='{"type":"turn.completed"}\n',
                stderr="",
            )

        result = self.installer.verify_provider(
            self.repo.resolve(),
            run_process=fake_run,
            find_binary=lambda _name: str(self.fake_codex),
        )

        self.assertEqual(result, 3)
        self.assertEqual(self.snapshot(self.state_directory), before)

    def test_escaped_canary_is_removed_and_verification_fails(self) -> None:
        target = self.repo / ".engineering-harness-provider-canary"

        def fake_run(
            command: list[str],
            **kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            audited = self.passthrough_audit(command, **kwargs)
            if audited is not None:
                return audited
            if command[-1] == "--version":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="codex-cli 1.2.3\n",
                    stderr="",
                )
            target.write_text("escaped\n", encoding="utf-8")
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="",
                stderr="",
            )

        result = self.installer.verify_provider(
            self.repo.resolve(),
            run_process=fake_run,
            find_binary=lambda _name: str(self.fake_codex),
        )

        self.assertEqual(result, 2)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
