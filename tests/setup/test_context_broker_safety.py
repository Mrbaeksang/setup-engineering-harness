from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BROKER_SOURCE = (
    ROOT
    / "skills"
    / "setup-engineering-harness"
    / "assets"
    / "harness"
    / "runtime"
    / "context_broker.py"
)


class ContextBrokerGitSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(
            prefix="context-broker-safety-test-"
        )
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / "project"
        broker = self.repo / ".agent-harness" / "bin" / "read_context.py"
        broker.parent.mkdir(parents=True)
        shutil.copy2(BROKER_SOURCE, broker)
        self.broker = broker
        (self.repo / "sample.txt").write_text("before\n", encoding="utf-8")
        self.run_git("init", "--quiet")
        self.run_git("config", "user.email", "test@example.invalid")
        self.run_git("config", "user.name", "Test")
        self.run_git("add", ".")
        self.run_git("commit", "--quiet", "-m", "baseline")

    def run_git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=True,
        )

    def test_security_named_source_files_are_readable_but_artifacts_are_not(
        self,
    ) -> None:
        readable = {
            "src/tokenizer.py": "TOKENIZER_SOURCE\n",
            "src/auth/token.ts": "TOKEN_SOURCE\n",
            "src/SecretManager.java": "SECRET_MANAGER_SOURCE\n",
            "src/credentials.ts": "CREDENTIALS_SOURCE\n",
        }
        for relative, content in readable.items():
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(self.broker), "read", relative],
                cwd=self.repo,
                env=os.environ.copy(),
                capture_output=True,
                text=True,
                check=False,
            )
            with self.subTest(relative=relative):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(content.strip(), result.stdout)

        protected = {
            ".env": "ENV-SECRET\n",
            "keys/private.pem": "PRIVATE-KEY\n",
            "config/credentials.json": "CREDENTIAL-STORE\n",
        }
        for relative, content in protected.items():
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(self.broker), "read", relative],
                cwd=self.repo,
                env=os.environ.copy(),
                capture_output=True,
                text=True,
                check=False,
            )
            with self.subTest(relative=relative):
                self.assertEqual(result.returncode, 2)
                self.assertNotIn(content.strip(), result.stdout + result.stderr)

    def test_git_diff_disables_repository_textconv_commands(self) -> None:
        marker = self.base / "textconv-executed"
        textconv = self.base / "textconv.py"
        textconv.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed')\n"
            "print('converted')\n",
            encoding="utf-8",
        )
        (self.repo / ".gitattributes").write_text(
            "*.txt diff=unsafe\n", encoding="utf-8"
        )
        self.run_git(
            "config",
            "diff.unsafe.textconv",
            f"{sys.executable} {textconv}",
        )
        self.run_git("add", ".gitattributes")
        self.run_git("commit", "--quiet", "-m", "attributes")
        (self.repo / "sample.txt").write_text("after\n", encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(self.broker), "git-diff"],
            cwd=self.repo,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-before", result.stdout)
        self.assertIn("+after", result.stdout)
        self.assertFalse(marker.exists())

    def test_git_status_disables_repository_fsmonitor_command(self) -> None:
        marker = self.base / "fsmonitor-executed"
        fsmonitor = self.base / "fsmonitor.py"
        fsmonitor.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed')\n",
            encoding="utf-8",
        )
        fsmonitor.chmod(0o755)
        self.run_git("config", "core.fsmonitor", str(fsmonitor))

        result = subprocess.run(
            [sys.executable, str(self.broker), "git-status"],
            cwd=self.repo,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_git_diff_filters_protected_changed_files(self) -> None:
        secret = "TOP-SECRET-VALUE"
        protected = [
            ".env",
            "keys/private.pem",
            "nested/.Env.Local",
        ]
        for relative in protected:
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("before\n", encoding="utf-8")
        self.run_git("add", ".")
        self.run_git("commit", "--quiet", "-m", "protected baseline")
        for relative in protected:
            (self.repo / relative).write_text(
                f"{secret}\n", encoding="utf-8"
            )
        (self.repo / "sample.txt").write_text("safe-after\n", encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(self.broker), "git-diff"],
            cwd=self.repo,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("safe-after", result.stdout)
        self.assertNotIn(secret, result.stdout)
        for relative in protected:
            self.assertNotIn(relative, result.stdout)

    def test_git_status_filters_protected_and_quotes_weird_names(self) -> None:
        secret_name = self.repo / ".env.weird\nname"
        secret_name.write_text("secret\n", encoding="utf-8")
        weird_name = self.repo / "safe\nname.txt"
        weird_name.write_text("safe\n", encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(self.broker), "git-status"],
            cwd=self.repo,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(".env", result.stdout)
        self.assertIn('"safe\\nname.txt"', result.stdout)
        self.assertEqual(len(result.stdout.splitlines()), 1)

    def test_explicit_protected_diff_path_is_denied(self) -> None:
        protected = self.repo / ".env"
        protected.write_text("before\n", encoding="utf-8")
        self.run_git("add", ".env")
        self.run_git("commit", "--quiet", "-m", "protected baseline")
        protected.write_text("TOP-SECRET-VALUE\n", encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(self.broker), "git-diff", ".env"],
            cwd=self.repo,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertNotIn("TOP-SECRET-VALUE", result.stdout + result.stderr)

    def test_dependency_read_and_search_reach_late_installed_symbol(
        self,
    ) -> None:
        package = self.repo / "node_modules" / "example-renderer"
        package.mkdir(parents=True)
        (package / "package.json").write_text(
            '{"name":"example-renderer","version":"1.2.3"}\n',
            encoding="utf-8",
        )
        late_symbol = "freezeCompletedBlocks"
        declarations = [
            *(f"export type Filler{number} = string;" for number in range(450)),
            f"export declare const {late_symbol}: boolean;",
        ]
        types_path = package / "index.d.ts"
        types_path.write_text(
            "\n".join(declarations) + "\n", encoding="utf-8"
        )

        late_read = subprocess.run(
            [
                sys.executable,
                str(self.broker),
                "dependency-read",
                "node_modules/example-renderer/index.d.ts",
                "--start",
                "440",
                "--lines",
                "20",
            ],
            cwd=self.repo,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            check=False,
        )
        searched = subprocess.run(
            [
                sys.executable,
                str(self.broker),
                "dependency-search",
                "node_modules/example-renderer/index.d.ts",
                late_symbol,
                "--limit",
                "1",
            ],
            cwd=self.repo,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(late_read.returncode, 0, late_read.stderr)
        self.assertIn(late_symbol, late_read.stdout)
        self.assertEqual(searched.returncode, 0, searched.stderr)
        self.assertIn(
            "node_modules/example-renderer/index.d.ts:451:",
            searched.stdout,
        )
        self.assertIn(late_symbol, searched.stdout)

    def test_dependency_broker_requires_exact_installed_package_root(
        self,
    ) -> None:
        fake = self.repo / "node_modules" / "not-installed"
        fake.mkdir(parents=True)
        (fake / "index.d.ts").write_text(
            "export declare const hidden: boolean;\n", encoding="utf-8"
        )

        result = subprocess.run(
            [
                sys.executable,
                str(self.broker),
                "dependency-search",
                "node_modules/not-installed/index.d.ts",
                "hidden",
            ],
            cwd=self.repo,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertNotIn("hidden: boolean", result.stdout + result.stderr)

    def test_dependency_broker_binds_python_module_to_distribution_metadata(
        self,
    ) -> None:
        site_packages = (
            self.repo
            / ".venv"
            / "lib"
            / "python3.12"
            / "site-packages"
        )
        metadata = site_packages / "demo-1.2.3.dist-info"
        metadata.mkdir(parents=True)
        (metadata / "METADATA").write_text(
            "Name: demo\nVersion: 1.2.3\n", encoding="utf-8"
        )
        (metadata / "top_level.txt").write_text(
            "demo\n", encoding="utf-8"
        )
        (site_packages / "demo.py").write_text(
            "def native_option():\n    return True\n", encoding="utf-8"
        )
        (site_packages / "unbound.py").write_text(
            "UNBOUND = True\n", encoding="utf-8"
        )

        exact = subprocess.run(
            [
                sys.executable,
                str(self.broker),
                "dependency-search",
                ".venv/lib/python3.12/site-packages/demo.py",
                "native_option",
            ],
            cwd=self.repo,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            check=False,
        )
        unbound = subprocess.run(
            [
                sys.executable,
                str(self.broker),
                "dependency-read",
                ".venv/lib/python3.12/site-packages/unbound.py",
            ],
            cwd=self.repo,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(exact.returncode, 0, exact.stderr)
        self.assertIn("native_option", exact.stdout)
        self.assertEqual(unbound.returncode, 2)
        self.assertNotIn("UNBOUND = True", unbound.stdout + unbound.stderr)


if __name__ == "__main__":
    unittest.main()
