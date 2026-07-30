from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import resource
import runpy
import shlex
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
BROKER_SOURCE = (
    ROOT
    / "skills"
    / "setup-engineering-harness"
    / "assets"
    / "harness"
    / "runtime"
    / "verification_broker.py"
)


class VerificationBrokerIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        if platform.system() not in {"Linux", "Darwin"}:
            self.skipTest("the MVP write isolators target Linux and macOS")
        temporary = tempfile.TemporaryDirectory(
            prefix="verification-broker-isolation-test-"
        )
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / "project"
        broker = self.repo / ".agent-harness" / "bin" / "run_verification.py"
        broker.parent.mkdir(parents=True)
        shutil.copy2(BROKER_SOURCE, broker)
        self.broker = broker
        self.profile = self.repo / ".agent-harness" / "repo-profile.json"
        (self.repo / "src").mkdir()
        (self.repo / "src" / "example.txt").write_text(
            "fixture\n", encoding="utf-8"
        )

    def run_registered(
        self,
        code: str,
        *,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = shlex.join([sys.executable, "-c", code])
        return self.run_command(command, environment=environment)

    def run_command(
        self,
        command: str,
        *,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.profile.write_text(
            json.dumps(
                {
                    "candidate_commands": [
                        {
                            "id": "test",
                            "command": command,
                            "executed": False,
                        }
                    ]
                }
            )
            + "\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [sys.executable, str(self.broker), "run", "test"],
            cwd=self.repo,
            env=environment or os.environ.copy(),
            capture_output=True,
            text=True,
            check=False,
        )
        if (
            result.returncode == 2
            and "write confinement is unavailable" in result.stderr
        ):
            self.skipTest(result.stderr.strip())
        return result

    def test_registered_command_runs_in_disposable_snapshot(self) -> None:
        result = self.run_registered(
            "from pathlib import Path; "
            "assert Path('src/example.txt').read_text() == 'fixture\\n'"
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_snapshot_keeps_security_named_source_and_omits_secret_artifacts(
        self,
    ) -> None:
        readable = (
            "src/tokenizer.py",
            "src/auth/token.ts",
            "src/SecretManager.java",
            "src/credentials.ts",
        )
        for relative in readable:
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{relative}\n", encoding="utf-8")
        protected = (
            ".env",
            "keys/private.pem",
            "config/credentials.json",
        )
        for relative in protected:
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("must-not-copy\n", encoding="utf-8")

        result = self.run_registered(
            "from pathlib import Path; "
            f"readable={readable!r}; protected={protected!r}; "
            "assert all(Path(item).is_file() for item in readable); "
            "assert all(not Path(item).exists() for item in protected)"
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_relative_parent_write_is_discarded_with_snapshot(self) -> None:
        escaped = self.base / "escaped.txt"
        result = self.run_registered(
            "from pathlib import Path; Path('../escaped.txt').write_text('x')"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(escaped.exists())

    def test_absolute_write_outside_isolation_is_denied(self) -> None:
        escaped = self.base / "absolute-escaped.txt"
        result = self.run_registered(
            "from pathlib import Path; "
            f"Path({str(escaped)!r}).write_text('x')"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(escaped.exists())

    def test_absolute_secret_outside_snapshot_is_not_readable(self) -> None:
        secret = self.base / "outside-secret.txt"
        secret.write_text("must-not-leak\n", encoding="utf-8")
        result = self.run_registered(
            "from pathlib import Path; "
            f"print(Path({str(secret)!r}).read_text())"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("must-not-leak", result.stdout)

    def test_tcp_network_connection_is_denied(self) -> None:
        result = self.run_registered(
            "import socket, sys"
            "\ntry:"
            "\n    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
            "\n    s.connect(('127.0.0.1', 9))"
            "\nexcept PermissionError: sys.exit(0)"
            "\nexcept OSError: sys.exit(3)"
            "\nelse: sys.exit(4)"
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_udp_network_creation_is_denied(self) -> None:
        result = self.run_registered(
            "import socket, sys"
            "\ntry:"
            "\n    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)"
            "\n    s.sendto(b'x', ('127.0.0.1', 9))"
            "\nexcept PermissionError: sys.exit(0)"
            "\nexcept OSError: sys.exit(3)"
            "\nelse: sys.exit(4)"
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_path_runtime_allowlist_does_not_expose_sibling_credentials(self) -> None:
        path_directory = self.base / "path-tools"
        path_directory.mkdir()
        fake_node = path_directory / "node"
        fake_node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_node.chmod(0o755)
        credential = path_directory / "credential.txt"
        credential.write_text("PATH-SECRET-VALUE\n", encoding="utf-8")
        environment = os.environ.copy()
        environment["PATH"] = (
            str(path_directory)
            + os.pathsep
            + environment.get("PATH", "")
        )

        result = self.run_registered(
            "from pathlib import Path; "
            f"print(Path({str(credential)!r}).read_text())",
            environment=environment,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PATH-SECRET-VALUE", result.stdout)

    def test_fnm_node_can_read_only_its_installation_runtime(self) -> None:
        if platform.system() != "Linux":
            self.skipTest("fnm runtime roots are a Linux Landlock concern")
        openssl_config = Path("/etc/ssl/openssl.cnf")
        if not openssl_config.is_file():
            self.skipTest("the host does not expose the standard OpenSSL config")
        fnm_root = self.base / ".local" / "share" / "fnm"
        installation = (
            fnm_root
            / "node-versions"
            / "v22.14.0"
            / "installation"
        )
        bin_directory = installation / "bin"
        runtime_file = installation / "lib" / "runtime.txt"
        outside_file = fnm_root / "credential.txt"
        bin_directory.mkdir(parents=True)
        runtime_file.parent.mkdir(parents=True)
        runtime_file.write_text("runtime-ok\n", encoding="utf-8")
        outside_file.write_text("must-not-read\n", encoding="utf-8")
        fake_node = bin_directory / "node"
        fake_node.write_text(
            "#!/bin/sh\n"
            f"IFS= read -r value < {shlex.quote(str(runtime_file))} || exit 12\n"
            '[ "$value" = "runtime-ok" ] || exit 13\n'
            f"IFS= read -r _ < {shlex.quote(str(openssl_config))} || exit 15\n"
            f"IFS= read -r leaked < {shlex.quote(str(outside_file))} && exit 14\n"
            "exit 0\n",
            encoding="utf-8",
        )
        fake_node.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = (
            str(bin_directory)
            + os.pathsep
            + environment.get("PATH", "")
        )

        result = self.run_command("node", environment=environment)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_hosted_toolcache_can_read_only_selected_tool_runtime(self) -> None:
        if platform.system() != "Linux":
            self.skipTest("hosted tool paths are a Linux Landlock concern")
        openssl_config = Path("/etc/ssl/openssl.cnf")
        if not openssl_config.is_file():
            self.skipTest("the host does not expose the standard OpenSSL config")
        toolcache_root = self.base / "opt" / "hostedtoolcache"
        installation = toolcache_root / "node" / "24.15.0" / "x64"
        bin_directory = installation / "bin"
        runtime_file = installation / "lib" / "npm" / "runtime.txt"
        outside_file = toolcache_root / "credential.txt"
        bin_directory.mkdir(parents=True)
        runtime_file.parent.mkdir(parents=True)
        runtime_file.write_text("runtime-ok\n", encoding="utf-8")
        outside_file.write_text("must-not-read\n", encoding="utf-8")
        fake_npm = bin_directory / "npm"
        fake_npm.write_text(
            "#!/bin/sh\n"
            f"IFS= read -r value < {shlex.quote(str(runtime_file))} || exit 12\n"
            '[ "$value" = "runtime-ok" ] || exit 13\n'
            f"IFS= read -r _ < {shlex.quote(str(openssl_config))} || exit 15\n"
            f"IFS= read -r leaked < {shlex.quote(str(outside_file))} && exit 14\n"
            "exit 0\n",
            encoding="utf-8",
        )
        fake_npm.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = (
            str(bin_directory)
            + os.pathsep
            + environment.get("PATH", "")
        )

        result = self.run_command("npm", environment=environment)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_openssl_allowlist_does_not_expose_private_directory(self) -> None:
        if platform.system() != "Linux":
            self.skipTest("OpenSSL paths are a Linux Landlock concern")
        openssl_config = Path("/etc/ssl/openssl.cnf")
        private_directory = Path("/etc/ssl/private")
        if not openssl_config.is_file() or not private_directory.is_dir():
            self.skipTest("the host does not expose the standard OpenSSL layout")
        runtime_paths = runpy.run_path(str(BROKER_SOURCE))[
            "_linux_readable_runtime_paths"
        ]([sys.executable], {"PATH": os.environ.get("PATH", "")})

        self.assertIn(openssl_config.resolve(strict=True), runtime_paths)
        for candidate in runtime_paths:
            if not candidate.is_dir():
                continue
            try:
                private_directory.resolve(strict=True).relative_to(candidate)
            except ValueError:
                continue
            self.fail(f"runtime allowlist exposes private SSL path via {candidate}")

    def test_python_runtime_allowlist_uses_precise_sysconfig_paths(self) -> None:
        if platform.system() != "Linux":
            self.skipTest("Python runtime paths are a Linux Landlock concern")
        installation = self.base / "hostedtoolcache" / "Python" / "3.12" / "x64"
        stdlib = installation / "lib" / "python3.12"
        purelib = installation / "lib" / "python3.12" / "site-packages"
        sibling_secret = installation.parent / "credentials.txt"
        stdlib.mkdir(parents=True)
        purelib.mkdir()
        sibling_secret.write_text("must-not-read\n", encoding="utf-8")
        runtime_paths = runpy.run_path(str(BROKER_SOURCE))[
            "_linux_readable_runtime_paths"
        ]

        with patch.object(
            sysconfig,
            "get_paths",
            return_value={
                "stdlib": str(stdlib),
                "platstdlib": str(stdlib),
                "purelib": str(purelib),
                "platlib": str(purelib),
                "data": str(installation),
            },
        ):
            readable = runtime_paths(
                [sys.executable],
                {"PATH": os.environ.get("PATH", "")},
            )

        self.assertIn(stdlib.resolve(strict=True), readable)
        self.assertIn(purelib.resolve(strict=True), readable)
        self.assertNotIn(installation.resolve(strict=True), readable)
        for candidate in readable:
            if not candidate.is_dir():
                continue
            try:
                sibling_secret.resolve(strict=True).relative_to(candidate)
            except ValueError:
                continue
            self.fail(f"runtime allowlist exposes sibling secret via {candidate}")

    def test_node_can_start_a_worker_thread_under_uid_relative_limit(self) -> None:
        if platform.system() != "Linux":
            self.skipTest("UID-relative process limits are a Linux concern")
        if shutil.which("node") is None:
            self.skipTest("Node.js is unavailable")
        code = (
            "const { Worker } = require('node:worker_threads');"
            "const worker = new Worker('0', { eval: true });"
            "worker.on('error', () => process.exit(12));"
            "worker.on('exit', code => process.exit(code));"
        )

        result = self.run_command(shlex.join(["node", "-e", code]))

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_uid_relative_limit_stops_excessive_additional_threads(self) -> None:
        if platform.system() != "Linux":
            self.skipTest("UID-relative process limits are a Linux concern")
        code = (
            "import threading\n"
            "gate = threading.Event()\n"
            "threads = []\n"
            "blocked = False\n"
            "try:\n"
            "    for _ in range(512):\n"
            "        thread = threading.Thread(target=gate.wait)\n"
            "        thread.start()\n"
            "        threads.append(thread)\n"
            "except RuntimeError:\n"
            "    blocked = True\n"
            "finally:\n"
            "    gate.set()\n"
            "    for thread in threads:\n"
            "        thread.join()\n"
            "raise SystemExit(0 if blocked else 13)\n"
        )

        result = self.run_registered(code)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_uid_task_measurement_failure_is_fail_closed(self) -> None:
        if platform.system() != "Linux":
            self.skipTest("UID-relative process limits are a Linux concern")
        count_tasks = runpy.run_path(str(BROKER_SOURCE))[
            "_linux_uid_task_count"
        ]

        with self.assertRaisesRegex(ValueError, "cannot measure"):
            count_tasks(proc_root=self.base / "missing-proc")

    def test_uid_relative_limit_respects_finite_hard_limit(self) -> None:
        namespace = runpy.run_path(str(BROKER_SOURCE))
        process_limit = namespace["_linux_uid_process_limit"]
        with (
            patch.dict(
                process_limit.__globals__,
                {"_linux_uid_task_count": lambda: 1_000},
            ),
            patch.object(
                resource,
                "getrlimit",
                return_value=(2_000, 1_100),
            ),
        ):
            self.assertEqual(process_limit(), 1_100)
        with (
            patch.dict(
                process_limit.__globals__,
                {"_linux_uid_task_count": lambda: 1_000},
            ),
            patch.object(
                resource,
                "getrlimit",
                return_value=(2_000, 1_000),
            ),
        ):
            with self.assertRaisesRegex(ValueError, "no verification headroom"):
                process_limit()

    def test_resource_limits_without_uid_count_omit_global_nproc(self) -> None:
        namespace = runpy.run_path(str(BROKER_SOURCE))
        install_limits = namespace["_install_resource_limits"]
        direct_limits: list[int] = []
        soft_limits: list[int] = []
        with (
            patch.object(
                resource,
                "setrlimit",
                side_effect=lambda identifier, _limits: direct_limits.append(
                    identifier
                ),
            ),
            patch.dict(
                install_limits.__globals__,
                {
                    "_set_soft_resource_cap": (
                        lambda identifier, _cap: soft_limits.append(identifier)
                    )
                },
            ),
        ):
            install_limits()

        self.assertNotIn(resource.RLIMIT_NPROC, direct_limits)
        self.assertNotIn(resource.RLIMIT_NPROC, soft_limits)

    def test_resource_limits_omit_unreliable_macos_address_space_cap(self) -> None:
        namespace = runpy.run_path(str(BROKER_SOURCE))
        install_limits = namespace["_install_resource_limits"]
        soft_limits: list[int] = []
        with (
            patch.object(platform, "system", return_value="Darwin"),
            patch.object(resource, "setrlimit"),
            patch.dict(
                install_limits.__globals__,
                {
                    "_set_soft_resource_cap": (
                        lambda identifier, _cap: soft_limits.append(identifier)
                    )
                },
            ),
        ):
            install_limits()

        self.assertNotIn(resource.RLIMIT_AS, soft_limits)

    def test_symlink_cannot_relabel_ignored_secret_into_snapshot(self) -> None:
        secret = self.repo / ".env"
        secret.write_text("SECRET=must-not-copy\n", encoding="utf-8")
        visible = self.repo / "src" / "visible.txt"
        try:
            visible.symlink_to("../.env")
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable: {error}")

        result = self.run_registered(
            "from pathlib import Path; print(Path('src/visible.txt').read_text())"
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("targets protected content", result.stderr)
        self.assertNotIn("must-not-copy", result.stdout)


if __name__ == "__main__":
    unittest.main()
