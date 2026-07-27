from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta, timezone
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
AUDIT = (
    ROOT
    / "skills"
    / "setup-engineering-harness"
    / "assets"
    / "harness"
    / "checks"
    / "audit.py"
)


def load_audit():
    spec = importlib.util.spec_from_file_location(
        "engineering_harness_audit_under_test",
        AUDIT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load audit")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class VerificationIsolatorCapabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load_audit()

    def test_linux_requires_landlock_abi_three(self) -> None:
        with (
            mock.patch.object(self.audit.platform, "system", return_value="Linux"),
            mock.patch.object(
                self.audit.platform,
                "machine",
                return_value="x86_64",
            ),
            mock.patch.object(
                self.audit,
                "_linux_landlock_abi",
                return_value=2,
            ),
        ):
            ready, detail = self.audit.verification_isolator_capability()

        self.assertFalse(ready)
        self.assertIn("Landlock ABI >= 3", detail)
        self.assertIn("detected 2", detail)

    def test_linux_accepts_reviewed_architecture_and_abi(self) -> None:
        with (
            mock.patch.object(self.audit.platform, "system", return_value="Linux"),
            mock.patch.object(
                self.audit.platform,
                "machine",
                return_value="aarch64",
            ),
            mock.patch.object(
                self.audit,
                "_linux_landlock_abi",
                return_value=3,
            ),
        ):
            ready, detail = self.audit.verification_isolator_capability()

        self.assertTrue(ready)
        self.assertIn("ABI 3", detail)

    def test_linux_rejects_unreviewed_socket_filter_architecture(self) -> None:
        with (
            mock.patch.object(self.audit.platform, "system", return_value="Linux"),
            mock.patch.object(
                self.audit.platform,
                "machine",
                return_value="riscv64",
            ),
        ):
            ready, detail = self.audit.verification_isolator_capability()

        self.assertFalse(ready)
        self.assertIn("riscv64", detail)

    def test_macos_requires_sandbox_exec(self) -> None:
        with (
            mock.patch.object(self.audit.platform, "system", return_value="Darwin"),
            mock.patch.object(self.audit.shutil, "which", return_value=None),
        ):
            ready, detail = self.audit.verification_isolator_capability()

        self.assertFalse(ready)
        self.assertIn("sandbox-exec", detail)


class ProviderReceiptFreshnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load_audit()

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(
            prefix="provider-receipt-test-"
        )
        self.addCleanup(temporary.cleanup)
        self.binary = Path(temporary.name) / "codex"
        self.binary.write_bytes(b"provider-v1")

    def status_at(self, observed: datetime) -> dict[str, object]:
        verified_at = observed.isoformat()
        digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        receipt = {
            "manifestChecksum": "manifest-digest",
            "providerBinary": str(self.binary),
            "providerBinarySha256": digest,
            "providerVersion": "codex-cli 1.2.3",
            "stderrSha256": hashlib.sha256(b"").hexdigest(),
            "stdoutSha256": hashlib.sha256(b"denied").hexdigest(),
            "verifiedAt": verified_at,
        }
        return {
            "providerBinary": str(self.binary),
            "providerBinarySha256": digest,
            "providerReceipt": receipt,
            "providerVersion": "codex-cli 1.2.3",
            "verificationEvidenceSha256": self.audit.canonical_digest(receipt),
            "verifiedAt": verified_at,
            "verifiedManifestChecksum": "manifest-digest",
        }

    def test_current_receipt_is_bound_to_binary_path_and_digest(self) -> None:
        status = self.status_at(datetime.now(timezone.utc))
        with mock.patch.object(
            self.audit.shutil,
            "which",
            return_value=str(self.binary),
        ):
            self.assertTrue(self.audit.provider_receipt_is_current(status))
            self.binary.write_bytes(b"provider-v2")
            self.assertFalse(self.audit.provider_receipt_is_current(status))

    def test_expired_receipt_and_path_drift_are_rejected(self) -> None:
        status = self.status_at(
            datetime.now(timezone.utc) - timedelta(days=2)
        )
        other = self.binary.with_name("other-codex")
        other.write_bytes(self.binary.read_bytes())
        with mock.patch.object(
            self.audit.shutil,
            "which",
            return_value=str(self.binary),
        ):
            self.assertFalse(self.audit.provider_receipt_is_current(status))

        status = self.status_at(datetime.now(timezone.utc))
        with mock.patch.object(
            self.audit.shutil,
            "which",
            return_value=str(other),
        ):
            self.assertFalse(self.audit.provider_receipt_is_current(status))


if __name__ == "__main__":
    unittest.main()
