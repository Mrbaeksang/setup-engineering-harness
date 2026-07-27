"""Trusted lifecycle for Task classification and scoped Write Leases.

This module mutates only host-controlled state outside the Project.  The
project-side broker is a protected launcher; it is not the authority.  Filesystem
permissions alone do not defend against a process running as the same OS user,
so provider sandboxing and hook trust remain separate deployment requirements.
"""

from __future__ import annotations

import argparse
import fcntl
import fnmatch
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePath
from typing import Any, Iterator, Sequence

try:
    from runtime.domain.gate import (
        GateState,
        StateValidationError,
        evidence_set_hash,
        lease_state_hash,
        parse_gate_state,
        safe_glob_matches,
        validate_safe_glob,
    )
except ImportError:  # Installed host package.
    from .domain import (  # type: ignore[no-redef]
        GateState,
        StateValidationError,
        evidence_set_hash,
        lease_state_hash,
        parse_gate_state,
        safe_glob_matches,
        validate_safe_glob,
    )


LEASE_REQUEST_RELATIVE_PATH = Path(
    ".agent-harness/bin/request_write_lease.py"
)
VERIFICATION_BROKER_RELATIVE_PATH = Path(
    ".agent-harness/bin/run_verification.py"
)
CONTRACT_FILENAME = "task-contract.json"
PROPOSAL_FILENAME = "lease-proposal.json"
RECEIPTS_FILENAME = "verification-receipts.json"
COMPLETION_FILENAME = "completion-receipt.json"
OFFICIAL_EVIDENCE_DIRECTORY = "official-evidence"
LOCK_FILENAME = "gate-state.lock"
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_OFFICIAL_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_OFFICIAL_OUTPUT_BYTES = 64 * 1024
MAX_OFFICIAL_OUTPUT_LINES = 400
MAX_OFFICIAL_SEARCH_RESULTS = 100
MAX_OFFICIAL_SEARCH_PATTERN = 256
MAX_AUTO_SCOPE_GLOBS = 8
MAX_OBSERVED_FILES = 50_000
MAX_OBSERVED_BYTES = 512 * 1024 * 1024

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EXACT_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!~-]{0,127}\Z")
_ENGLISH_DEPENDENCY = re.compile(
    r"\b(package|library|dependency|dependencies|sdk|framework|upgrade|"
    r"migration|version|deprecated|npm|pnpm|yarn|pip|cargo)\b",
    re.IGNORECASE,
)
_KOREAN_DEPENDENCY = re.compile(
    r"(라이브러리|패키지|의존성|버전|업그레이드|마이그레이션)"
)
_ENGLISH_BUILD = re.compile(
    r"\b(add|build|create|implement|design|choose|stack|architecture|service)\b",
    re.IGNORECASE,
)
_KOREAN_BUILD = re.compile(
    r"(만들|추가|구현|설계|선택|스택|아키텍처|서비스)"
)
_CLEAR_ACTION = re.compile(
    r"\b(add|build|create|implement|design|choose|fix|update|change|"
    r"remove|delete|debug|refactor|rename|test|document|upgrade|migrate|"
    r"investigate|diagnose)\b|"
    r"(만들|추가|구현|설계|선택|고쳐|수정|변경|삭제|디버그|"
    r"리팩터|이름.?변경|테스트|문서|업그레이드|마이그레이션|조사|진단)",
    re.IGNORECASE,
)
_ENGLISH_PRODUCT = re.compile(
    r"\b(real[- ]?time|chat|streaming|websocket|sse|service|product)\b",
    re.IGNORECASE,
)
_KOREAN_PRODUCT = re.compile(r"(실시간|채팅|스트리밍|서비스|제품)")
_HIGH_RISK = re.compile(
    r"\b(auth|authentication|authorization|security|payment|billing|privacy|"
    r"credential|secret|database migration|schema migration|delete|destructive|"
    r"production)\b|"
    r"(인증|인가|보안|결제|과금|개인정보|비밀|운영.?배포|"
    r"데이터베이스.?마이그레이션|스키마.?마이그레이션|삭제)",
    re.IGNORECASE,
)
_GENERIC_AMBIGUITY = re.compile(
    r"^\s*(?:make|do|fix|improve|refactor)?\s*(?:it|this|things?)?\s*"
    r"(?:better|good|nice|faster)?\s*[.!?]*\s*$|"
    r"^\s*(?:알아서|좋게|더\s*좋게|개선해|고쳐|해줘|잘\s*해줘)\s*[.!?]*\s*$",
    re.IGNORECASE,
)
_EXPLICIT_CONTINUATION = re.compile(
    r"^\s*(?:continue|continue\s+this\s+task|same[- ]task|"
    r"계속|계속해|계속\s*진행|이\s*작업\s*계속)"
    r"(?:\s*:\s*(?P<body>.+))?\s*$",
    re.IGNORECASE,
)
_EXPLICIT_NEW_TASK = re.compile(
    r"^\s*(?:new\s+task|새\s*작업)\s*:\s*(?P<body>.+?)\s*$",
    re.IGNORECASE,
)
_ANSWER_LIKE = re.compile(
    r"^\s*(?:[A-Da-d](?:로|으로)?(?:\s+.*)?|"
    r"(?:yes|no|approve|reject|네|아니오|응|아니|승인|거절)"
    r"(?:\s+.*)?)\s*[.!]?\s*$",
    re.IGNORECASE,
)
_USER_APPROVAL = re.compile(
    r"^\s*(?:approve|승인)\s+(?P<proposal>"
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*$",
    re.IGNORECASE,
)
_UNRUN_REASON_LINE = re.compile(
    r"^\s*(?:skip|unrun|검증\s*생략)\s+"
    r"(?P<decision>DECISION-unrun-[A-Za-z0-9._:-]+)\s*:\s*"
    r"(?P<reason>\S(?:.*\S)?)\s*$",
    re.IGNORECASE,
)
_PACKAGE_NAME = re.compile(
    r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\Z",
    re.IGNORECASE,
)
_PYTHON_PACKAGE_NAME = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z"
)
_RUST_PACKAGE_NAME = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z"
)
_GO_MODULE_SEGMENT = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._~+-]{0,127}\Z"
)
_DEPENDENCY_REFERENCE = re.compile(
    r"[A-Za-z0-9@][A-Za-z0-9@._+~/-]{0,254}\Z"
)
_SUPPORTED_DEPENDENCY_ECOSYSTEMS = frozenset(
    {"go", "npm", "python", "rust"}
)
_SYMBOL = re.compile(r"[A-Za-z_$][A-Za-z0-9_$.:/-]{0,255}\Z")
_HOSTNAME = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}\Z",
    re.IGNORECASE,
)

_EVIDENCE_KINDS = frozenset(
    {
        "repository-fact",
        "manifest",
        "lockfile",
        "installed-metadata",
        "official-doc",
        "type-definition",
        "source-code",
        "reproduction",
        "test-result",
        "measurement",
    }
)
_NATIVE_CAPABILITY_KINDS = frozenset(
    {"official-doc", "type-definition", "source-code"}
)
_MANIFEST_NAMES = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "Pipfile",
        "Cargo.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile",
    }
)
_LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "Cargo.lock",
        "go.sum",
        "Gemfile.lock",
    }
)
_ECOSYSTEM_MANIFESTS = {
    "go": frozenset({"go.mod"}),
    "npm": frozenset({"package.json"}),
    "python": frozenset(
        {"pyproject.toml", "requirements.txt", "Pipfile"}
    ),
    "rust": frozenset({"Cargo.toml"}),
}
_ECOSYSTEM_LOCKFILES = {
    "go": frozenset({"go.sum"}),
    "npm": frozenset(
        {
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lock",
            "bun.lockb",
        }
    ),
    "python": frozenset({"uv.lock", "poetry.lock", "Pipfile.lock"}),
    "rust": frozenset({"Cargo.lock"}),
}
_PROTECTED_SCOPE_PARTS = frozenset(
    {".git", ".agent-harness", ".codex", ".ssh", ".aws", ".gnupg"}
)
_SECRET_ARTIFACT_NAMES = frozenset(
    {
        "credentials",
        "credentials.json",
        "credentials.yaml",
        "credentials.yml",
        "credentials.toml",
        "secrets.json",
        "secrets.yaml",
        "secrets.yml",
        "secrets.toml",
        "tokens.json",
        "auth.json",
        "service-account.json",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "id_rsa",
        "id_ed25519",
    }
)
_SECRET_KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
_PRIVATE_KEY_ARTIFACT_SUFFIXES = ("", ".txt", ".json", ".yaml", ".yml")
_WALK_SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "coverage",
        "__pycache__",
        ".venv",
    }
)
_UNOBSERVABLE_SCOPE_PARTS = _WALK_SKIP_DIRECTORIES | frozenset(
    {"site-packages", "dist-packages"}
)


class LifecycleError(ValueError):
    """A lease request is invalid or cannot safely advance."""


@dataclass(frozen=True, slots=True)
class EvidenceSpec:
    kind: str
    source_path: str


@dataclass(frozen=True, slots=True)
class DependencyClaim:
    package: str
    exact_version: str
    question_hash: str
    native_symbol: str
    metadata_path: str
    native_path: str
    ecosystem: str = "npm"


@dataclass(frozen=True, slots=True)
class InstalledPackageIdentity:
    ecosystem: str
    package: str
    exact_version: str
    package_root: Path


@dataclass(frozen=True, slots=True)
class LeaseRequest:
    acceptance_hash: str
    allowed_globs: tuple[str, ...]
    verification_ids: tuple[str, ...]
    evidence: tuple[EvidenceSpec, ...]
    dependency_claim: DependencyClaim | None = None
    official_evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AcceptanceInput:
    task_id: str
    task_revision: int
    provenance_hash: str
    outcome: str
    observable_criteria: tuple[str, ...]
    exclusions: tuple[str, ...]
    assumptions: tuple[str, ...]
    resolved_decisions: tuple[str, ...] = ()
    dependency_package: str | None = None
    dependency_question: str | None = None


@dataclass(frozen=True, slots=True)
class TaskClassification:
    phase: str
    pending_decisions: tuple[str, ...]
    dependency_research_required: bool
    risk: str


@dataclass(frozen=True, slots=True)
class LifecycleOutcome:
    status: str
    task_id: str
    proposal_id: str | None = None
    lease_id: str | None = None
    acceptance_hash: str | None = None
    dependency_question_hash: str | None = None
    receipt_id: str | None = None
    phase: str | None = None
    reason: str | None = None
    pending_decision_ids: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "acceptanceHash": self.acceptance_hash,
            "dependencyQuestionHash": self.dependency_question_hash,
            "leaseId": self.lease_id,
            "pendingDecisionIds": list(self.pending_decision_ids),
            "phase": self.phase,
            "proposalId": self.proposal_id,
            "reason": self.reason,
            "receiptId": self.receipt_id,
            "status": self.status,
            "taskId": self.task_id,
        }


def sha256_digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def canonical_digest(value: Any) -> str:
    return sha256_digest(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    )


def classify_task_prompt(prompt: str) -> TaskClassification:
    dependency = bool(
        _ENGLISH_DEPENDENCY.search(prompt) or _KOREAN_DEPENDENCY.search(prompt)
    )
    open_ended = bool(
        _ENGLISH_BUILD.search(prompt) or _KOREAN_BUILD.search(prompt)
    )
    product = bool(
        _ENGLISH_PRODUCT.search(prompt) or _KOREAN_PRODUCT.search(prompt)
    )
    high_risk = bool(_HIGH_RISK.search(prompt))
    generic = bool(_GENERIC_AMBIGUITY.fullmatch(prompt))
    clear_action = bool(_CLEAR_ACTION.search(prompt))
    if (
        high_risk
        or generic
        or not clear_action
        or (open_ended and product)
    ):
        return TaskClassification(
            phase="decision-required",
            pending_decisions=("DECISION-product-contract",),
            dependency_research_required=dependency,
            risk="high" if high_risk else "material",
        )
    if dependency:
        return TaskClassification(
            phase="research-required",
            pending_decisions=(),
            dependency_research_required=True,
            risk="low",
        )
    return TaskClassification(
        phase="discovery",
        pending_decisions=(),
        dependency_research_required=False,
        risk="low",
    )


def _dependency_reference_is_safe(value: str) -> bool:
    if (
        _DEPENDENCY_REFERENCE.fullmatch(value) is None
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
    ):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _package_name_is_valid(ecosystem: str, value: str) -> bool:
    if ecosystem == "npm":
        return _PACKAGE_NAME.fullmatch(value) is not None
    if ecosystem == "python":
        return _PYTHON_PACKAGE_NAME.fullmatch(value) is not None
    if ecosystem == "rust":
        return _RUST_PACKAGE_NAME.fullmatch(value) is not None
    if ecosystem == "go":
        parts = value.split("/")
        return (
            len(parts) >= 2
            and ".." not in value
            and all(_GO_MODULE_SEGMENT.fullmatch(part) is not None for part in parts)
        )
    return False


def _same_package_name(ecosystem: str, left: str, right: str) -> bool:
    if ecosystem == "python":
        return _normalized_package_name(left) == _normalized_package_name(right)
    if ecosystem == "npm":
        return left.casefold() == right.casefold()
    return left == right


def parse_lease_request_tokens(tokens: Sequence[str]) -> LeaseRequest:
    acceptance: str | None = None
    scopes: list[str] = []
    verification_ids: list[str] = []
    evidence: list[EvidenceSpec] = []
    official_evidence_ids: list[str] = []
    dependency_values: dict[str, str] = {}
    if len(tokens) > 64:
        raise LifecycleError("lease request has too many arguments")
    for token in tokens:
        if (
            not isinstance(token, str)
            or not token
            or token != token.strip()
            or any(character in token for character in "\0\n\r")
        ):
            raise LifecycleError("lease request contains an unsafe argument")
        if token.startswith("acceptance="):
            if acceptance is not None:
                raise LifecycleError("acceptance must occur exactly once")
            acceptance = token.removeprefix("acceptance=")
            if _DIGEST.fullmatch(acceptance) is None:
                raise LifecycleError("acceptance is not a SHA-256 digest")
        elif token.startswith("scope="):
            scopes.append(
                validate_lease_scope(token.removeprefix("scope="))
            )
        elif token.startswith("verify="):
            identifier = token.removeprefix("verify=")
            if _IDENTIFIER.fullmatch(identifier) is None:
                raise LifecycleError("verification id is invalid")
            verification_ids.append(identifier)
        elif token.startswith("evidence="):
            encoded = token.removeprefix("evidence=")
            kind, separator, path = encoded.partition(":")
            if not separator or kind not in _EVIDENCE_KINDS:
                raise LifecycleError(
                    "evidence kind is invalid; valid kinds: "
                    + ", ".join(sorted(_EVIDENCE_KINDS))
                )
            evidence.append(
                EvidenceSpec(kind=kind, source_path=validate_relative_path(path))
            )
        elif token.startswith("official="):
            identifier = token.removeprefix("official=")
            if _IDENTIFIER.fullmatch(identifier) is None:
                raise LifecycleError("official Evidence id is invalid")
            official_evidence_ids.append(identifier)
        elif token.startswith("dep-"):
            key, separator, value = token.partition("=")
            if (
                not separator
                or key
                not in {
                    "dep-ecosystem",
                    "dep-package",
                    "dep-version",
                    "dep-question",
                    "dep-symbol",
                    "dep-metadata",
                    "dep-native",
                }
                or key in dependency_values
            ):
                raise LifecycleError("dependency claim argument is invalid")
            dependency_values[key] = value
        else:
            raise LifecycleError("unknown lease request argument")
    if acceptance is None:
        raise LifecycleError("acceptance is required")
    if not scopes:
        raise LifecycleError("at least one write scope is required")
    if not evidence:
        raise LifecycleError("at least one regular-file Evidence is required")
    if len(set(scopes)) != len(scopes):
        raise LifecycleError("write scopes must be unique")
    if len(set(verification_ids)) != len(verification_ids):
        raise LifecycleError("verification ids must be unique")
    evidence_keys = {(item.kind, item.source_path) for item in evidence}
    if len(evidence_keys) != len(evidence):
        raise LifecycleError("Evidence entries must be unique")
    if len(set(official_evidence_ids)) != len(official_evidence_ids):
        raise LifecycleError("official Evidence ids must be unique")
    dependency_claim: DependencyClaim | None = None
    if dependency_values:
        required = {
            "dep-ecosystem",
            "dep-package",
            "dep-version",
            "dep-question",
            "dep-symbol",
            "dep-metadata",
            "dep-native",
        }
        if set(dependency_values) != required:
            raise LifecycleError(
                "dependency claim requires ecosystem, package, exact version, "
                "question, symbol, metadata path, and native path"
            )
        ecosystem = dependency_values["dep-ecosystem"]
        package = dependency_values["dep-package"]
        exact_version = dependency_values["dep-version"]
        question_hash = dependency_values["dep-question"]
        native_symbol = dependency_values["dep-symbol"]
        if (
            ecosystem not in _SUPPORTED_DEPENDENCY_ECOSYSTEMS
            or not _package_name_is_valid(ecosystem, package)
        ):
            raise LifecycleError("dependency package name is invalid")
        if _EXACT_VERSION.fullmatch(exact_version) is None:
            raise LifecycleError("dependency version must be exact")
        if _DIGEST.fullmatch(question_hash) is None:
            raise LifecycleError("dependency question hash is invalid")
        if _SYMBOL.fullmatch(native_symbol) is None:
            raise LifecycleError("dependency native symbol is invalid")
        dependency_claim = DependencyClaim(
            package=package,
            exact_version=exact_version,
            question_hash=question_hash,
            native_symbol=native_symbol,
            metadata_path=validate_relative_path(
                dependency_values["dep-metadata"]
            ),
            native_path=validate_relative_path(
                dependency_values["dep-native"]
            ),
            ecosystem=ecosystem,
        )
    return LeaseRequest(
        acceptance_hash=acceptance,
        allowed_globs=tuple(scopes),
        verification_ids=tuple(verification_ids),
        evidence=tuple(evidence),
        dependency_claim=dependency_claim,
        official_evidence_ids=tuple(official_evidence_ids),
    )


def build_lease_request_command(
    state: GateState,
    request: LeaseRequest,
    *,
    python_executable: PurePath | None = None,
) -> str:
    executable = python_executable or state.read_broker_python_executables[0]
    if executable not in state.read_broker_python_executables:
        raise LifecycleError("Python executable is not state-approved")
    arguments = [
        str(executable),
        str(state.project_root.joinpath(LEASE_REQUEST_RELATIVE_PATH)),
        "request",
        f"acceptance={request.acceptance_hash}",
    ]
    arguments.extend(f"scope={value}" for value in request.allowed_globs)
    arguments.extend(f"verify={value}" for value in request.verification_ids)
    arguments.extend(
        f"evidence={item.kind}:{item.source_path}"
        for item in request.evidence
    )
    arguments.extend(
        f"official={identifier}" for identifier in request.official_evidence_ids
    )
    if request.dependency_claim is not None:
        claim = request.dependency_claim
        arguments.extend(
            [
                f"dep-ecosystem={claim.ecosystem}",
                f"dep-package={claim.package}",
                f"dep-version={claim.exact_version}",
                f"dep-question={claim.question_hash}",
                f"dep-symbol={claim.native_symbol}",
                f"dep-metadata={claim.metadata_path}",
                f"dep-native={claim.native_path}",
            ]
        )
    return shlex.join(arguments)


def parse_acceptance_tokens(tokens: Sequence[str]) -> AcceptanceInput:
    single: dict[str, str] = {}
    criteria: list[str] = []
    exclusions: list[str] = []
    assumptions: list[str] = []
    resolved: list[str] = []
    if not tokens or len(tokens) > 32:
        raise LifecycleError("acceptance command has an invalid argument count")
    for token in tokens:
        if (
            not isinstance(token, str)
            or token != token.strip()
            or any(character in token for character in "\0\n\r")
        ):
            raise LifecycleError("acceptance command contains an unsafe argument")
        key, separator, value = token.partition("=")
        if not separator:
            raise LifecycleError("acceptance argument is malformed")
        if key in {
            "task",
            "revision",
            "provenance",
            "outcome",
            "dependency-package",
            "dependency-question",
        }:
            if key in single:
                raise LifecycleError(f"{key} must occur at most once")
            single[key] = value
        elif key == "criterion":
            criteria.append(_contract_text(value, "criterion"))
        elif key == "exclusion":
            exclusions.append(_contract_text(value, "exclusion"))
        elif key == "assumption":
            assumptions.append(_contract_text(value, "assumption"))
        elif key == "resolve":
            if _IDENTIFIER.fullmatch(value) is None:
                raise LifecycleError("resolved decision id is invalid")
            resolved.append(value)
        else:
            raise LifecycleError("unknown acceptance argument")
    required = {"task", "revision", "provenance", "outcome"}
    if not required.issubset(single):
        raise LifecycleError(
            "acceptance requires task, revision, provenance, and outcome"
        )
    if _IDENTIFIER.fullmatch(single["task"]) is None:
        raise LifecycleError("acceptance task id is invalid")
    try:
        revision = int(single["revision"], 10)
    except ValueError as error:
        raise LifecycleError("acceptance revision is invalid") from error
    if not 1 <= revision <= 1_000_000:
        raise LifecycleError("acceptance revision is out of range")
    if _DIGEST.fullmatch(single["provenance"]) is None:
        raise LifecycleError("acceptance provenance hash is invalid")
    if len(set(resolved)) != len(resolved):
        raise LifecycleError("resolved decision ids must be unique")
    package = single.get("dependency-package")
    question = single.get("dependency-question")
    if (package is None) != (question is None):
        raise LifecycleError(
            "dependency acceptance requires both package and question"
        )
    if package is not None and not _dependency_reference_is_safe(package):
        raise LifecycleError("dependency package name is invalid")
    return AcceptanceInput(
        task_id=single["task"],
        task_revision=revision,
        provenance_hash=single["provenance"],
        outcome=_contract_text(single["outcome"], "outcome"),
        observable_criteria=tuple(criteria),
        exclusions=tuple(exclusions),
        assumptions=tuple(assumptions),
        resolved_decisions=tuple(resolved),
        dependency_package=package,
        dependency_question=(
            None
            if question is None
            else _contract_text(question, "dependency question")
        ),
    )


def build_set_acceptance_command(
    state: GateState,
    acceptance: AcceptanceInput,
    *,
    python_executable: PurePath | None = None,
) -> str:
    executable = python_executable or state.read_broker_python_executables[0]
    if executable not in state.read_broker_python_executables:
        raise LifecycleError("Python executable is not state-approved")
    arguments = [
        str(executable),
        str(state.project_root.joinpath(LEASE_REQUEST_RELATIVE_PATH)),
        "set-acceptance",
        f"task={acceptance.task_id}",
        f"revision={acceptance.task_revision}",
        f"provenance={acceptance.provenance_hash}",
        f"outcome={acceptance.outcome}",
    ]
    arguments.extend(
        f"criterion={value}" for value in acceptance.observable_criteria
    )
    arguments.extend(f"exclusion={value}" for value in acceptance.exclusions)
    arguments.extend(f"assumption={value}" for value in acceptance.assumptions)
    arguments.extend(
        f"resolve={value}" for value in acceptance.resolved_decisions
    )
    if acceptance.dependency_package is not None:
        arguments.append(
            f"dependency-package={acceptance.dependency_package}"
        )
        arguments.append(
            f"dependency-question={acceptance.dependency_question}"
        )
    return shlex.join(arguments)


def parse_official_registration_tokens(
    tokens: Sequence[str],
) -> dict[str, str]:
    values: dict[str, str] = {}
    for token in tokens:
        if (
            not isinstance(token, str)
            or token != token.strip()
            or any(character in token for character in "\0\n\r")
        ):
            raise LifecycleError(
                "official Evidence command contains an unsafe argument"
            )
        key, separator, value = token.partition("=")
        if (
            not separator
            or key not in {"package", "question", "url"}
            or key in values
        ):
            raise LifecycleError("official Evidence argument is invalid")
        values[key] = value
    if set(values) != {"package", "question", "url"}:
        raise LifecycleError(
            "official Evidence requires package, question, and url"
        )
    if not _dependency_reference_is_safe(values["package"]):
        raise LifecycleError("official Evidence package name is invalid")
    if _DIGEST.fullmatch(values["question"]) is None:
        raise LifecycleError("official Evidence question hash is invalid")
    _validate_official_url(values["url"])
    return values


def parse_official_read_tokens(
    tokens: Sequence[str],
) -> tuple[str, int, int]:
    if not tokens or _IDENTIFIER.fullmatch(tokens[0]) is None:
        raise LifecycleError("official-read requires a valid Evidence id")
    values = _parse_bounded_official_options(
        tokens[1:],
        defaults={"--lines": 200, "--start": 1},
        maximums={
            "--lines": MAX_OFFICIAL_OUTPUT_LINES,
            "--start": 2**31 - 1,
        },
    )
    return tokens[0], values["--start"], values["--lines"]


def parse_official_search_tokens(
    tokens: Sequence[str],
) -> tuple[str, str, int]:
    if len(tokens) < 2 or _IDENTIFIER.fullmatch(tokens[0]) is None:
        raise LifecycleError(
            "official-search requires a valid Evidence id and pattern"
        )
    pattern = tokens[1]
    if (
        not pattern
        or pattern.startswith("-")
        or len(pattern) > MAX_OFFICIAL_SEARCH_PATTERN
        or any(character in pattern for character in "\0\n\r")
    ):
        raise LifecycleError("official-search pattern is empty or unsafe")
    values = _parse_bounded_official_options(
        tokens[2:],
        defaults={"--limit": 50},
        maximums={"--limit": MAX_OFFICIAL_SEARCH_RESULTS},
    )
    return tokens[0], pattern, values["--limit"]


def _parse_bounded_official_options(
    tokens: Sequence[str],
    *,
    defaults: dict[str, int],
    maximums: dict[str, int],
) -> dict[str, int]:
    values = dict(defaults)
    seen: set[str] = set()
    index = 0
    while index < len(tokens):
        option = tokens[index]
        if (
            option not in defaults
            or option in seen
            or index + 1 >= len(tokens)
        ):
            raise LifecycleError("official Evidence read option is invalid")
        rendered = tokens[index + 1]
        if not rendered.isascii() or not rendered.isdecimal():
            raise LifecycleError(
                "official Evidence read limits must be positive integers"
            )
        number = int(rendered)
        if number < 1 or number > maximums[option]:
            raise LifecycleError(
                "official Evidence read limit is outside the allowed range"
            )
        values[option] = number
        seen.add(option)
        index += 2
    return values


def _contract_text(value: str, field: str) -> str:
    text = " ".join(value.split())
    if (
        not text
        or len(text) > 800
        or any(character in text for character in "\0\n\r")
    ):
        raise LifecycleError(f"{field} is empty, multiline, or too long")
    return text


def is_lifecycle_command(command: str, state: GateState) -> bool:
    """Recognize one exact agent-callable protected lifecycle command."""

    if any(character in command for character in "\0\n\r"):
        return False
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return False
    if len(arguments) < 3:
        return False
    try:
        executable = PurePath(arguments[0])
        broker = PurePath(arguments[1])
    except (TypeError, ValueError):
        return False
    if executable not in state.read_broker_python_executables:
        return False
    if broker != state.project_root.joinpath(LEASE_REQUEST_RELATIVE_PATH):
        return False
    if command != shlex.join(arguments):
        return False
    try:
        operation = arguments[2]
        if operation == "request":
            if len(arguments) < 6:
                return False
            parse_lease_request_tokens(arguments[3:])
        elif operation == "set-acceptance":
            parse_acceptance_tokens(arguments[3:])
        elif operation == "register-official":
            parse_official_registration_tokens(arguments[3:])
        elif operation == "official-read":
            parse_official_read_tokens(arguments[3:])
        elif operation == "official-search":
            parse_official_search_tokens(arguments[3:])
        elif operation in {"renew", "complete"}:
            if len(arguments) != 4 or _IDENTIFIER.fullmatch(arguments[3]) is None:
                return False
        elif operation == "describe":
            if len(arguments) != 3:
                return False
        else:
            return False
    except (LifecycleError, StateValidationError):
        return False
    return True


def is_lease_request_command(command: str, state: GateState) -> bool:
    """Backward-compatible name for the exact lifecycle recognizer."""

    return is_lifecycle_command(command, state)


def validate_relative_path(value: str) -> str:
    rendered = value.replace("\\", "/")
    path = PurePath(rendered)
    if (
        not rendered
        or rendered.startswith("/")
        or rendered.endswith("/")
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(character in rendered for character in "*?[]{}")
    ):
        raise LifecycleError("Evidence path must be safe and project-relative")
    return path.as_posix()


def validate_lease_scope(value: str) -> str:
    try:
        scope = validate_safe_glob(value)
    except StateValidationError as error:
        raise LifecycleError(str(error)) from error
    _validate_observable_scope(scope)
    parts = scope.split("/")
    first = parts[0]
    if (
        first.startswith(".")
        or any(character in first for character in "*?")
        or any(part.lower() in _PROTECTED_SCOPE_PARTS for part in parts)
        or any(part.startswith(".") for part in parts)
    ):
        raise LifecycleError("write scope is broad or protected")
    final = parts[-1].lower()
    protected_names = _MANIFEST_NAMES | _LOCKFILE_NAMES
    if final not in {"*", "**"} and any(
        fnmatch.fnmatchcase(name.lower(), final) for name in protected_names
    ):
        if any(character in final for character in "*?"):
            raise LifecycleError(
                "manifest and lockfile scopes must name one exact path"
            )
    if _is_secret_artifact_path(parts):
        raise LifecycleError("secret-bearing write scopes are protected")
    return scope


def _is_secret_artifact_path(parts: Sequence[str]) -> bool:
    lowered = tuple(part.casefold() for part in parts)
    name = lowered[-1] if lowered else ""
    private_key_artifact = (
        "private-key" in name or "private_key" in name
    ) and Path(name).suffix in _PRIVATE_KEY_ARTIFACT_SUFFIXES
    return (
        any(part.startswith(".env") for part in lowered)
        or any(part in _SECRET_ARTIFACT_NAMES for part in lowered)
        or any(part.endswith(_SECRET_KEY_SUFFIXES) for part in lowered)
        or private_key_artifact
    )


def _validate_observable_scope(scope: str) -> str:
    if any(
        part.casefold() in _UNOBSERVABLE_SCOPE_PARTS
        for part in PurePath(scope).parts
    ):
        raise LifecycleError(
            "write scope targets an unobservable dependency, cache, or generated root"
        )
    return scope


def _is_exact_dependency_scope(scope: str) -> bool:
    if any(character in scope for character in "*?"):
        return False
    return PurePath(scope).name.casefold() in {
        name.casefold() for name in (_MANIFEST_NAMES | _LOCKFILE_NAMES)
    }


def record_prompt_task(
    *,
    prompt: str,
    repo: Path,
    state_path: Path,
) -> dict[str, Any]:
    """Record a user turn, revoking stale authority before classifying it.

    A later prompt is never silently treated as compatible with an active
    lease.  Only an explicit continuation or a bounded answer to a pending
    decision keeps the Task identity.  ``new task: ...`` explicitly abandons
    pending work.  Every kept Task still advances its revision and revokes the
    old lease.
    """

    normalized = prompt.strip()
    if not normalized:
        raise LifecycleError("Task prompt is empty")
    repo = repo.resolve(strict=True)
    validate_authoritative_state_path(state_path, repo)
    with state_lock(state_path):
        state_value = load_json_object(state_path)
        state = parse_gate_state(json.dumps(state_value))
        if Path(state.project_root) != repo:
            raise LifecycleError("Gate state belongs to another Project")
        existing = _load_current_contract(state_path, state)
        continuation = _EXPLICIT_CONTINUATION.fullmatch(normalized)
        explicit_new_task = _EXPLICIT_NEW_TASK.fullmatch(normalized)
        answer_like = bool(_ANSWER_LIKE.fullmatch(normalized))
        has_active_lease = state.write_lease is not None
        keep_task = existing is not None and (
            explicit_new_task is None
            and (
                continuation is not None
                or bool(state.pending_decisions)
                or answer_like
            )
        )
        revoked_lease_id = (
            state.write_lease.id if state.write_lease is not None else None
        )
        if keep_task and existing is not None:
            material_body = (
                continuation.group("body")
                if continuation is not None
                else normalized
            )
            material = bool(material_body and material_body.strip())
            provenance_kind = (
                "user-answer"
                if state.pending_decisions or answer_like
                else "explicit-continuation"
            )
            contract = _revise_contract(
                existing,
                prompt=normalized,
                provenance_kind=provenance_kind,
                material=material,
            )
            preserved = True
        else:
            contract = _new_task_contract(
                prompt=(
                    explicit_new_task.group("body")
                    if explicit_new_task is not None
                    else normalized
                ),
                provenance_prompt=normalized,
                project_id=state.project_id,
                previous_task_id=state.task_id,
                previous_acceptance_hash=state.acceptance_hash,
            )
            preserved = False
        acceptance_hash = acceptance_contract_hash(contract)
        contract["acceptanceHash"] = acceptance_hash
        phase = _contract_phase(contract)
        prelease_hash = canonical_digest(
            {
                "acceptanceHash": acceptance_hash,
                "phase": phase,
                "projectId": state.project_id,
                "taskId": contract["taskId"],
                "taskRevision": contract["taskRevision"],
            }
        )
        state_value.update(
            {
                "acceptanceHash": acceptance_hash,
                "baseTreeHash": prelease_hash,
                "evidence": [],
                "pendingDecisions": list(contract["pendingDecisions"]),
                "phase": phase,
                "taskId": contract["taskId"],
                "writeLease": None,
            }
        )
        parse_gate_state(json.dumps(state_value))
        atomic_write_json(contract_path(state_path), contract)
        atomic_write_json(state_path, state_value)
        _reset_lifecycle_sidecars(
            state_path,
            task_id=contract["taskId"],
            task_revision=contract["taskRevision"],
            revoked_lease_id=revoked_lease_id,
        )
        result = task_context_from_state(state_value, preserved=preserved)
        result.update(
            {
                "acceptanceComplete": (
                    contract["acceptanceStatus"] == "accepted"
                ),
                "dependencyResearchRequired": (
                    contract.get("dependencyResearchRequired") is True
                ),
                "latestPromptHash": contract["latestPromptHash"],
                "leaseRevoked": has_active_lease,
                "taskRevision": contract["taskRevision"],
            }
        )
        return result


def process_user_prompt(
    *,
    prompt: str,
    repo: Path,
    state_path: Path,
    config_path: Path,
    profile_path: Path,
) -> dict[str, Any]:
    """Handle a user-authenticated approval or record a normal user turn."""

    normalized = prompt.strip()
    approval = _USER_APPROVAL.fullmatch(normalized)
    if approval is not None:
        prompt_hash = sha256_digest(normalized.encode("utf-8"))
        outcome = approve_proposal(
            proposal_id=approval.group("proposal"),
            repo=repo,
            state_path=state_path,
            config_path=config_path,
            profile_path=profile_path,
            user_prompt_hash=prompt_hash,
        )
        state = load_json_object(state_path)
        context = task_context_from_state(state, preserved=True)
        context.update(
            {
                "acceptanceComplete": True,
                "dependencyResearchRequired": (
                    load_json_object(contract_path(state_path)).get(
                        "dependencyResearchRequired"
                    )
                    is True
                ),
                "lifecycleAction": outcome.status,
                "proposalId": outcome.proposal_id,
                "leaseId": outcome.lease_id,
            }
        )
        return context
    return record_prompt_task(
        prompt=normalized,
        repo=repo,
        state_path=state_path,
    )


def revoke_write_lease_after_prompt_failure(
    *,
    repo: Path,
    state_path: Path,
) -> bool:
    """Atomically remove stale write authority after a failed prompt submit."""

    repo = repo.resolve(strict=True)
    validate_authoritative_state_path(state_path, repo)
    with state_lock(state_path):
        state_value = load_json_object(state_path)
        project_root = state_value.get("projectRoot")
        if project_root != str(repo):
            raise LifecycleError("Gate state belongs to another Project")
        lease = state_value.get("writeLease")
        if lease is None:
            return False
        revoked_id = (
            lease.get("id") if isinstance(lease, dict) else "invalid-lease"
        )
        state_value["phase"] = "blocked"
        state_value["writeLease"] = None
        try:
            parse_gate_state(json.dumps(state_value))
        except StateValidationError:
            # Even a partially stale state must lose its capability. The
            # remaining schema error makes subsequent tool use fail closed.
            pass
        atomic_write_json(state_path, state_value)
        task_id = state_value.get("taskId")
        if isinstance(task_id, str):
            atomic_write_json(
                receipts_path(state_path),
                {
                    "receipts": [],
                    "revokedLeaseId": revoked_id,
                    "schemaVersion": 1,
                    "taskId": task_id,
                },
            )
        return True


def set_acceptance_contract(
    *,
    acceptance: AcceptanceInput,
    repo: Path,
    state_path: Path,
    config_path: Path,
    profile_path: Path,
) -> LifecycleOutcome:
    """Install a complete, structured acceptance contract in host state."""

    repo = repo.resolve(strict=True)
    validate_authoritative_state_path(state_path, repo)
    with state_lock(state_path):
        state_value = load_json_object(state_path)
        state = parse_gate_state(json.dumps(state_value))
        if Path(state.project_root) != repo:
            raise LifecycleError("Gate state belongs to another Project")
        if state.write_lease is not None:
            raise LifecycleError(
                "active lease must be revoked by a user turn before acceptance changes"
            )
        contract = load_json_object(contract_path(state_path))
        _validate_contract_identity(contract, state)
        if (
            acceptance.task_id != state.task_id
            or acceptance.task_revision != contract.get("taskRevision")
            or acceptance.provenance_hash != contract.get("latestPromptHash")
        ):
            raise LifecycleError(
                "acceptance does not match the current Task revision and user provenance"
            )
        pending = list(state.pending_decisions)
        pending_set = set(pending)
        previous_verification_pending = (
            _verification_plan_pending_decisions(contract)
        )
        if not previous_verification_pending.issubset(pending_set):
            raise LifecycleError(
                "verification plan decisions do not match current Gate state"
            )
        unknown_resolutions = set(acceptance.resolved_decisions) - set(pending)
        if unknown_resolutions:
            raise LifecycleError(
                f"acceptance resolves unknown decisions: {sorted(unknown_resolutions)}"
            )
        superseded_verification_decisions: set[str] = set()
        if (
            pending
            and not acceptance.resolved_decisions
            and previous_verification_pending
            and contract.get("acceptanceFromPromptHash")
            == acceptance.provenance_hash
            and contract.get("acceptanceAtTaskRevision")
            == acceptance.task_revision
        ):
            # A verification decision belongs to the agent-authored acceptance
            # draft that created it. Before any Write Lease exists, the agent
            # may replace that same-provenance draft and let the host build a
            # fresh verification plan. Product/user decisions remain pending.
            superseded_verification_decisions = previous_verification_pending
            pending = [
                identifier
                for identifier in pending
                if identifier not in superseded_verification_decisions
            ]
        if pending and set(acceptance.resolved_decisions) != set(pending):
            raise LifecycleError(
                "unresolved user decisions prohibit setting acceptance"
            )
        _validate_acceptance_completeness(acceptance)
        if acceptance.resolved_decisions:
            provenance = contract.get("userProvenance")
            latest = provenance[-1] if isinstance(provenance, list) and provenance else {}
            if (
                not isinstance(latest, dict)
                or latest.get("kind") != "user-answer"
                or latest.get("contentHash") != acceptance.provenance_hash
            ):
                raise LifecycleError(
                    "decisions require a recorded later user answer as provenance"
                )
            pending = [
                identifier
                for identifier in pending
                if identifier not in acceptance.resolved_decisions
            ]
        dependency_required = (
            contract.get("dependencyResearchRequired") is True
            or acceptance.dependency_package is not None
        )
        if dependency_required and (
            acceptance.dependency_package is None
            or acceptance.dependency_question is None
        ):
            raise LifecycleError(
                "dependency Tasks require a package and explicit research question"
            )
        dependency: dict[str, Any] | None = None
        if acceptance.dependency_package is not None:
            question = acceptance.dependency_question or ""
            dependency = {
                "package": acceptance.dependency_package,
                "question": question,
                "questionHash": sha256_digest(question.encode("utf-8")),
            }
        config = load_json_object(config_path)
        profile = load_json_object(profile_path)
        verification_plan = build_verification_plan(
            criteria=acceptance.observable_criteria,
            risk=str(contract.get("risk", "")),
            config=config,
            profile=profile,
            unrun_decisions=_validated_unrun_decisions(contract),
        )
        pending = sorted(
            set(pending)
            | set(verification_plan["pendingDecisionIds"])
        )
        acceptance_status = "accepted" if not pending else "draft"
        contract.update(
            {
                "acceptance": {
                    "assumptions": list(acceptance.assumptions),
                    "exclusions": list(acceptance.exclusions),
                    "observableCriteria": list(
                        acceptance.observable_criteria
                    ),
                    "outcome": acceptance.outcome,
                    "resolvedDecisions": list(
                        acceptance.resolved_decisions
                    ),
                },
                "acceptanceStatus": acceptance_status,
                "acceptanceAtTaskRevision": acceptance.task_revision,
                "acceptanceFromPromptHash": acceptance.provenance_hash,
                "acceptedFromPromptHash": (
                    acceptance.provenance_hash
                    if acceptance_status == "accepted"
                    else None
                ),
                "dependency": dependency,
                "dependencyResearchRequired": dependency_required,
                "pendingDecisions": pending,
                "supersededVerificationDecisionIds": sorted(
                    superseded_verification_decisions
                ),
                "verificationPlan": verification_plan,
            }
        )
        acceptance_hash = acceptance_contract_hash(contract)
        contract["acceptanceHash"] = acceptance_hash
        phase = _contract_phase(contract)
        state_value.update(
            {
                "acceptanceHash": acceptance_hash,
                "baseTreeHash": canonical_digest(
                    {
                        "acceptanceHash": acceptance_hash,
                        "phase": phase,
                        "projectId": state.project_id,
                        "taskId": state.task_id,
                        "taskRevision": contract["taskRevision"],
                    }
                ),
                "evidence": [],
                "pendingDecisions": pending,
                "phase": phase,
                "writeLease": None,
            }
        )
        parse_gate_state(json.dumps(state_value))
        atomic_write_json(contract_path(state_path), contract)
        atomic_write_json(state_path, state_value)
        return LifecycleOutcome(
            status=(
                "decision-required" if pending else "acceptance-set"
            ),
            task_id=state.task_id,
            acceptance_hash=acceptance_hash,
            dependency_question_hash=(
                str(dependency["questionHash"])
                if dependency is not None
                else None
            ),
            pending_decision_ids=tuple(pending),
            phase=phase,
            reason=(
                "unresolved user decisions remain; unrun verification "
                "decisions require `skip DECISION-id: explicit reason`"
                if pending
                else None
            ),
        )


def acceptance_contract_hash(contract: dict[str, Any]) -> str:
    material = dict(contract)
    material.pop("acceptanceHash", None)
    return canonical_digest(material)


def _new_task_contract(
    *,
    prompt: str,
    provenance_prompt: str | None = None,
    project_id: str,
    previous_task_id: str,
    previous_acceptance_hash: str,
) -> dict[str, Any]:
    classification = classify_task_prompt(prompt)
    prompt_hash = sha256_digest(
        (provenance_prompt or prompt).encode("utf-8")
    )
    task_material = {
        "previousAcceptanceHash": previous_acceptance_hash,
        "previousTaskId": previous_task_id,
        "projectId": project_id,
        "promptHash": prompt_hash,
    }
    task_id = (
        f"TASK-{canonical_digest(task_material).removeprefix('sha256:')[:16]}"
    )
    return {
        "acceptance": None,
        "acceptanceAtTaskRevision": None,
        "acceptanceFromPromptHash": None,
        "acceptanceStatus": "draft",
        "acceptedFromPromptHash": None,
        "dependency": None,
        "dependencyResearchRequired": (
            classification.dependency_research_required
        ),
        "latestPromptHash": prompt_hash,
        "originalRequestHash": prompt_hash,
        "pendingDecisions": list(classification.pending_decisions),
        "projectId": project_id,
        "risk": classification.risk,
        "schemaVersion": 2,
        "taskId": task_id,
        "taskRevision": 1,
        "unrunDecisions": {},
        "userProvenance": [
            {
                "contentHash": prompt_hash,
                "kind": "initial-request",
                "sequence": 1,
            }
        ],
    }


def _revise_contract(
    contract: dict[str, Any],
    *,
    prompt: str,
    provenance_kind: str,
    material: bool,
) -> dict[str, Any]:
    revised = json.loads(json.dumps(contract))
    revision = revised.get("taskRevision")
    if type(revision) is not int:
        raise LifecycleError("task contract revision is invalid")
    prompt_hash = sha256_digest(prompt.encode("utf-8"))
    provenance = revised.get("userProvenance")
    if not isinstance(provenance, list):
        raise LifecycleError("task contract provenance is invalid")
    revision += 1
    provenance.append(
        {
            "contentHash": prompt_hash,
            "kind": provenance_kind,
            "sequence": revision,
        }
    )
    pending = revised.get("pendingDecisions")
    if not isinstance(pending, list):
        raise LifecycleError("task contract pending decisions are invalid")
    unrun_decisions = revised.get("unrunDecisions")
    if not isinstance(unrun_decisions, dict):
        raise LifecycleError("task contract unrun decisions are invalid")
    for identifier, reason in _parse_user_unrun_reasons(prompt).items():
        if identifier in pending:
            unrun_decisions[identifier] = {
                "provenanceHash": prompt_hash,
                "reason": reason,
            }
    revised["taskRevision"] = revision
    revised["latestPromptHash"] = prompt_hash
    if material:
        revised["acceptance"] = None
        revised["acceptanceAtTaskRevision"] = None
        revised["acceptanceFromPromptHash"] = None
        revised["acceptanceStatus"] = "draft"
        revised["acceptedFromPromptHash"] = None
        revised["dependency"] = None
    revised.pop("acceptanceHash", None)
    return revised


def _parse_user_unrun_reasons(prompt: str) -> dict[str, str]:
    answers: dict[str, str] = {}
    for line in prompt.splitlines():
        match = _UNRUN_REASON_LINE.fullmatch(line)
        if match is None:
            continue
        identifier = match.group("decision")
        reason = match.group("reason").strip()
        if len(reason) < 12:
            continue
        answers[identifier] = reason
    return answers


def _validated_unrun_decisions(
    contract: dict[str, Any],
) -> dict[str, dict[str, str]]:
    raw = contract.get("unrunDecisions")
    provenance = contract.get("userProvenance")
    if not isinstance(raw, dict) or not isinstance(provenance, list):
        raise LifecycleError("task contract unrun decisions are invalid")
    user_answer_hashes = {
        item.get("contentHash")
        for item in provenance
        if isinstance(item, dict) and item.get("kind") == "user-answer"
    }
    validated: dict[str, dict[str, str]] = {}
    for identifier, answer in raw.items():
        if (
            not isinstance(identifier, str)
            or _UNRUN_REASON_LINE.fullmatch(
                f"skip {identifier}: placeholder reason"
            )
            is None
            or not isinstance(answer, dict)
        ):
            raise LifecycleError("task contract unrun decision is invalid")
        reason = answer.get("reason")
        provenance_hash = answer.get("provenanceHash")
        if (
            not isinstance(reason, str)
            or len(reason) < 12
            or not isinstance(provenance_hash, str)
            or provenance_hash not in user_answer_hashes
        ):
            raise LifecycleError("task contract unrun decision is invalid")
        validated[identifier] = {
            "provenanceHash": provenance_hash,
            "reason": reason,
        }
    return validated


def _verification_plan_pending_decisions(
    contract: dict[str, Any],
) -> set[str]:
    plan = contract.get("verificationPlan")
    if plan is None:
        return set()
    if not isinstance(plan, dict):
        raise LifecycleError("task contract verification plan is invalid")
    raw = plan.get("pendingDecisionIds")
    if not isinstance(raw, list):
        raise LifecycleError(
            "task contract verification decisions are invalid"
        )
    pending: set[str] = set()
    for value in raw:
        if (
            not isinstance(value, str)
            or _IDENTIFIER.fullmatch(value) is None
            or not value.startswith("DECISION-unrun-")
            or value in pending
        ):
            raise LifecycleError(
                "task contract verification decisions are invalid"
            )
        pending.add(value)
    return pending


def _load_current_contract(
    state_path: Path, state: GateState
) -> dict[str, Any] | None:
    path = contract_path(state_path)
    if not path.exists():
        return None
    contract = load_json_object(path)
    try:
        _validate_contract_identity(contract, state)
    except LifecycleError:
        return None
    return contract


def _validate_contract_identity(
    contract: dict[str, Any], state: GateState
) -> None:
    if (
        contract.get("schemaVersion") != 2
        or contract.get("projectId") != state.project_id
        or contract.get("taskId") != state.task_id
        or contract.get("acceptanceHash") != state.acceptance_hash
        or acceptance_contract_hash(contract) != state.acceptance_hash
    ):
        raise LifecycleError("task contract does not match current Gate state")


def _contract_phase(contract: dict[str, Any]) -> str:
    pending = contract.get("pendingDecisions")
    if isinstance(pending, list) and pending:
        return "decision-required"
    if contract.get("acceptanceStatus") != "accepted":
        return "discovery-locked"
    if contract.get("dependencyResearchRequired") is True:
        return "research-required"
    return "discovery"


def _validate_acceptance_completeness(
    acceptance: AcceptanceInput,
) -> None:
    outcome = acceptance.outcome
    if len(outcome) < 12 or _GENERIC_AMBIGUITY.fullmatch(outcome):
        raise LifecycleError(
            "acceptance outcome is too vague to authorize implementation"
        )
    if (
        not acceptance.observable_criteria
        or not acceptance.exclusions
        or not acceptance.assumptions
    ):
        raise LifecycleError(
            "acceptance requires observable criteria, exclusions, and assumptions"
        )
    for label, values in (
        ("observable criteria", acceptance.observable_criteria),
        ("exclusions", acceptance.exclusions),
        ("assumptions", acceptance.assumptions),
    ):
        if len(values) > 8 or len(set(values)) != len(values):
            raise LifecycleError(f"{label} are duplicated or too numerous")
        if any(len(value) < 4 for value in values):
            raise LifecycleError(f"{label} contain an incomplete item")
    observable = re.compile(
        r"\b(test|build|typecheck|lint|output|return|render|error|file|"
        r"command|status|pass|fail|equal|count|latency|http|browser|"
        r"interaction|viewport|benchmark|performance)\w*\b|"
        r"(테스트|빌드|타입|린트|출력|반환|렌더|오류|파일|명령|"
        r"상태|통과|실패|동작|같|브라우저|상호작용|성능)",
        re.IGNORECASE,
    )
    if not any(observable.search(value) for value in acceptance.observable_criteria):
        raise LifecycleError(
            "acceptance needs at least one mechanically observable criterion"
        )


def _reset_lifecycle_sidecars(
    state_path: Path,
    *,
    task_id: str,
    task_revision: int,
    revoked_lease_id: str | None,
) -> None:
    atomic_write_json(
        receipts_path(state_path),
        {
            "receipts": [],
            "revokedLeaseId": revoked_lease_id,
            "schemaVersion": 1,
            "taskId": task_id,
            "taskRevision": task_revision,
        },
    )
    if proposal_path(state_path).exists():
        atomic_write_json(
            proposal_path(state_path),
            {
                "revokedLeaseId": revoked_lease_id,
                "schemaVersion": 1,
                "status": "task-revised",
                "taskId": task_id,
                "taskRevision": task_revision,
            },
        )


def request_write_lease(
    *,
    request: LeaseRequest,
    repo: Path,
    state_path: Path,
    config_path: Path,
    profile_path: Path,
    now: datetime | None = None,
    force_user_approval: bool = False,
    expected_proposal_id: str | None = None,
    renewing_lease_id: str | None = None,
) -> LifecycleOutcome:
    """Validate a request, persist a proposal, and issue only when authorized."""

    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise LifecycleError("lease clock must be timezone-aware")
    repo = repo.resolve(strict=True)
    validate_authoritative_state_path(state_path, repo)
    with state_lock(state_path):
        state_value = load_json_object(state_path)
        state = parse_gate_state(json.dumps(state_value))
        if Path(state.project_root) != repo:
            raise LifecycleError("Gate state belongs to another Project")
        if state.write_lease is not None:
            if renewing_lease_id != state.write_lease.id:
                raise LifecycleError(
                    "an active lease already exists; use the exact renew operation"
                )
        contract = load_json_object(contract_path(state_path))
        validate_contract(contract, state, request)
        config = load_json_object(config_path)
        profile = load_json_object(profile_path)
        max_scopes, lease_minutes, auto_approve = gate_configuration(config)
        if len(request.allowed_globs) > max_scopes:
            raise LifecycleError(
                f"write request exceeds the {max_scopes}-scope limit"
            )
        commands = registered_verification_commands(
            state, profile, request.verification_ids
        )
        validate_verification_plan(
            contract=contract,
            config=config,
            profile=profile,
            selected_ids=request.verification_ids,
        )
        evidence = capture_evidence(
            repo,
            request.evidence,
            state_path=state_path,
            official_evidence_ids=request.official_evidence_ids,
        )
        dependency_claim_material: dict[str, Any] | None = None
        if contract.get("dependencyResearchRequired") is True:
            dependency_claim_material = validate_dependency_evidence(
                evidence,
                repo,
                contract=contract,
                claim=request.dependency_claim,
                state_path=state_path,
                official_evidence_ids=request.official_evidence_ids,
            )
            evidence.append(
                {
                    "contentHash": canonical_digest(
                        dependency_claim_material
                    ),
                    "id": (
                        "CLAIM-"
                        + canonical_digest(
                            dependency_claim_material
                        ).removeprefix("sha256:")[:16]
                    ),
                    "kind": "dependency-claim",
                    "sourcePath": (
                        "@claim/"
                        + canonical_digest(
                            dependency_claim_material
                        ).removeprefix("sha256:")[:16]
                    ),
                }
            )
        elif request.dependency_claim is not None:
            raise LifecycleError(
                "dependency claim is not valid for a non-dependency Task"
            )

        pre_write_implementation_hash = observe_scope_tree(
            repo, request.allowed_globs
        )
        proposal_material = {
            "acceptanceHash": request.acceptance_hash,
            "allowedGlobs": list(request.allowed_globs),
            "dependencyClaim": dependency_claim_material,
            "evidence": evidence,
            "officialEvidenceIds": list(request.official_evidence_ids),
            "preWriteImplementationTreeHash": (
                pre_write_implementation_hash
            ),
            "projectId": state.project_id,
            "schemaVersion": 1,
            "taskId": state.task_id,
            "taskRevision": contract["taskRevision"],
            "verificationIds": list(request.verification_ids),
        }
        proposal_id = (
            f"PROPOSAL-{canonical_digest(proposal_material).removeprefix('sha256:')[:16]}"
        )
        if expected_proposal_id is not None and proposal_id != expected_proposal_id:
            raise LifecycleError("proposal changed before user approval")

        decision_blocked = bool(state.pending_decisions) or (
            state.phase == "decision-required"
        )
        protected_dependency_scopes = [
            scope
            for scope in request.allowed_globs
            if _is_exact_dependency_scope(scope)
        ]
        low_risk = (
            contract.get("risk") == "low"
            and state.phase
            in {"discovery", "research-required", "implementing", "verifying"}
            and all(
                "*" not in scope and "?" not in scope
                for scope in request.allowed_globs
            )
            and not protected_dependency_scopes
        )
        should_issue = (
            not decision_blocked
            and (
                force_user_approval
                or (auto_approve and low_risk)
            )
        )
        proposal = {
            **proposal_material,
            "createdAt": current_time.isoformat(),
            "requiresProtectedScopeApproval": bool(
                protected_dependency_scopes
            ),
            "proposalId": proposal_id,
            "status": (
                "decision-required"
                if decision_blocked
                else ("approved" if should_issue else "awaiting-user-approval")
            ),
        }
        atomic_write_json(proposal_path(state_path), proposal)
        if not should_issue:
            reason = (
                "pending decisions cannot be auto-approved"
                if decision_blocked
                else (
                    "explicit user approval is required; send the exact user "
                    f"prompt `approve {proposal_id}` or run the broker outside "
                    "the Coding Agent"
                )
            )
            return LifecycleOutcome(
                status=proposal["status"],
                task_id=state.task_id,
                proposal_id=proposal_id,
                phase=state.phase,
                reason=reason,
            )

        base_hash = observe_outside_scope_tree(
            repo, request.allowed_globs
        )
        state_value.update(
            {
                "acceptanceHash": request.acceptance_hash,
                "baseTreeHash": base_hash,
                "evidence": evidence,
                "phase": "implementing",
                "writeLease": None,
            }
        )
        prelease_state = parse_gate_state(json.dumps(state_value))
        evidence_hash = evidence_set_hash(prelease_state.evidence)
        binding_hash = lease_state_hash(prelease_state)
        lease_body = {
            "acceptanceHash": request.acceptance_hash,
            "allowedCommands": list(commands),
            "allowedGlobs": list(request.allowed_globs),
            "baseTreeHash": base_hash,
            "expiresAt": (
                current_time + timedelta(minutes=lease_minutes)
            ).isoformat(),
            "issuedAt": current_time.isoformat(),
            "issuedForEvidenceHash": evidence_hash,
            "issuedForStateHash": binding_hash,
            "projectId": state.project_id,
            "taskId": state.task_id,
        }
        lease_id = (
            f"LEASE-{canonical_digest(lease_body).removeprefix('sha256:')[:16]}"
        )
        state_value["writeLease"] = {"id": lease_id, **lease_body}
        parse_gate_state(json.dumps(state_value))
        atomic_write_json(state_path, state_value)
        atomic_write_json(
            receipts_path(state_path),
            {
                "leaseId": lease_id,
                "receipts": [],
                "schemaVersion": 1,
                "taskId": state.task_id,
                "taskRevision": contract["taskRevision"],
            },
        )
        proposal["status"] = "lease-issued"
        proposal["leaseId"] = lease_id
        proposal["approvalMode"] = (
            "user" if force_user_approval else "automatic"
        )
        atomic_write_json(proposal_path(state_path), proposal)
        return LifecycleOutcome(
            status="lease-issued",
            task_id=state.task_id,
            proposal_id=proposal_id,
            lease_id=lease_id,
            acceptance_hash=request.acceptance_hash,
            phase="implementing",
        )


def approve_proposal(
    *,
    proposal_id: str,
    repo: Path,
    state_path: Path,
    config_path: Path,
    profile_path: Path,
    now: datetime | None = None,
    user_prompt_hash: str | None = None,
) -> LifecycleOutcome:
    """Issue a previously saved proposal after an out-of-band user action."""

    if _IDENTIFIER.fullmatch(proposal_id) is None:
        raise LifecycleError("proposal id is invalid")
    proposal = load_json_object(proposal_path(state_path))
    if proposal.get("proposalId") != proposal_id:
        raise LifecycleError("proposal is missing or no longer current")
    tokens = [f"acceptance={proposal.get('acceptanceHash', '')}"]
    tokens.extend(f"scope={item}" for item in proposal.get("allowedGlobs", []))
    tokens.extend(
        f"verify={item}" for item in proposal.get("verificationIds", [])
    )
    for item in proposal.get("evidence", []):
        if (
            isinstance(item, dict)
            and item.get("kind") != "dependency-claim"
            and isinstance(item.get("sourcePath"), str)
            and not item["sourcePath"].startswith("@")
        ):
            tokens.append(
                f"evidence={item.get('kind', '')}:{item.get('sourcePath', '')}"
            )
    for identifier in proposal.get("officialEvidenceIds", []):
        tokens.append(f"official={identifier}")
    claim = proposal.get("dependencyClaim")
    if isinstance(claim, dict):
        tokens.extend(
            [
                f"dep-ecosystem={claim.get('ecosystem', '')}",
                f"dep-package={claim.get('package', '')}",
                f"dep-version={claim.get('exactVersion', '')}",
                f"dep-question={claim.get('questionHash', '')}",
                f"dep-symbol={claim.get('nativeSymbol', '')}",
                f"dep-metadata={claim.get('metadataPath', '')}",
                f"dep-native={claim.get('nativePath', '')}",
            ]
        )
    request = parse_lease_request_tokens(tokens)
    outcome = request_write_lease(
        request=request,
        repo=repo,
        state_path=state_path,
        config_path=config_path,
        profile_path=profile_path,
        now=now,
        force_user_approval=True,
        expected_proposal_id=proposal_id,
    )
    if user_prompt_hash is not None:
        if _DIGEST.fullmatch(user_prompt_hash) is None:
            raise LifecycleError("user approval provenance hash is invalid")
        current = load_json_object(proposal_path(state_path))
        current["approvedByUserPromptHash"] = user_prompt_hash
        atomic_write_json(proposal_path(state_path), current)
    return outcome


def renew_write_lease(
    *,
    lease_id: str,
    repo: Path,
    state_path: Path,
    config_path: Path,
    profile_path: Path,
    now: datetime | None = None,
) -> LifecycleOutcome:
    """Revoke one current lease, then re-evaluate its proposal from scratch."""

    if _IDENTIFIER.fullmatch(lease_id) is None:
        raise LifecycleError("lease id is invalid")
    proposal = load_json_object(proposal_path(state_path))
    request = request_from_proposal(proposal)
    repo = repo.resolve(strict=True)
    validate_authoritative_state_path(state_path, repo)
    with state_lock(state_path):
        state_value = load_json_object(state_path)
        state = parse_gate_state(json.dumps(state_value))
        if (
            state.write_lease is None
            or state.write_lease.id != lease_id
            or proposal.get("leaseId") != lease_id
            or proposal.get("taskId") != state.task_id
        ):
            raise LifecycleError("renewal does not match the current lease")
        contract = load_json_object(contract_path(state_path))
        _validate_contract_identity(contract, state)
        phase = _contract_phase(contract)
        state_value.update(
            {
                "baseTreeHash": canonical_digest(
                    {
                        "acceptanceHash": state.acceptance_hash,
                        "phase": phase,
                        "projectId": state.project_id,
                        "renewedFrom": lease_id,
                        "taskId": state.task_id,
                    }
                ),
                "evidence": [],
                "phase": phase,
                "writeLease": None,
            }
        )
        parse_gate_state(json.dumps(state_value))
        atomic_write_json(state_path, state_value)
        _reset_lifecycle_sidecars(
            state_path,
            task_id=state.task_id,
            task_revision=contract["taskRevision"],
            revoked_lease_id=lease_id,
        )
    return request_write_lease(
        request=request,
        repo=repo,
        state_path=state_path,
        config_path=config_path,
        profile_path=profile_path,
        now=now,
    )


def request_from_proposal(proposal: dict[str, Any]) -> LeaseRequest:
    tokens = [f"acceptance={proposal.get('acceptanceHash', '')}"]
    tokens.extend(
        f"scope={item}" for item in proposal.get("allowedGlobs", [])
    )
    tokens.extend(
        f"verify={item}" for item in proposal.get("verificationIds", [])
    )
    for item in proposal.get("evidence", []):
        if (
            isinstance(item, dict)
            and item.get("kind") != "dependency-claim"
            and isinstance(item.get("sourcePath"), str)
            and not item["sourcePath"].startswith("@")
        ):
            tokens.append(
                f"evidence={item.get('kind', '')}:{item['sourcePath']}"
            )
    for identifier in proposal.get("officialEvidenceIds", []):
        tokens.append(f"official={identifier}")
    claim = proposal.get("dependencyClaim")
    if isinstance(claim, dict):
        tokens.extend(
            [
                f"dep-ecosystem={claim.get('ecosystem', '')}",
                f"dep-package={claim.get('package', '')}",
                f"dep-version={claim.get('exactVersion', '')}",
                f"dep-question={claim.get('questionHash', '')}",
                f"dep-symbol={claim.get('nativeSymbol', '')}",
                f"dep-metadata={claim.get('metadataPath', '')}",
                f"dep-native={claim.get('nativePath', '')}",
            ]
        )
    return parse_lease_request_tokens(tokens)


def record_verification_receipt(
    *,
    verification_id: str,
    repo: Path,
    state_path: Path,
    profile_path: Path,
    expected_implementation_hash: str,
    now: datetime | None = None,
) -> LifecycleOutcome:
    """Record one successful trusted verification against current output bytes."""

    if _IDENTIFIER.fullmatch(verification_id) is None:
        raise LifecycleError("verification id is invalid")
    if _DIGEST.fullmatch(expected_implementation_hash) is None:
        raise LifecycleError("verification input hash is invalid")
    current_time = now or datetime.now(timezone.utc)
    repo = repo.resolve(strict=True)
    validate_authoritative_state_path(state_path, repo)
    with state_lock(state_path):
        state_value = load_json_object(state_path)
        state = parse_gate_state(json.dumps(state_value))
        if Path(state.project_root) != repo or state.write_lease is None:
            raise LifecycleError("verification has no current Write Lease")
        drift = active_lease_attestation(
            state,
            now=current_time,
            state_path=state_path,
        )
        if drift is not None:
            raise LifecycleError(f"verification receipt denied: {drift}")
        profile = load_json_object(profile_path)
        commands = registered_verification_commands(
            state, profile, (verification_id,)
        )
        command = commands[0]
        if command not in state.write_lease.allowed_commands:
            raise LifecycleError(
                "verification id is not authorized by the current lease"
            )
        implementation_hash = observe_scope_tree(
            repo, state.write_lease.allowed_globs
        )
        if implementation_hash != expected_implementation_hash:
            raise LifecycleError(
                "live implementation changed after the verified snapshot was captured"
            )
        receipt_material = {
            "acceptanceHash": state.acceptance_hash,
            "baseTreeHash": state.base_tree_hash,
            "command": command,
            "implementationTreeHash": implementation_hash,
            "leaseId": state.write_lease.id,
            "taskId": state.task_id,
            "verificationId": verification_id,
        }
        receipt_id = (
            "VERIFY-"
            + canonical_digest(receipt_material).removeprefix("sha256:")[:20]
        )
        ledger = _load_receipts_for_lease(
            state_path, state.task_id, state.write_lease.id
        )
        receipts = [
            item
            for item in ledger["receipts"]
            if isinstance(item, dict)
            and item.get("verificationId") != verification_id
        ]
        receipts.append(
            {
                **receipt_material,
                "exitCode": 0,
                "receiptId": receipt_id,
                "recordedAt": current_time.isoformat(),
            }
        )
        proposal = load_json_object(proposal_path(state_path))
        required = proposal.get("verificationIds")
        if not isinstance(required, list):
            raise LifecycleError("lease proposal verification registry is invalid")
        receipt_by_id = {
            item.get("verificationId"): item
            for item in receipts
            if isinstance(item, dict)
        }
        all_current = bool(required) and all(
            identifier in receipt_by_id
            and receipt_by_id[identifier].get("implementationTreeHash")
            == implementation_hash
            for identifier in required
        )
        state_value["phase"] = "verifying" if all_current else "implementing"
        parse_gate_state(json.dumps(state_value))
        atomic_write_json(state_path, state_value)
        atomic_write_json(
            receipts_path(state_path),
            {
                "implementationTreeHash": implementation_hash,
                "leaseId": state.write_lease.id,
                "receipts": sorted(
                    receipts,
                    key=lambda item: str(item.get("verificationId", "")),
                ),
                "schemaVersion": 1,
                "taskId": state.task_id,
            },
        )
        return LifecycleOutcome(
            status="verification-recorded",
            task_id=state.task_id,
            lease_id=state.write_lease.id,
            receipt_id=receipt_id,
            phase=state_value["phase"],
        )


def complete_task(
    *,
    lease_id: str,
    repo: Path,
    state_path: Path,
    config_path: Path,
    profile_path: Path,
    now: datetime | None = None,
) -> LifecycleOutcome:
    """Close a Task only when all receipts attest the current implementation."""

    if _IDENTIFIER.fullmatch(lease_id) is None:
        raise LifecycleError("lease id is invalid")
    current_time = now or datetime.now(timezone.utc)
    repo = repo.resolve(strict=True)
    validate_authoritative_state_path(state_path, repo)
    with state_lock(state_path):
        state_value = load_json_object(state_path)
        state = parse_gate_state(json.dumps(state_value))
        if (
            state.write_lease is None
            or state.write_lease.id != lease_id
            or state.phase not in {"implementing", "verifying"}
        ):
            raise LifecycleError(
                "completion requires the current lease in an implementation phase"
            )
        drift = active_lease_attestation(
            state,
            now=current_time,
            state_path=state_path,
        )
        if drift is not None:
            raise LifecycleError(f"completion denied: {drift}")
        proposal = load_json_object(proposal_path(state_path))
        required = proposal.get("verificationIds")
        if not isinstance(required, list):
            raise LifecycleError("completion verification registry is invalid")
        if required and state.phase != "verifying":
            raise LifecycleError(
                "completion requires current receipts in verifying phase"
            )
        contract = load_json_object(contract_path(state_path))
        validate_verification_plan(
            contract=contract,
            config=load_json_object(config_path),
            profile=load_json_object(profile_path),
            selected_ids=tuple(required),
        )
        ledger = _load_receipts_for_lease(
            state_path, state.task_id, lease_id
        )
        implementation_hash = observe_scope_tree(
            repo, state.write_lease.allowed_globs
        )
        receipts = ledger["receipts"]
        receipt_by_id = {
            item.get("verificationId"): item
            for item in receipts
            if isinstance(item, dict)
        }
        if required and not all(
            identifier in receipt_by_id
            and receipt_by_id[identifier].get("exitCode") == 0
            and receipt_by_id[identifier].get("implementationTreeHash")
            == implementation_hash
            and receipt_by_id[identifier].get("leaseId") == lease_id
            for identifier in required
        ):
            raise LifecycleError(
                "completion receipts are missing or stale for current output"
            )
        if not required:
            pre_write_hash = proposal.get(
                "preWriteImplementationTreeHash"
            )
            if (
                not isinstance(pre_write_hash, str)
                or _DIGEST.fullmatch(pre_write_hash) is None
                or pre_write_hash == implementation_hash
            ):
                raise LifecycleError(
                    "completion without command receipts requires an observed "
                    "in-scope implementation change"
                )
        completion_material = {
            "acceptanceHash": state.acceptance_hash,
            "completedAt": current_time.isoformat(),
            "implementationTreeHash": implementation_hash,
            "leaseId": lease_id,
            "receiptSetHash": canonical_digest(receipts),
            "taskId": state.task_id,
        }
        completion_id = (
            "COMPLETE-"
            + canonical_digest(completion_material).removeprefix("sha256:")[:20]
        )
        atomic_write_json(
            completion_path(state_path),
            {
                **completion_material,
                "completionId": completion_id,
                "schemaVersion": 1,
            },
        )
        state_value["phase"] = "complete"
        state_value["writeLease"] = None
        parse_gate_state(json.dumps(state_value))
        atomic_write_json(state_path, state_value)
        proposal["completionId"] = completion_id
        proposal["status"] = "complete"
        atomic_write_json(proposal_path(state_path), proposal)
        return LifecycleOutcome(
            status="complete",
            task_id=state.task_id,
            receipt_id=completion_id,
            phase="complete",
        )


def _load_receipts_for_lease(
    state_path: Path, task_id: str, lease_id: str
) -> dict[str, Any]:
    ledger = load_json_object(receipts_path(state_path))
    receipts = ledger.get("receipts")
    if (
        ledger.get("schemaVersion") != 1
        or ledger.get("taskId") != task_id
        or ledger.get("leaseId") != lease_id
        or not isinstance(receipts, list)
    ):
        raise LifecycleError("verification receipt ledger is stale or invalid")
    return ledger


def active_lease_attestation(
    state: GateState,
    *,
    now: datetime | None = None,
    state_path: Path | None = None,
) -> str | None:
    """Return ``None`` only when actual Evidence and base observation still match."""

    lease = state.write_lease
    if lease is None:
        return "no active Write Lease"
    current_time = now or datetime.now(timezone.utc)
    if current_time < lease.issued_at or current_time >= lease.expires_at:
        return "Write Lease is outside its active time window"
    root = Path(state.project_root)
    try:
        actual_base = observe_outside_scope_tree(root, lease.allowed_globs)
    except (OSError, LifecycleError) as error:
        return f"base observation failed: {error}"
    if actual_base != state.base_tree_hash:
        return "Project HEAD or an outside-scope file changed"
    for item in state.evidence:
        if item.kind == "dependency-claim" and item.source_path.startswith(
            "@claim/"
        ):
            continue
        if item.kind == "official-doc" and item.source_path.startswith(
            "@official/"
        ):
            if state_path is None:
                return (
                    f"Evidence {item.id} requires host registry attestation"
                )
            identifier = item.source_path.removeprefix("@official/")
            try:
                registration = load_official_registration(
                    state_path, identifier
                )
                cached = official_evidence_body_path(
                    state_path, identifier
                )
                digest = digest_file(cached)
            except (OSError, LifecycleError) as error:
                return f"Evidence {item.id} cannot be attested: {error}"
            if (
                digest != item.content_hash
                or registration.get("contentHash") != item.content_hash
            ):
                return f"Evidence {item.id} content changed"
            continue
        if any(
            safe_glob_matches(scope, item.source_path)
            for scope in lease.allowed_globs
        ):
            # The pre-write Evidence remains in the host ledger, but an
            # authorized target is expected to change during implementation.
            continue
        try:
            path = safe_regular_project_file(root, item.source_path)
            digest = digest_file(path)
        except (OSError, LifecycleError) as error:
            return f"Evidence {item.id} cannot be attested: {error}"
        if digest != item.content_hash:
            return f"Evidence {item.id} content changed"
    return None


def observe_outside_scope_tree(
    root: Path, allowed_globs: Sequence[str]
) -> str:
    """Hash Git HEAD plus tracked/untracked non-ignored files outside scopes.

    A non-Git Project falls back to a bounded filesystem walk.  Files inside a
    lease scope are deliberately excluded so multiple authorized writes do not
    make the lease permanently stale.
    """

    root = root.resolve(strict=True)
    try:
        normalized_scopes = tuple(
            _validate_observable_scope(validate_safe_glob(item))
            for item in allowed_globs
        )
    except StateValidationError as error:
        raise LifecycleError("lease contains an unsafe scope") from error
    head, files = git_observation_files(root)
    if files is None:
        head = "non-git"
        files = filesystem_observation_files(root)
    payload = bytearray()
    payload.extend(b"engineering-harness-base-v1\0")
    payload.extend(head.encode("utf-8", "surrogateescape"))
    payload.extend(b"\0")
    total_bytes = 0
    observed = 0
    for relative in sorted(files):
        if any(safe_glob_matches(scope, relative) for scope in normalized_scopes):
            continue
        observed += 1
        if observed > MAX_OBSERVED_FILES:
            raise LifecycleError("base observation exceeds the file limit")
        path = root.joinpath(*PurePath(relative).parts)
        payload.extend(relative.encode("utf-8", "surrogateescape"))
        payload.extend(b"\0")
        try:
            metadata = path.lstat()
        except OSError:
            payload.extend(b"missing\n")
            continue
        payload.extend(f"{stat.S_IMODE(metadata.st_mode):o}".encode("ascii"))
        payload.extend(b"\0")
        if stat.S_ISLNK(metadata.st_mode):
            payload.extend(b"symlink\0")
            payload.extend(os.readlink(path).encode("utf-8", "surrogateescape"))
        elif stat.S_ISREG(metadata.st_mode):
            total_bytes += metadata.st_size
            if total_bytes > MAX_OBSERVED_BYTES:
                raise LifecycleError("base observation exceeds the byte limit")
            payload.extend(b"file\0")
            payload.extend(digest_file(path).encode("ascii"))
        else:
            payload.extend(b"other")
        payload.extend(b"\n")
    return sha256_digest(bytes(payload))


def observe_scope_tree(root: Path, allowed_globs: Sequence[str]) -> str:
    """Hash the concrete post-write implementation covered by a lease."""

    root = root.resolve(strict=True)
    try:
        normalized_scopes = tuple(
            _validate_observable_scope(validate_safe_glob(item))
            for item in allowed_globs
        )
    except StateValidationError as error:
        raise LifecycleError("lease contains an unsafe scope") from error
    _head, files = git_observation_files(root)
    if files is None:
        files = filesystem_observation_files(root)
    selected = sorted(
        relative
        for relative in files
        if any(
            safe_glob_matches(scope, relative)
            for scope in normalized_scopes
        )
    )
    payload = bytearray(b"engineering-harness-implementation-v1\0")
    total_bytes = 0
    for scope in sorted(normalized_scopes):
        payload.extend(b"scope\0")
        payload.extend(scope.encode("utf-8", "surrogateescape"))
        payload.extend(b"\n")
    for relative in selected:
        path = root.joinpath(*PurePath(relative).parts)
        metadata = path.lstat()
        payload.extend(relative.encode("utf-8", "surrogateescape"))
        payload.extend(b"\0")
        payload.extend(f"{stat.S_IMODE(metadata.st_mode):o}".encode("ascii"))
        payload.extend(b"\0")
        if stat.S_ISLNK(metadata.st_mode):
            payload.extend(b"symlink\0")
            payload.extend(os.readlink(path).encode("utf-8", "surrogateescape"))
        elif stat.S_ISREG(metadata.st_mode):
            total_bytes += metadata.st_size
            if total_bytes > MAX_OBSERVED_BYTES:
                raise LifecycleError(
                    "implementation observation exceeds the byte limit"
                )
            payload.extend(b"file\0")
            payload.extend(digest_file(path).encode("ascii"))
        else:
            payload.extend(b"other")
        payload.extend(b"\n")
    return sha256_digest(bytes(payload))


def git_observation_files(root: Path) -> tuple[str, list[str] | None]:
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "HOME": os.devnull,
        "PATH": os.environ.get("PATH", ""),
    }
    head_result = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        capture_output=True,
        check=False,
        env=environment,
    )
    files_result = subprocess.run(
        [
            "git",
            "--no-optional-locks",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        capture_output=True,
        check=False,
        env=environment,
    )
    if files_result.returncode != 0:
        return "non-git", None
    head = (
        head_result.stdout.strip().decode("ascii", "replace")
        if head_result.returncode == 0
        else "unborn"
    )
    paths: list[str] = []
    for raw in files_result.stdout.split(b"\0"):
        if not raw:
            continue
        rendered = raw.decode("utf-8", "surrogateescape").replace("\\", "/")
        try:
            relative = validate_relative_path(rendered)
        except LifecycleError as error:
            raise LifecycleError("Git reported an unsafe path") from error
        paths.append(relative)
    return f"git:{head}", paths


def filesystem_observation_files(root: Path) -> list[str]:
    files: list[str] = []
    for directory, names, filenames in os.walk(root, followlinks=False):
        base = Path(directory)
        names[:] = [
            name
            for name in sorted(names)
            if name not in _WALK_SKIP_DIRECTORIES
            and not (base / name).is_symlink()
        ]
        for name in sorted(filenames):
            candidate = base / name
            relative = candidate.relative_to(root).as_posix()
            files.append(validate_relative_path(relative))
    return files


def capture_evidence(
    root: Path,
    specs: Sequence[EvidenceSpec],
    *,
    state_path: Path,
    official_evidence_ids: Sequence[str],
) -> list[dict[str, str]]:
    evidence: list[dict[str, str]] = []
    for index, spec in enumerate(specs, start=1):
        path = safe_regular_project_file(root, spec.source_path)
        digest = digest_file(path)
        evidence.append(
            {
                "contentHash": digest,
                "id": f"EVIDENCE-{index:02d}-{digest.removeprefix('sha256:')[:8]}",
                "kind": spec.kind,
                "sourcePath": spec.source_path,
            }
        )
    for identifier in official_evidence_ids:
        registration = load_official_registration(state_path, identifier)
        body = official_evidence_body_path(state_path, identifier)
        content_hash = digest_file(body)
        if content_hash != registration.get("contentHash"):
            raise LifecycleError(
                f"official Evidence {identifier} cache content changed"
            )
        evidence.append(
            {
                "contentHash": content_hash,
                "id": f"OFFICIAL-{identifier}",
                "kind": "official-doc",
                "sourcePath": f"@official/{identifier}",
            }
        )
    return evidence


def safe_regular_project_file(root: Path, relative: str) -> Path:
    rendered = validate_relative_path(relative)
    path = root
    for part in PurePath(rendered).parts:
        path = path / part
        if path.is_symlink():
            raise LifecycleError("Evidence paths cannot contain symlinks")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        metadata = resolved.stat()
    except (OSError, ValueError) as error:
        raise LifecycleError("Evidence is missing or outside the Project") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise LifecycleError("Evidence must be a regular file")
    if metadata.st_size > MAX_EVIDENCE_BYTES:
        raise LifecycleError("Evidence file exceeds the size limit")
    parts = [part.lower() for part in PurePath(rendered).parts]
    if (
        any(part in _PROTECTED_SCOPE_PARTS for part in parts)
        or _is_secret_artifact_path(parts)
    ):
        raise LifecycleError("protected files cannot be Evidence")
    return resolved


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(128 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def register_official_evidence(
    *,
    registration: dict[str, str],
    repo: Path,
    state_path: Path,
    config_path: Path,
    now: datetime | None = None,
) -> LifecycleOutcome:
    """Fetch and register bounded HTTPS bytes from a user-allowlisted host."""

    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise LifecycleError("official Evidence clock must be timezone-aware")
    repo = repo.resolve(strict=True)
    validate_authoritative_state_path(state_path, repo)
    parsed = _validate_official_url(registration["url"])
    config = load_json_object(config_path)
    allowed_hosts = official_source_hosts(config)
    hostname = (parsed.hostname or "").casefold()
    if hostname not in allowed_hosts:
        raise LifecycleError(
            "official Evidence host is not explicitly allowlisted"
        )
    with state_lock(state_path):
        state = parse_gate_state(
            json.dumps(load_json_object(state_path))
        )
        contract = load_json_object(contract_path(state_path))
        _validate_contract_identity(contract, state)
        dependency = contract.get("dependency")
        if (
            contract.get("acceptanceStatus") != "accepted"
            or not isinstance(dependency, dict)
            or _normalized_package_name(registration["package"])
            != _normalized_package_name(
                str(dependency.get("package", ""))
            )
            or registration["question"] != dependency.get("questionHash")
        ):
            raise LifecycleError(
                "official Evidence is not bound to the accepted dependency question"
            )
        request = urllib.request.Request(
            registration["url"],
            headers={
                "Accept": "text/html,text/plain,application/json;q=0.9,*/*;q=0.1",
                "User-Agent": "setup-engineering-harness/1",
            },
            method="GET",
        )
        opener = urllib.request.build_opener(_NoRedirectHandler())
        try:
            with opener.open(request, timeout=15) as response:
                final = _validate_official_url(response.geturl())
                if (final.hostname or "").casefold() != hostname:
                    raise LifecycleError(
                        "official Evidence redirect changed the allowlisted host"
                    )
                content = response.read(MAX_OFFICIAL_EVIDENCE_BYTES + 1)
        except (
            OSError,
            urllib.error.HTTPError,
            urllib.error.URLError,
        ) as error:
            raise LifecycleError(
                "official Evidence fetch failed closed"
            ) from error
        if len(content) > MAX_OFFICIAL_EVIDENCE_BYTES:
            raise LifecycleError("official Evidence exceeds the byte limit")
        if not content:
            raise LifecycleError("official Evidence response is empty")
        try:
            content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise LifecycleError(
                "official Evidence must be UTF-8 text"
            ) from error
        content_hash = sha256_digest(content)
        material = {
            "contentHash": content_hash,
            "package": registration["package"],
            "questionHash": registration["question"],
            "url": registration["url"],
        }
        identifier = (
            "WEB-" + canonical_digest(material).removeprefix("sha256:")[:20]
        )
        _secure_official_evidence_directory(state_path)
        body_path = official_evidence_body_path(
            state_path, identifier, for_write=True
        )
        atomic_write_bytes(body_path, content)
        atomic_write_json(
            official_evidence_metadata_path(state_path, identifier),
            {
                **material,
                "accessedAt": current_time.isoformat(),
                "evidenceId": identifier,
                "schemaVersion": 1,
            },
        )
        return LifecycleOutcome(
            status="official-evidence-registered",
            task_id=state.task_id,
            receipt_id=identifier,
            phase=state.phase,
        )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _validate_official_url(value: str) -> urllib.parse.ParseResult:
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or any(character in value for character in "\0\n\r")
    ):
        raise LifecycleError("official Evidence URL is invalid")
    parsed = urllib.parse.urlparse(value)
    hostname = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or not hostname
        or _HOSTNAME.fullmatch(hostname) is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.fragment
        or not parsed.path
    ):
        raise LifecycleError(
            "official Evidence URL must be normalized public HTTPS"
        )
    return parsed


def official_source_hosts(config: dict[str, Any]) -> frozenset[str]:
    research = config.get("research")
    if not isinstance(research, dict):
        return frozenset()
    values = research.get("official_source_hosts")
    if not isinstance(values, list):
        return frozenset()
    hosts: set[str] = set()
    for value in values:
        if (
            not isinstance(value, str)
            or _HOSTNAME.fullmatch(value) is None
        ):
            raise LifecycleError(
                "research.official_source_hosts contains an invalid hostname"
            )
        hosts.add(value.casefold())
    return frozenset(hosts)


def official_evidence_directory(state_path: Path) -> Path:
    return state_path.parent / OFFICIAL_EVIDENCE_DIRECTORY


def _secure_official_evidence_directory(state_path: Path) -> Path:
    directory = official_evidence_directory(state_path)
    if directory.is_symlink():
        raise LifecycleError("official Evidence directory is unsafe")
    directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    if not directory.is_dir():
        raise LifecycleError("official Evidence directory is unavailable")
    os.chmod(directory, 0o700)
    return directory


def official_evidence_metadata_path(
    state_path: Path, identifier: str
) -> Path:
    if _IDENTIFIER.fullmatch(identifier) is None:
        raise LifecycleError("official Evidence id is invalid")
    directory = official_evidence_directory(state_path)
    if directory.is_symlink() or not directory.is_dir():
        raise LifecycleError("official Evidence directory is unsafe")
    return directory / f"{identifier}.json"


def official_evidence_body_path(
    state_path: Path,
    identifier: str,
    *,
    for_write: bool = False,
) -> Path:
    if _IDENTIFIER.fullmatch(identifier) is None:
        raise LifecycleError("official Evidence id is invalid")
    directory = official_evidence_directory(state_path)
    if directory.is_symlink() or not directory.is_dir():
        raise LifecycleError("official Evidence directory is unsafe")
    path = directory / f"{identifier}.bin"
    if not for_write and (path.is_symlink() or not path.is_file()):
        raise LifecycleError("official Evidence body is unavailable or unsafe")
    return path


def load_official_registration(
    state_path: Path, identifier: str
) -> dict[str, Any]:
    value = load_json_object(
        official_evidence_metadata_path(state_path, identifier)
    )
    if (
        value.get("schemaVersion") != 1
        or value.get("evidenceId") != identifier
        or _DIGEST.fullmatch(str(value.get("contentHash", ""))) is None
        or not _dependency_reference_is_safe(
            str(value.get("package", ""))
        )
        or _DIGEST.fullmatch(str(value.get("questionHash", ""))) is None
    ):
        raise LifecycleError("official Evidence registration is invalid")
    _validate_official_url(str(value.get("url", "")))
    return value


def load_verified_official_body(
    state_path: Path,
    identifier: str,
    registration: dict[str, Any] | None = None,
) -> bytes:
    metadata = registration or load_official_registration(
        state_path, identifier
    )
    path = official_evidence_body_path(state_path, identifier)
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        stat_result = os.fstat(descriptor)
        if (
            not stat.S_ISREG(stat_result.st_mode)
            or stat_result.st_size > MAX_OFFICIAL_EVIDENCE_BYTES
        ):
            raise LifecycleError(
                "official Evidence body is unavailable or oversized"
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            content = handle.read(MAX_OFFICIAL_EVIDENCE_BYTES + 1)
    except LifecycleError:
        raise
    except OSError as error:
        raise LifecycleError(
            "official Evidence body is unavailable or unsafe"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        len(content) > MAX_OFFICIAL_EVIDENCE_BYTES
        or sha256_digest(content) != metadata.get("contentHash")
    ):
        raise LifecycleError(
            "official Evidence body does not match its stored receipt"
        )
    return content


def read_official_evidence(
    *,
    identifier: str,
    start: int,
    lines: int,
    repo: Path,
    state_path: Path,
) -> tuple[dict[str, Any], ...]:
    registration, text = _load_bound_official_text(
        identifier=identifier,
        repo=repo,
        state_path=state_path,
    )
    all_lines = text.splitlines()
    selected = list(
        enumerate(
            all_lines[start - 1 : start - 1 + lines],
            start=start,
        )
    )
    return _bounded_official_records(
        registration=registration,
        operation="official-read",
        selected=selected,
        requested={"lines": lines, "start": start},
    )


def search_official_evidence(
    *,
    identifier: str,
    pattern: str,
    limit: int,
    repo: Path,
    state_path: Path,
) -> tuple[dict[str, Any], ...]:
    registration, text = _load_bound_official_text(
        identifier=identifier,
        repo=repo,
        state_path=state_path,
    )
    selected: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if pattern in line:
            selected.append((number, line))
            if len(selected) >= limit:
                break
    return _bounded_official_records(
        registration=registration,
        operation="official-search",
        selected=selected,
        requested={"limit": limit, "pattern": pattern},
    )


def _load_bound_official_text(
    *,
    identifier: str,
    repo: Path,
    state_path: Path,
) -> tuple[dict[str, Any], str]:
    repo = repo.resolve(strict=True)
    validate_authoritative_state_path(state_path, repo)
    with state_lock(state_path):
        state = parse_gate_state(
            json.dumps(load_json_object(state_path))
        )
        contract = load_json_object(contract_path(state_path))
        _validate_contract_identity(contract, state)
        registration = load_official_registration(
            state_path, identifier
        )
        _validate_official_registration_binding(
            registration, contract
        )
        content = load_verified_official_body(
            state_path, identifier, registration
        )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise LifecycleError(
            "official Evidence body is not UTF-8 text"
        ) from error
    return registration, text


def _validate_official_registration_binding(
    registration: dict[str, Any],
    contract: dict[str, Any],
) -> None:
    dependency = contract.get("dependency")
    if (
        contract.get("acceptanceStatus") != "accepted"
        or not isinstance(dependency, dict)
        or _normalized_package_name(
            str(registration.get("package", ""))
        )
        != _normalized_package_name(
            str(dependency.get("package", ""))
        )
        or registration.get("questionHash")
        != dependency.get("questionHash")
    ):
        raise LifecycleError(
            "official Evidence is not bound to the current dependency question"
        )


def _bounded_official_records(
    *,
    registration: dict[str, Any],
    operation: str,
    selected: Sequence[tuple[int, str]],
    requested: dict[str, Any],
) -> tuple[dict[str, Any], ...]:
    common = {
        "bodySha256": registration["contentHash"],
        "evidenceId": registration["evidenceId"],
    }
    header = {
        **common,
        "operation": operation,
        "package": registration["package"],
        "record": "official-evidence-begin",
        "request": requested,
        "sourceUrl": registration["url"],
        "trust": "untrusted-external-text",
    }
    records: list[dict[str, Any]] = [header]
    emitted = 0
    used = len(_json_line(header))
    for number, line in selected:
        record = {
            **common,
            "line": number,
            "record": "official-evidence-text",
            "text": line[:4000],
            "trust": "untrusted-external-text",
        }
        footer_reserve = 512
        encoded = _json_line(record)
        if used + len(encoded) + footer_reserve > MAX_OFFICIAL_OUTPUT_BYTES:
            break
        records.append(record)
        used += len(encoded)
        emitted += 1
    footer = {
        **common,
        "emittedRecords": emitted,
        "record": "official-evidence-end",
        "truncated": emitted < len(selected),
        "trust": "untrusted-external-text",
    }
    records.append(footer)
    if sum(len(_json_line(record)) for record in records) > MAX_OFFICIAL_OUTPUT_BYTES:
        raise LifecycleError("official Evidence framing exceeds output limit")
    return tuple(records)


def _json_line(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n"
    ).encode("utf-8")


def lifecycle_protocol_description() -> dict[str, Any]:
    """Return the exact agent-callable request vocabulary."""

    return {
        "dependencyClaimTokens": [
            "dep-ecosystem=<go|npm|python|rust>",
            "dep-package=<installed-name>",
            "dep-version=<exact-version>",
            "dep-question=sha256:<accepted-question-hash>",
            "dep-symbol=<public-symbol>",
            "dep-metadata=<installed-metadata-path>",
            "dep-native=<docs-types-or-source-path>",
        ],
        "dependencyEcosystems": sorted(_SUPPORTED_DEPENDENCY_ECOSYSTEMS),
        "evidenceKinds": sorted(_EVIDENCE_KINDS),
        "exampleDependencyRequestTokens": [
            "acceptance=sha256:<acceptance-hash>",
            "scope=src/example.js",
            "verify=test",
            "evidence=manifest:package.json",
            "evidence=lockfile:package-lock.json",
            (
                "evidence=installed-metadata:"
                "node_modules/example/package.json"
            ),
            (
                "evidence=type-definition:"
                "node_modules/example/index.d.ts"
            ),
            "dep-ecosystem=npm",
            "dep-package=example",
            "dep-version=1.2.3",
            "dep-question=sha256:<accepted-question-hash>",
            "dep-symbol=nativeOption",
            "dep-metadata=node_modules/example/package.json",
            "dep-native=node_modules/example/index.d.ts",
        ],
        "nativeCapabilityEvidenceKinds": sorted(
            _NATIVE_CAPABILITY_KINDS
        ),
        "operation": "request",
        "requestTokens": [
            "acceptance=sha256:<acceptance-hash>",
            "scope=<project-relative-safe-glob>",
            "verify=<repo-profile-verification-id>",
            "evidence=<kind>:<regular-project-file>",
            "official=<registered-official-evidence-id>",
        ],
        "schemaVersion": 1,
    }


def validate_dependency_evidence(
    evidence: Sequence[dict[str, str]],
    root: Path,
    *,
    contract: dict[str, Any],
    claim: DependencyClaim | None,
    state_path: Path,
    official_evidence_ids: Sequence[str],
) -> dict[str, Any]:
    if claim is None:
        raise LifecycleError(
            "dependency research requires a package/version/question/symbol claim"
        )
    dependency = contract.get("dependency")
    if (
        not isinstance(dependency, dict)
        or claim.ecosystem not in _SUPPORTED_DEPENDENCY_ECOSYSTEMS
        or not _same_package_name(
            claim.ecosystem,
            claim.package,
            str(dependency.get("package", "")),
        )
        or claim.question_hash != dependency.get("questionHash")
    ):
        raise LifecycleError(
            "dependency claim is not bound to the accepted package and question"
        )
    named = [(item["kind"], PurePath(item["sourcePath"]).name) for item in evidence]
    ecosystem_manifests = _ECOSYSTEM_MANIFESTS[claim.ecosystem]
    ecosystem_lockfiles = _ECOSYSTEM_LOCKFILES[claim.ecosystem]
    manifest_or_lock = any(
        (kind == "manifest" and name in ecosystem_manifests)
        or (kind == "lockfile" and name in ecosystem_lockfiles)
        for kind, name in named
    )
    if not manifest_or_lock:
        raise LifecycleError(
            "dependency research requires manifest or lockfile Evidence"
        )
    metadata_evidence = next(
        (
            item
            for item in evidence
            if item["kind"] == "installed-metadata"
            and item["sourcePath"] == claim.metadata_path
        ),
        None,
    )
    if metadata_evidence is None:
        raise LifecycleError(
            "dependency claim metadata path is not bound Evidence"
        )
    metadata_path = safe_regular_project_file(root, claim.metadata_path)
    installed_identity = _installed_package_identity(metadata_path)
    if (
        installed_identity is None
        or installed_identity.ecosystem != claim.ecosystem
        or not _same_package_name(
            claim.ecosystem,
            installed_identity.package,
            claim.package,
        )
        or installed_identity.exact_version != claim.exact_version
    ):
        raise LifecycleError(
            "dependency claim does not match exact installed package metadata"
        )
    native_evidence = next(
        (
            item
            for item in evidence
            if item["sourcePath"] == claim.native_path
            and item["kind"] in _NATIVE_CAPABILITY_KINDS
            and is_native_capability_evidence(item)
        ),
        None,
    )
    if native_evidence is None:
        raise LifecycleError(
            "dependency native symbol source is not bound; bind dep-native "
            "with evidence=official-doc:<path>, "
            "evidence=type-definition:<path>, or "
            "evidence=source-code:<path>"
        )
    native_path = safe_regular_project_file(root, claim.native_path)
    if not _same_installed_package(
        metadata_path,
        native_path,
        package=claim.package,
        ecosystem=claim.ecosystem,
    ):
        raise LifecycleError(
            "dependency metadata and native capability are from different packages"
        )
    try:
        native_content = native_path.read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError as error:
        raise LifecycleError("dependency native Evidence is unreadable") from error
    if claim.native_symbol not in native_content:
        raise LifecycleError(
            "dependency native symbol is absent from the bound Evidence"
        )
    for identifier in official_evidence_ids:
        registration = load_official_registration(state_path, identifier)
        load_verified_official_body(
            state_path, identifier, registration
        )
        if (
            not _same_package_name(
                claim.ecosystem,
                str(registration.get("package", "")),
                claim.package,
            )
            or registration.get("questionHash") != claim.question_hash
        ):
            raise LifecycleError(
                "official Evidence is not bound to the dependency package/question"
            )
    return {
        "ecosystem": claim.ecosystem,
        "exactVersion": claim.exact_version,
        "metadataPath": claim.metadata_path,
        "nativePath": claim.native_path,
        "nativeSymbol": claim.native_symbol,
        "officialEvidenceIds": list(official_evidence_ids),
        "package": claim.package,
        "questionHash": claim.question_hash,
    }


def _contains_adjacent_parts(
    parts: Sequence[str], expected: tuple[str, ...]
) -> bool:
    width = len(expected)
    return any(
        tuple(parts[index : index + width]) == expected
        for index in range(len(parts) - width + 1)
    )


def is_native_capability_evidence(item: dict[str, str]) -> bool:
    path = PurePath(item["sourcePath"])
    lowered_parts = [part.lower() for part in path.parts]
    if not any(
        part
        in {
            "node_modules",
            "site-packages",
            "dist-packages",
            "vendor",
        }
        for part in lowered_parts
    ) and not any(
        _contains_adjacent_parts(lowered_parts, marker)
        for marker in (("pkg", "mod"), ("registry", "src"))
    ):
        return False
    name = path.name
    kind = item["kind"]
    if kind == "type-definition":
        return name.endswith((".d.ts", ".pyi"))
    if kind == "official-doc":
        return name.lower() in {
            "readme",
            "readme.md",
            "changelog",
            "changelog.md",
        }
    return kind == "source-code" and name.endswith(
        (".js", ".mjs", ".cjs", ".ts", ".py", ".rs", ".go")
    )


def _node_modules_package_root(path: Path) -> Path | None:
    indexes = [
        index for index, part in enumerate(path.parts) if part == "node_modules"
    ]
    if not indexes:
        return None
    index = indexes[-1]
    end = index + 2
    if end > len(path.parts):
        return None
    if path.parts[index + 1].startswith("@"):
        end += 1
    if end > len(path.parts):
        return None
    package_root = Path(*path.parts[:end])
    if path != package_root / "package.json":
        return None
    return package_root


def _python_site_root(path: Path) -> Path | None:
    for index, part in enumerate(path.parts):
        if part in {"site-packages", "dist-packages"}:
            return Path(*path.parts[: index + 1])
    return None


def _go_module_cache_root(path: Path) -> tuple[Path, str] | None:
    lowered = [part.lower() for part in path.parts]
    indexes = [
        index
        for index in range(len(lowered) - 1)
        if tuple(lowered[index : index + 2]) == ("pkg", "mod")
    ]
    if not indexes or path.name != "go.mod":
        return None
    package_root = path.parent
    leaf = package_root.name
    if "@" not in leaf:
        return None
    _encoded_name, version = leaf.rsplit("@", 1)
    if (
        not version.startswith("v")
        or _EXACT_VERSION.fullmatch(version) is None
    ):
        return None
    if indexes[-1] + 2 >= len(package_root.parts):
        return None
    return package_root, version


def _is_rust_dependency_manifest(path: Path) -> bool:
    if path.name != "Cargo.toml":
        return False
    lowered = [part.lower() for part in path.parts]
    return "vendor" in lowered or _contains_adjacent_parts(
        lowered, ("registry", "src")
    )


def _installed_package_identity(
    path: Path,
) -> InstalledPackageIdentity | None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    if path.name == "package.json":
        package_root = _node_modules_package_root(path)
        if package_root is None:
            return None
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(value, dict):
            return None
        name = value.get("name")
        version = value.get("version")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not _package_name_is_valid("npm", name)
            or _EXACT_VERSION.fullmatch(version) is None
        ):
            return None
        return InstalledPackageIdentity("npm", name, version, package_root)
    if path.name in {"METADATA", "PKG-INFO"}:
        expected_suffix = (
            ".dist-info" if path.name == "METADATA" else ".egg-info"
        )
        site_root = _python_site_root(path)
        if (
            site_root is None
            or not path.parent.name.endswith(expected_suffix)
        ):
            return None
        name: str | None = None
        version: str | None = None
        for line in text.splitlines():
            if line.startswith("Name: "):
                candidate = line.removeprefix("Name: ").strip()
                if _package_name_is_valid("python", candidate):
                    name = candidate
            if line.startswith("Version: "):
                candidate = line.removeprefix("Version: ").strip()
                if _EXACT_VERSION.fullmatch(candidate) is not None:
                    version = candidate
        if name is None or version is None:
            return None
        return InstalledPackageIdentity("python", name, version, site_root)
    go_root = _go_module_cache_root(path)
    if go_root is not None:
        package_root, version = go_root
        module_name: str | None = None
        for line in text.splitlines():
            match = re.fullmatch(r"\s*module\s+(\S+)\s*", line)
            if match is not None:
                module_name = match.group(1)
                break
        if (
            module_name is None
            or not _package_name_is_valid("go", module_name)
        ):
            return None
        return InstalledPackageIdentity(
            "go", module_name, version, package_root
        )
    if _is_rust_dependency_manifest(path):
        try:
            value = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return None
        package = value.get("package")
        if not isinstance(package, dict):
            return None
        name = package.get("name")
        version = package.get("version")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not _package_name_is_valid("rust", name)
            or _EXACT_VERSION.fullmatch(version) is None
        ):
            return None
        return InstalledPackageIdentity("rust", name, version, path.parent)
    return None


def installed_package_identity(
    path: Path,
) -> tuple[str | None, str | None]:
    identity = _installed_package_identity(path)
    if identity is None:
        return None, None
    return identity.package, identity.exact_version


def has_exact_installed_version(path: Path) -> bool:
    name, version = installed_package_identity(path)
    return name is not None and version is not None


def _normalized_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _same_installed_package(
    metadata_path: Path,
    native_path: Path,
    *,
    package: str,
    ecosystem: str,
) -> bool:
    identity = _installed_package_identity(metadata_path)
    if (
        identity is None
        or identity.ecosystem != ecosystem
        or not _same_package_name(ecosystem, identity.package, package)
    ):
        return False
    if ecosystem in {"go", "npm", "rust"}:
        return (
            native_path == identity.package_root
            or identity.package_root in native_path.parents
        )
    metadata_parts = list(metadata_path.parts)
    try:
        site_index = next(
            index
            for index, part in enumerate(metadata_parts)
            if part in {"site-packages", "dist-packages"}
        )
    except StopIteration:
        return False
    site_root = Path(*metadata_parts[: site_index + 1])
    try:
        relative = native_path.relative_to(site_root)
    except ValueError:
        return False
    if not relative.parts:
        return False
    top_level = relative.parts[0]
    return _normalized_package_name(top_level) in {
        _normalized_package_name(package),
        _normalized_package_name(package).replace("-", "_"),
    }


def registered_verification_commands(
    state: GateState,
    profile: dict[str, Any],
    requested_ids: Sequence[str],
) -> tuple[str, ...]:
    registry = verification_registry(profile)
    registered = set(registry)
    unknown = set(requested_ids) - registered
    if unknown:
        raise LifecycleError(
            f"verification ids are not registered: {sorted(unknown)}"
        )
    executable = state.read_broker_python_executables[0]
    broker = state.project_root.joinpath(VERIFICATION_BROKER_RELATIVE_PATH)
    return tuple(
        shlex.join([str(executable), str(broker), "run", identifier])
        for identifier in requested_ids
    )


def verification_registry(
    profile: dict[str, Any],
) -> dict[str, dict[str, str]]:
    candidates = profile.get("candidate_commands")
    if not isinstance(candidates, list):
        raise LifecycleError("verification registry is malformed")
    registry: dict[str, dict[str, str]] = {}
    for item in candidates:
        if not isinstance(item, dict):
            raise LifecycleError("verification registry entry is malformed")
        identifier = item.get("id")
        command = item.get("command")
        kind = item.get("kind")
        if (
            not isinstance(identifier, str)
            or _IDENTIFIER.fullmatch(identifier) is None
            or not isinstance(command, str)
            or not command
            or not isinstance(kind, str)
            or _IDENTIFIER.fullmatch(kind) is None
            or item.get("executed") is not False
            or identifier in registry
        ):
            raise LifecycleError("verification registry entry is invalid")
        registry[identifier] = {"command": command, "kind": kind.casefold()}
    return registry


_CRITERION_COMMAND_KINDS = (
    (
        "test",
        re.compile(
            r"\b(test|tests|testing|spec|specs|assert|assertion)\b|"
            r"(테스트|단위\s*검사|통합\s*검사)",
            re.IGNORECASE,
        ),
    ),
    (
        "build",
        re.compile(r"\b(build|compile|bundle)\w*\b|(빌드|컴파일)", re.IGNORECASE),
    ),
    (
        "typecheck",
        re.compile(
            r"\b(typecheck|type-check|types?)\w*\b|(타입.?체크|타입\s*검사)",
            re.IGNORECASE,
        ),
    ),
    (
        "lint",
        re.compile(r"\b(lint|linter)\w*\b|(린트)", re.IGNORECASE),
    ),
    (
        "format",
        re.compile(r"\b(format|formatting)\w*\b|(포맷)", re.IGNORECASE),
    ),
)
_CRITERION_UI_SIGNAL = re.compile(
    r"\b(browser|playwright|viewport|screen|focus|console|network|"
    r"hydration|user interaction|ui flow)\b|"
    r"(브라우저|화면|뷰포트|포커스|콘솔|네트워크|사용자\s*상호작용)",
    re.IGNORECASE,
)
_CRITERION_PERFORMANCE_SIGNAL = re.compile(
    r"\b(performance|benchmark|latency|throughput|render count|"
    r"memory usage|cpu usage)\b|"
    r"(성능|벤치마크|지연시간|처리량|렌더\s*횟수|메모리\s*사용량)",
    re.IGNORECASE,
)


def _configured_verification_ids(
    *,
    verification: dict[str, Any],
    field: str,
    registry: dict[str, dict[str, str]],
) -> list[str]:
    values = verification.get(field)
    if not isinstance(values, list) or not all(
        isinstance(item, str) and _IDENTIFIER.fullmatch(item) is not None
        for item in values
    ):
        raise LifecycleError(f"verification.{field} is malformed")
    if len(set(values)) != len(values):
        raise LifecycleError(f"verification.{field} must be unique")
    unknown = set(values) - set(registry)
    if unknown:
        raise LifecycleError(
            f"verification.{field} are not registered: {sorted(unknown)}"
        )
    return sorted(values)


def _unrun_decision_id(material: dict[str, Any]) -> str:
    return (
        "DECISION-unrun-"
        + canonical_digest(material).removeprefix("sha256:")[:16]
    )


def _user_decision_evidence(
    decision_id: str,
    unrun_decisions: dict[str, dict[str, str]],
) -> dict[str, str] | None:
    answer = unrun_decisions.get(decision_id)
    if answer is None:
        return None
    return {
        "decisionId": decision_id,
        "provenanceHash": answer["provenanceHash"],
        "reason": answer["reason"],
        "reasonHash": sha256_digest(answer["reason"].encode("utf-8")),
        "type": "user-decision",
    }


def build_verification_plan(
    *,
    criteria: Sequence[str],
    risk: str,
    config: dict[str, Any],
    profile: dict[str, Any],
    unrun_decisions: dict[str, dict[str, str]],
) -> dict[str, Any]:
    """Bind acceptance claims to host-detected checks and user-owned policy."""

    registry = verification_registry(profile)
    verification = config.get("verification")
    if not isinstance(verification, dict):
        raise LifecycleError("verification configuration is malformed")
    configured = _configured_verification_ids(
        verification=verification,
        field="required_commands",
        registry=registry,
    )
    ui_flows = _configured_verification_ids(
        verification=verification,
        field="ui_flows",
        registry=registry,
    )
    performance_scenarios = _configured_verification_ids(
        verification=verification,
        field="performance_scenarios",
        registry=registry,
    )

    criterion_plans: list[dict[str, Any]] = []
    criterion_required: set[str] = set()
    pending_decisions: set[str] = set()
    for index, statement in enumerate(criteria):
        kinds = {
            kind
            for kind, signal in _CRITERION_COMMAND_KINDS
            if signal.search(statement)
        }
        command_ids = sorted(
            identifier
            for identifier, entry in registry.items()
            if entry["kind"] in kinds
        )
        criterion_id = (
            "CRITERION-"
            + canonical_digest(
                {"index": index, "statement": statement}
            ).removeprefix("sha256:")[:16]
        )
        evidence = [
            {"type": "command", "verificationId": identifier}
            for identifier in command_ids
        ]
        criterion_required.update(command_ids)
        missing_dimensions: list[str] = []
        if _CRITERION_UI_SIGNAL.search(statement):
            if ui_flows:
                evidence.extend(
                    {
                        "type": "interaction",
                        "verificationId": identifier,
                    }
                    for identifier in ui_flows
                )
                criterion_required.update(ui_flows)
            else:
                missing_dimensions.append("ui-flow")
        if _CRITERION_PERFORMANCE_SIGNAL.search(statement):
            if performance_scenarios:
                evidence.extend(
                    {
                        "type": "interaction",
                        "verificationId": identifier,
                    }
                    for identifier in performance_scenarios
                )
                criterion_required.update(performance_scenarios)
            else:
                missing_dimensions.append("performance-scenario")
        if not evidence or missing_dimensions:
            decision_id = _unrun_decision_id(
                {
                    "criterionId": criterion_id,
                    "missingDimensions": missing_dimensions or ["semantic-proof"],
                }
            )
            user_evidence = _user_decision_evidence(
                decision_id, unrun_decisions
            )
            if user_evidence is None:
                pending_decisions.add(decision_id)
            else:
                evidence.append(user_evidence)
        criterion_plans.append(
            {
                "criterionId": criterion_id,
                "evidence": evidence,
                "unrunDecisionId": (
                    decision_id
                    if not command_ids or missing_dimensions
                    else None
                ),
                "statementHash": sha256_digest(statement.encode("utf-8")),
            }
        )

    risk_required: set[str] = set()
    risk_evidence: list[dict[str, str]] = []
    if risk == "material":
        risk_required.update(
            identifier
            for identifier, entry in registry.items()
            if entry["kind"] == "test"
        )
    elif risk == "high":
        risk_required.update(registry)
    elif risk != "low":
        raise LifecycleError("task risk classification is invalid")
    if risk in {"material", "high"} and not risk_required:
        risk_decision_id = _unrun_decision_id(
            {
                "profileHash": canonical_digest(profile),
                "risk": risk,
                "type": "risk-proof",
            }
        )
        risk_user_evidence = _user_decision_evidence(
            risk_decision_id, unrun_decisions
        )
        if risk_user_evidence is None:
            pending_decisions.add(risk_decision_id)
        else:
            risk_evidence.append(risk_user_evidence)
    required = criterion_required | set(configured) | risk_required
    return {
        "configRequiredVerificationIds": sorted(configured),
        "criteria": criterion_plans,
        "pendingDecisionIds": sorted(pending_decisions),
        "profileHash": canonical_digest(profile),
        "requiredVerificationIds": sorted(required),
        "risk": risk,
        "riskEvidence": risk_evidence,
        "riskRequiredVerificationIds": sorted(risk_required),
        "schemaVersion": 1,
        "verificationConfigHash": canonical_digest(verification),
    }


def validate_verification_plan(
    *,
    contract: dict[str, Any],
    config: dict[str, Any],
    profile: dict[str, Any],
    selected_ids: Sequence[str],
) -> None:
    acceptance = contract.get("acceptance")
    if not isinstance(acceptance, dict):
        raise LifecycleError("verification plan has no accepted contract")
    criteria = acceptance.get("observableCriteria")
    if not isinstance(criteria, list) or not all(
        isinstance(item, str) for item in criteria
    ):
        raise LifecycleError("verification plan criteria are invalid")
    expected = build_verification_plan(
        criteria=criteria,
        risk=str(contract.get("risk", "")),
        config=config,
        profile=profile,
        unrun_decisions=_validated_unrun_decisions(contract),
    )
    if expected["pendingDecisionIds"]:
        raise LifecycleError(
            "host verification plan has unresolved Evidence decisions"
        )
    if contract.get("verificationPlan") != expected:
        raise LifecycleError(
            "host verification plan is stale; acceptance must be renewed"
        )
    required = expected["requiredVerificationIds"]
    missing = set(required) - set(selected_ids)
    if missing:
        raise LifecycleError(
            "host verification plan requires verification ids: "
            f"{sorted(missing)}"
        )


def validate_contract(
    contract: dict[str, Any], state: GateState, request: LeaseRequest
) -> None:
    _validate_contract_identity(contract, state)
    acceptance = contract.get("acceptance")
    if (
        request.acceptance_hash != state.acceptance_hash
        or contract.get("acceptanceStatus") != "accepted"
        or not isinstance(acceptance, dict)
        or not isinstance(acceptance.get("outcome"), str)
        or not isinstance(acceptance.get("observableCriteria"), list)
        or not isinstance(acceptance.get("exclusions"), list)
        or not isinstance(acceptance.get("assumptions"), list)
    ):
        raise LifecycleError(
            "a complete structured acceptance contract is required"
        )


def gate_configuration(config: dict[str, Any]) -> tuple[int, int, bool]:
    gate = config.get("write_gate")
    if not isinstance(gate, dict):
        gate = {}
    auto = gate.get("auto_approve_reversible_lite") is True
    maximum = gate.get("max_auto_scope_globs", MAX_AUTO_SCOPE_GLOBS)
    minutes = gate.get("lease_minutes", 30)
    if type(maximum) is not int or not 1 <= maximum <= 16:
        raise LifecycleError("write_gate.max_auto_scope_globs must be 1..16")
    if type(minutes) is not int or not 5 <= minutes <= 60:
        raise LifecycleError("write_gate.lease_minutes must be 5..60")
    return maximum, minutes, auto


def task_context_from_state(
    state: dict[str, Any], *, preserved: bool
) -> dict[str, Any]:
    return {
        "acceptanceHash": state.get("acceptanceHash"),
        "dependencyResearchRequired": state.get("phase") == "research-required",
        "pendingDecisions": state.get("pendingDecisions", []),
        "phase": state.get("phase", "unavailable"),
        "preserved": preserved,
        "taskId": state.get("taskId", "unavailable"),
    }


def contract_path(state_path: Path) -> Path:
    return state_path.parent / CONTRACT_FILENAME


def proposal_path(state_path: Path) -> Path:
    return state_path.parent / PROPOSAL_FILENAME


def receipts_path(state_path: Path) -> Path:
    return state_path.parent / RECEIPTS_FILENAME


def completion_path(state_path: Path) -> Path:
    return state_path.parent / COMPLETION_FILENAME


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise OSError("path is not a safe regular file")
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LifecycleError(f"{path.name} is unavailable or invalid") from error
    if not isinstance(value, dict):
        raise LifecycleError(f"{path.name} must contain an object")
    return value


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    content = (
        json.dumps(value, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    atomic_write_bytes(path, content)


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise LifecycleError("authoritative output path is unsafe")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".engineering-harness-", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


@contextmanager
def state_lock(state_path: Path) -> Iterator[None]:
    lock_path = state_path.parent / LOCK_FILENAME
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise LifecycleError("state lock is not a regular file")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def validate_authoritative_state_path(state_path: Path, repo: Path) -> None:
    if not state_path.is_absolute() or state_path.is_symlink():
        raise LifecycleError("authoritative state path is unsafe")
    try:
        state_path.parent.resolve(strict=True).relative_to(repo)
    except ValueError:
        pass
    except OSError as error:
        raise LifecycleError("authoritative state directory is unavailable") from error
    else:
        raise LifecycleError("authoritative state must be outside the Project")
    if not state_path.is_file():
        raise LifecycleError("authoritative state is missing or not regular")


def lifecycle_main(
    argv: Sequence[str],
    *,
    repo: Path,
    state_path: Path,
    config_path: Path,
    profile_path: Path,
) -> int:
    parser = argparse.ArgumentParser(description="Engineering Harness lease broker")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    request_protocol = lifecycle_protocol_description()
    request_parser = subparsers.add_parser(
        "request",
        description=(
            "Request one scoped Write Lease using canonical key=value tokens."
        ),
        epilog=(
            "Evidence kinds: "
            + ", ".join(request_protocol["evidenceKinds"])
            + "\nNative capability kinds: "
            + ", ".join(
                request_protocol["nativeCapabilityEvidenceKinds"]
            )
            + "\nDependency example:\n  "
            + "\n  ".join(
                request_protocol["exampleDependencyRequestTokens"]
            )
            + "\nRun the protected `describe` operation for machine-readable JSON."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    request_parser.add_argument(
        "tokens",
        nargs="+",
        metavar="TOKEN",
        help=(
            "acceptance=…, scope=…, optional verify=…, and one or more "
            "evidence=<kind>:<path> tokens"
        ),
    )
    subparsers.add_parser(
        "describe",
        help="Print the exact request token vocabulary as JSON.",
    )
    acceptance_parser = subparsers.add_parser("set-acceptance")
    acceptance_parser.add_argument("tokens", nargs="+")
    official_parser = subparsers.add_parser("register-official")
    official_parser.add_argument("tokens", nargs="+")
    official_read_parser = subparsers.add_parser("official-read")
    official_read_parser.add_argument("identifier")
    official_read_parser.add_argument("--start", type=int, default=1)
    official_read_parser.add_argument("--lines", type=int, default=200)
    official_search_parser = subparsers.add_parser("official-search")
    official_search_parser.add_argument("identifier")
    official_search_parser.add_argument("pattern")
    official_search_parser.add_argument("--limit", type=int, default=50)
    approve_parser = subparsers.add_parser("approve")
    approve_parser.add_argument("proposal_id")
    renew_parser = subparsers.add_parser("renew")
    renew_parser.add_argument("lease_id")
    complete_parser = subparsers.add_parser("complete")
    complete_parser.add_argument("lease_id")
    args = parser.parse_args(list(argv))
    try:
        if args.operation == "describe":
            print(
                json.dumps(
                    lifecycle_protocol_description(), sort_keys=True
                )
            )
            return 0
        if args.operation == "request":
            outcome = request_write_lease(
                request=parse_lease_request_tokens(args.tokens),
                repo=repo,
                state_path=state_path,
                config_path=config_path,
                profile_path=profile_path,
            )
        elif args.operation == "set-acceptance":
            outcome = set_acceptance_contract(
                acceptance=parse_acceptance_tokens(args.tokens),
                repo=repo,
                state_path=state_path,
                config_path=config_path,
                profile_path=profile_path,
            )
        elif args.operation == "register-official":
            outcome = register_official_evidence(
                registration=parse_official_registration_tokens(
                    args.tokens
                ),
                repo=repo,
                state_path=state_path,
                config_path=config_path,
            )
        elif args.operation == "official-read":
            identifier, start, lines = parse_official_read_tokens(
                [
                    args.identifier,
                    "--start",
                    str(args.start),
                    "--lines",
                    str(args.lines),
                ]
            )
            records = read_official_evidence(
                identifier=identifier,
                start=start,
                lines=lines,
                repo=repo,
                state_path=state_path,
            )
            for record in records:
                print(
                    json.dumps(
                        record, ensure_ascii=True, sort_keys=True
                    )
                )
            return 0
        elif args.operation == "official-search":
            identifier, pattern, limit = parse_official_search_tokens(
                [
                    args.identifier,
                    args.pattern,
                    "--limit",
                    str(args.limit),
                ]
            )
            records = search_official_evidence(
                identifier=identifier,
                pattern=pattern,
                limit=limit,
                repo=repo,
                state_path=state_path,
            )
            for record in records:
                print(
                    json.dumps(
                        record, ensure_ascii=True, sort_keys=True
                    )
                )
            return 0
        elif args.operation == "approve":
            outcome = approve_proposal(
                proposal_id=args.proposal_id,
                repo=repo,
                state_path=state_path,
                config_path=config_path,
                profile_path=profile_path,
            )
        elif args.operation == "renew":
            outcome = renew_write_lease(
                lease_id=args.lease_id,
                repo=repo,
                state_path=state_path,
                config_path=config_path,
                profile_path=profile_path,
            )
        else:
            outcome = complete_task(
                lease_id=args.lease_id,
                repo=repo,
                state_path=state_path,
                config_path=config_path,
                profile_path=profile_path,
            )
    except (LifecycleError, OSError, StateValidationError) as error:
        print(
            json.dumps(
                {"reason": str(error), "status": "denied"},
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(outcome.as_dict(), sort_keys=True))
    return (
        0
        if outcome.status
        in {
            "acceptance-set",
            "complete",
            "lease-issued",
            "official-evidence-registered",
            "verification-recorded",
        }
        else 3
    )
