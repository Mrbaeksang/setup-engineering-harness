#!/usr/bin/env python3
"""Plan, install, audit, repair, or uninstall an Engineering Harness."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

HARNESS_VERSION = "0.2.0"
SCHEMA_VERSION = 1
HARNESS_NAME = "engineering-harness"
SKILL_ROOT = Path(__file__).resolve().parents[1]
ASSET_ROOT = SKILL_ROOT / "assets"
PROJECT_ASSET_ROOT = ASSET_ROOT / "harness"
HOST_ASSET_ROOT = ASSET_ROOT / "runtime"
HARNESS_DIR = ".agent-harness"
MANIFEST_RELATIVE = f"{HARNESS_DIR}/manifest.json"
DEFAULT_PROVIDER_ID = "codex"
MUTABLE_HOST_STATE_FILES = (
    "completion-receipt.json",
    "gate-state.lock",
    "lease-proposal.json",
    "task-contract.json",
    "verification-receipts.json",
)

BRIDGE_START = "<!-- engineering-harness:bridge:start -->"
BRIDGE_END = "<!-- engineering-harness:bridge:end -->"
BRIDGE_TEXT = f"""\
{BRIDGE_START}
## Engineering Harness

For coding work, read `.agent-harness/router.md` before broad exploration. It routes only the
Playbooks needed for the current Task. Apply detected facts from `repo-profile.json` and
user-owned constraints from `config.json` and `local.md`. The default assistive Hook is a thin
safety boundary; it does not require acceptance tokens or leases for normal app work. Before
claiming completion, follow the verification Playbook. Run
`python3 .agent-harness/checks/audit.py` after Harness or instruction changes, not ordinary
application-code changes.
{BRIDGE_END}"""
BRIDGE_BYTES = BRIDGE_TEXT.encode("utf-8")

PROJECT_ASSETS = (
    ("router.md", f"{HARNESS_DIR}/router.md", 0o644),
    ("playbooks/core.md", f"{HARNESS_DIR}/playbooks/core.md", 0o644),
    ("playbooks/conversation.md", f"{HARNESS_DIR}/playbooks/conversation.md", 0o644),
    ("playbooks/dependencies.md", f"{HARNESS_DIR}/playbooks/dependencies.md", 0o644),
    ("playbooks/planning.md", f"{HARNESS_DIR}/playbooks/planning.md", 0o644),
    ("playbooks/implementation.md", f"{HARNESS_DIR}/playbooks/implementation.md", 0o644),
    ("playbooks/architecture.md", f"{HARNESS_DIR}/playbooks/architecture.md", 0o644),
    ("playbooks/verification.md", f"{HARNESS_DIR}/playbooks/verification.md", 0o644),
    ("playbooks/documentation.md", f"{HARNESS_DIR}/playbooks/documentation.md", 0o644),
    ("playbooks/safety.md", f"{HARNESS_DIR}/playbooks/safety.md", 0o644),
    ("runtime/runtime-contract.json", f"{HARNESS_DIR}/runtime/runtime-contract.json", 0o644),
    ("runtime/context_broker.py", f"{HARNESS_DIR}/bin/read_context.py", 0o755),
    (
        "runtime/lease_request_broker.py",
        f"{HARNESS_DIR}/bin/request_write_lease.py",
        0o755,
    ),
    (
        "runtime/verification_broker.py",
        f"{HARNESS_DIR}/bin/run_verification.py",
        0o755,
    ),
    ("checks/audit.py", f"{HARNESS_DIR}/checks/audit.py", 0o755),
)
SEEDED_ASSETS = (
    ("config.json", f"{HARNESS_DIR}/config.json", 0o644),
    ("local.md", f"{HARNESS_DIR}/local.md", 0o644),
)
HOST_ASSETS = (
    ("pretool_gate.py", "runtime/pretool_gate.py", 0o700),
    ("userprompt_context.py", "runtime/userprompt_context.py", 0o700),
    (
        "engineering_harness_gate/__init__.py",
        "runtime/engineering_harness_gate/__init__.py",
        0o600,
    ),
    (
        "engineering_harness_gate/domain.py",
        "runtime/engineering_harness_gate/domain.py",
        0o600,
    ),
    (
        "engineering_harness_gate/state_source.py",
        "runtime/engineering_harness_gate/state_source.py",
        0o600,
    ),
    (
        "engineering_harness_gate/codex.py",
        "runtime/engineering_harness_gate/codex.py",
        0o600,
    ),
    (
        "engineering_harness_gate/lifecycle.py",
        "runtime/engineering_harness_gate/lifecycle.py",
        0o600,
    ),
)

PRETOOL_HOOK_ID = "pretool-v1"
PROMPT_HOOK_ID = "userprompt-v1"
PROTECTED_GLOBS = [
    ".env*",
    "**/.env*",
    ".git",
    ".git/**",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/credentials",
    "**/credentials.json",
    "**/credentials.yaml",
    "**/credentials.yml",
    "**/credentials.toml",
    "**/secrets.json",
    "**/secrets.yaml",
    "**/secrets.yml",
    "**/secrets.toml",
    "**/tokens.json",
    "**/auth.json",
    "**/service-account.json",
    "**/.netrc",
    "**/.npmrc",
    "**/.pypirc",
    "**/id_rsa",
    "**/id_ed25519",
    "**/*private-key*.txt",
    "**/*private_key*.txt",
    "**/*private-key*.json",
    "**/*private_key*.json",
    "**/*private-key*.yaml",
    "**/*private_key*.yaml",
    "**/*private-key*.yml",
    "**/*private_key*.yml",
    ".agent-harness",
    ".agent-harness/**",
    "node_modules",
    "node_modules/**",
    "**/node_modules",
    "**/node_modules/**",
    "vendor",
    "vendor/**",
    "**/vendor",
    "**/vendor/**",
    ".venv",
    ".venv/**",
    "**/.venv",
    "**/.venv/**",
    "site-packages",
    "site-packages/**",
    "**/site-packages",
    "**/site-packages/**",
    "dist-packages",
    "dist-packages/**",
    "**/dist-packages",
    "**/dist-packages/**",
    ".codex/hooks.json",
    ".claude/settings.json",
    "package.json",
    "**/package.json",
    "package-lock.json",
    "**/package-lock.json",
    "npm-shrinkwrap.json",
    "**/npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "**/pnpm-lock.yaml",
    "yarn.lock",
    "**/yarn.lock",
    "bun.lock",
    "**/bun.lock",
    "bun.lockb",
    "**/bun.lockb",
    "pyproject.toml",
    "**/pyproject.toml",
    "requirements.txt",
    "**/requirements.txt",
    "uv.lock",
    "**/uv.lock",
    "poetry.lock",
    "**/poetry.lock",
    "Pipfile.lock",
    "**/Pipfile.lock",
    "Cargo.toml",
    "**/Cargo.toml",
    "Cargo.lock",
    "**/Cargo.lock",
    "go.mod",
    "**/go.mod",
    "go.sum",
    "**/go.sum",
    "Gemfile",
    "**/Gemfile",
    "Gemfile.lock",
    "**/Gemfile.lock",
    "pom.xml",
    "**/pom.xml",
    "build.gradle",
    "**/build.gradle",
    "build.gradle.kts",
    "**/build.gradle.kts",
]

KNOWN_FILES = {
    "package.json": ("JavaScript/TypeScript", "manifest"),
    "tsconfig.json": ("TypeScript", "config"),
    "deno.json": ("Deno", "config"),
    "deno.jsonc": ("Deno", "config"),
    "pyproject.toml": ("Python", "manifest"),
    "requirements.txt": ("Python", "manifest"),
    "Cargo.toml": ("Rust", "manifest"),
    "go.mod": ("Go", "manifest"),
    "pom.xml": ("Java", "manifest"),
    "build.gradle": ("Java/Kotlin", "manifest"),
    "build.gradle.kts": ("Java/Kotlin", "manifest"),
    "Gemfile": ("Ruby", "manifest"),
    "Makefile": ("Make", "build"),
}
LOCKFILES = {
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "bun.lock": "bun",
    "bun.lockb": "bun",
    "uv.lock": "uv",
    "poetry.lock": "Poetry",
    "Pipfile.lock": "Pipenv",
    "Cargo.lock": "Cargo",
    "go.sum": "Go modules",
    "Gemfile.lock": "Bundler",
}
INSTRUCTION_FILES = (
    "AGENTS.md",
    "CLAUDE.md",
    "CONTEXT.md",
    ".github/copilot-instructions.md",
)
SCRIPT_KINDS = {
    "build": "build",
    "test": "test",
    "test:unit": "test",
    "test:integration": "test",
    "lint": "lint",
    "typecheck": "typecheck",
    "type-check": "typecheck",
    "check:types": "typecheck",
    "format:check": "format",
    "check:format": "format",
}


@dataclass(frozen=True)
class DesiredFile:
    path: Path
    label: str
    content: bytes
    mode: int
    source: str


@dataclass(frozen=True)
class Mutation:
    path: Path
    label: str
    content: bytes | None
    mode: int
    reason: str


@dataclass
class SetupPlan:
    root: Path
    profile: dict[str, Any]
    mutations: list[Mutation]
    preserved: list[str]
    conflicts: list[str]
    manifest: dict[str, Any] | None


@dataclass(frozen=True)
class ProviderSpec:
    id: str
    display_name: str
    binary_name: str
    bridge_relative: str
    hooks_relative: str
    hook_matcher: str


PROVIDERS = {
    "codex": ProviderSpec(
        id="codex",
        display_name="Codex",
        binary_name="codex",
        bridge_relative="AGENTS.md",
        hooks_relative=".codex/hooks.json",
        hook_matcher=".*",
    ),
    "claude-code": ProviderSpec(
        id="claude-code",
        display_name="Claude Code",
        binary_name="claude",
        bridge_relative="CLAUDE.md",
        hooks_relative=".claude/settings.json",
        hook_matcher="*",
    ),
}


def provider_spec(provider_id: str) -> ProviderSpec:
    try:
        return PROVIDERS[provider_id]
    except KeyError as error:
        raise ValueError(f"unsupported provider: {safe_text(provider_id)}") from error


def manifest_provider_id(manifest: dict[str, Any] | None) -> str | None:
    if not manifest:
        return None
    provider = manifest.get("provider_hooks")
    if not isinstance(provider, dict):
        return None
    configured = provider.get("provider")
    if isinstance(configured, str) and configured in PROVIDERS:
        return configured
    path = provider.get("path")
    matches = [
        spec.id for spec in PROVIDERS.values() if spec.hooks_relative == path
    ]
    return matches[0] if len(matches) == 1 else None


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def canonical_digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def safe_text(value: Any) -> str:
    return "".join(character if character.isprintable() else "?" for character in str(value))


def normalized_relative(value: str) -> PurePosixPath:
    if not value or "\\" in value:
        raise ValueError(f"invalid managed path: {safe_text(value)}")
    result = PurePosixPath(value)
    if result.is_absolute() or any(part in {"", ".", ".."} for part in result.parts):
        raise ValueError(f"invalid managed path: {safe_text(value)}")
    return result


def project_path(root: Path, relative: str) -> Path:
    return root.joinpath(*normalized_relative(relative).parts)


def path_issue(root: Path, relative: str, *, directory: bool = False) -> str | None:
    rel = normalized_relative(relative)
    current = root
    for index, part in enumerate(rel.parts):
        current = current / part
        if current.is_symlink():
            return f"{relative}: symlinks are not allowed in managed paths"
        if current.exists() and index < len(rel.parts) - 1 and not current.is_dir():
            return f"{relative}: parent is not a directory"
    if current.exists():
        if directory and not current.is_dir():
            return f"{relative}: expected a directory"
        if not directory and current.is_dir():
            return f"{relative}: expected a file"
    return None


def read_small(path: Path, limit: int) -> bytes | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_bytes()
    except OSError:
        return None


def package_manager(package: dict[str, Any] | None, managers: list[str]) -> str | None:
    if package:
        declared = package.get("packageManager")
        if isinstance(declared, str):
            match = re.fullmatch(r"(npm|pnpm|yarn|bun)@[0-9A-Za-z.+_-]+", declared)
            if match:
                return match.group(1)
    candidates = sorted(set(managers) & {"npm", "pnpm", "yarn", "bun"})
    return candidates[0] if len(candidates) == 1 else None


def script_command(manager: str, name: str) -> str:
    return f"yarn {name}" if manager == "yarn" else f"{manager} run {name}"


def direct_package_script_command(script: str, kind: str) -> str | None:
    """Return a package-manager-independent command only when it is unambiguous.

    A missing lockfile must not force a guess between npm, pnpm, Yarn, and Bun.
    It also must not hide a verification command that already names its runtime
    directly. Keep this intentionally narrow: Node's built-in test runner is
    available without resolving a package-local binary, and the verification
    broker executes argv directly rather than through a shell.
    """

    if kind != "test" or len(script) > 4096:
        return None
    try:
        arguments = shlex.split(script, posix=True)
    except ValueError:
        return None
    if (
        len(arguments) < 2
        or arguments[0] != "node"
        or not any(
            argument == "--test" or argument.startswith("--test=")
            for argument in arguments[1:]
        )
    ):
        return None
    canonical = shlex.join(arguments)
    return canonical if canonical == script else None


def detects_stdlib_unittest(root: Path) -> bool:
    """Boundedly detect tests runnable by Python's built-in discovery."""

    tests = root / "tests"
    if not tests.is_dir() or tests.is_symlink():
        return False
    visited = 0
    for directory, names, files in os.walk(tests, followlinks=False):
        names[:] = sorted(
            name
            for name in names
            if not (Path(directory) / name).is_symlink()
        )[:100]
        for name in sorted(files):
            visited += 1
            if visited > 1000:
                return False
            if not name.startswith("test") or not name.endswith(".py"):
                continue
            path = Path(directory) / name
            if path.is_symlink():
                continue
            content = read_small(path, 256 * 1024)
            if content is None:
                continue
            if (
                b"import unittest" in content
                or b"from unittest" in content
                or b"unittest.TestCase" in content
            ):
                return True
    return False


def inspect_repository(root: Path) -> dict[str, Any]:
    manifests: list[str] = []
    configs: list[str] = []
    stacks: set[str] = set()
    lockfiles: list[dict[str, str]] = []
    instructions: list[str] = []
    ci_files: list[str] = []
    candidates: list[dict[str, Any]] = []
    notes: list[str] = []

    for name, (stack, role) in sorted(KNOWN_FILES.items()):
        candidate = root / name
        if candidate.is_file() and not candidate.is_symlink():
            stacks.add(stack)
            (manifests if role == "manifest" else configs).append(name)
        elif candidate.is_symlink():
            notes.append(f"Skipped symlinked repository marker: {name}")

    managers: list[str] = []
    for name, tool in sorted(LOCKFILES.items()):
        candidate = root / name
        if candidate.is_file() and not candidate.is_symlink():
            lockfiles.append({"path": name, "tool": tool})
            managers.append(tool)

    for name in INSTRUCTION_FILES:
        candidate = project_path(root, name)
        if candidate.is_file() and not candidate.is_symlink():
            if name in {"AGENTS.md", "CLAUDE.md"}:
                content = read_small(candidate, 2 * 1024 * 1024)
                if content is not None:
                    start = BRIDGE_START.encode()
                    end = BRIDGE_END.encode()
                    if content.count(start) == 1 and content.count(end) == 1:
                        begin = content.index(start)
                        finish = content.index(end, begin) + len(end)
                        outside = content[:begin] + content[finish:]
                        if not outside.strip():
                            continue
            instructions.append(name)

    workflows = root / ".github" / "workflows"
    if workflows.is_dir() and not workflows.is_symlink():
        try:
            ci_files = [
                f".github/workflows/{path.name}"
                for path in sorted(workflows.iterdir(), key=lambda item: item.name)[:100]
                if path.is_file()
                and not path.is_symlink()
                and path.suffix.lower() in {".yml", ".yaml"}
            ]
        except OSError:
            notes.append("Could not list .github/workflows")

    package_data: dict[str, Any] | None = None
    package_raw = read_small(root / "package.json", 2 * 1024 * 1024)
    if package_raw is not None:
        try:
            parsed = json.loads(package_raw.decode())
            if isinstance(parsed, dict):
                package_data = parsed
        except (UnicodeError, json.JSONDecodeError):
            notes.append("package.json could not be parsed")
    manager = package_manager(package_data, managers)
    scripts = package_data.get("scripts") if package_data else None
    if isinstance(scripts, dict):
        for name, kind in sorted(SCRIPT_KINDS.items()):
            script = scripts.get(name)
            if isinstance(script, str):
                if manager:
                    candidates.append(
                        {
                            "command": script_command(manager, name),
                            "evidence": f"package.json#scripts.{name}",
                            "executed": False,
                            "kind": kind,
                        }
                    )
                else:
                    direct = direct_package_script_command(script, kind)
                    if direct:
                        candidates.append(
                            {
                                "command": direct,
                                "evidence": (
                                    f"package.json#scripts.{name} "
                                    "(direct Node.js test runner)"
                                ),
                                "executed": False,
                                "kind": kind,
                            }
                        )
                        notes.append(
                            f"Registered script {name!r} directly; "
                            "no package manager selection was required"
                        )
                    else:
                        notes.append(
                            f"Found script {name!r}, but package manager is ambiguous"
                        )

    if (root / "Cargo.toml").is_file() and not (root / "Cargo.toml").is_symlink():
        candidates.extend(
            [
                {
                    "command": "cargo build",
                    "evidence": "Cargo.toml",
                    "executed": False,
                    "kind": "build",
                },
                {
                    "command": "cargo test",
                    "evidence": "Cargo.toml",
                    "executed": False,
                    "kind": "test",
                },
                {
                    "command": "cargo check",
                    "evidence": "Cargo.toml",
                    "executed": False,
                    "kind": "typecheck",
                },
            ]
        )
    if (root / "go.mod").is_file() and not (root / "go.mod").is_symlink():
        candidates.extend(
            [
                {
                    "command": "go test ./...",
                    "evidence": "go.mod",
                    "executed": False,
                    "kind": "test",
                },
                {
                    "command": "go vet ./...",
                    "evidence": "go.mod",
                    "executed": False,
                    "kind": "lint",
                },
            ]
        )
    pyproject = read_small(root / "pyproject.toml", 512 * 1024)
    if (
        ((root / "pytest.ini").is_file() and not (root / "pytest.ini").is_symlink())
        or (pyproject is not None and b"[tool.pytest" in pyproject)
    ):
        command = "uv run pytest" if (root / "uv.lock").is_file() else "python -m pytest"
        candidates.append(
            {
                "command": command,
                "evidence": "pytest configuration",
                "executed": False,
                "kind": "test",
            }
        )
    if detects_stdlib_unittest(root):
        candidates.append(
            {
                "command": "python -m unittest discover",
                "evidence": "bounded tests/test*.py unittest inspection",
                "executed": False,
                "kind": "test",
            }
        )

    unique = {
        (item["kind"], item["command"], item["evidence"]): item for item in candidates
    }
    candidates = [unique[key] for key in sorted(unique)]
    identifier_counts: dict[str, int] = {}
    for item in candidates:
        base = re.sub(r"[^A-Za-z0-9._:-]+", "-", item["kind"]).strip("-") or "check"
        identifier_counts[base] = identifier_counts.get(base, 0) + 1
        count = identifier_counts[base]
        item["id"] = base if count == 1 else f"{base}-{count}"
    return {
        "_generated_by": f"{HARNESS_NAME}@{HARNESS_VERSION}",
        "_ownership": "installer-owned; regenerate with setup_harness.py",
        "candidate_commands": candidates,
        "facts": {
            "ci_files": sorted(ci_files),
            "configs": sorted(configs),
            "instruction_files": sorted(instructions),
            "lockfiles": lockfiles,
            "manifests": sorted(manifests),
            "stacks": sorted(stacks),
        },
        "notes": sorted(set(notes))
        + [
            "Facts come from bounded repository metadata inspection.",
            "Candidate commands were detected, not executed or authorized.",
        ],
        "schema_version": SCHEMA_VERSION,
        "scope": ".",
    }


def state_locations(root: Path) -> tuple[str, Path, Path, Path]:
    configured = os.environ.get("XDG_STATE_HOME")
    base = Path(configured).expanduser() if configured else Path.home() / ".local" / "state"
    if not base.is_absolute():
        raise ValueError("XDG_STATE_HOME must be absolute")
    base = base.resolve(strict=False)
    project_id = f"project-{sha256(str(root).encode())[:20]}"
    directory = (base / HARNESS_NAME / project_id).resolve(strict=False)
    try:
        directory.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError(
            "authoritative Harness state must be outside the target repository"
        )
    return project_id, directory, directory / "gate-state.json", directory / "setup-status.json"


def desired_project_files(root: Path, profile: dict[str, Any]) -> list[DesiredFile]:
    result: list[DesiredFile] = []
    for source_name, target_name, mode in PROJECT_ASSETS:
        source = PROJECT_ASSET_ROOT.joinpath(*PurePosixPath(source_name).parts)
        result.append(
            DesiredFile(
                project_path(root, target_name),
                target_name,
                source.read_bytes(),
                mode,
                f"assets/harness/{source_name}",
            )
        )
    profile_name = f"{HARNESS_DIR}/repo-profile.json"
    result.append(
        DesiredFile(
            project_path(root, profile_name),
            profile_name,
            json_bytes(profile),
            0o644,
            "generated repository profile",
        )
    )
    return sorted(result, key=lambda item: item.label)


def desired_host_files(directory: Path) -> list[DesiredFile]:
    result: list[DesiredFile] = []
    for source_name, relative, mode in HOST_ASSETS:
        source = HOST_ASSET_ROOT / source_name
        result.append(
            DesiredFile(
                directory.joinpath(*PurePosixPath(relative).parts),
                f"host:{relative}",
                source.read_bytes(),
                mode,
                f"assets/runtime/{source_name}",
            )
        )
    return result


def initial_gate_state(root: Path, project_id: str, profile: dict[str, Any]) -> bytes:
    base_hash = f"sha256:{sha256(b'initial-locked-state\\0' + json_bytes(profile))}"
    acceptance_hash = f"sha256:{sha256(b'setup-initial')}"
    python_executable = str(Path(sys.executable).resolve(strict=True))
    return json_bytes(
        {
            "acceptanceHash": acceptance_hash,
            "baseTreeHash": base_hash,
            "evidence": [],
            "pendingDecisions": [],
            "phase": "received",
            "projectId": project_id,
            "projectRoot": str(root),
            "protectedGlobs": PROTECTED_GLOBS,
            "readBrokerPythonExecutables": [python_executable],
            "schemaVersion": 1,
            "taskId": "setup-initial",
            "writeLease": None,
        }
    )


def initial_setup_status(
    root: Path, project_id: str, broker_digest: str, provider: ProviderSpec
) -> bytes:
    return json_bytes(
        {
            "contextBrokerSha256": broker_digest,
            "hookTrustVerified": False,
            "projectId": project_id,
            "projectRoot": str(root),
            "providerId": provider.id,
            "providerBinary": None,
            "providerBinarySha256": None,
            "providerReceipt": None,
            "providerVersion": None,
            "runtimeReady": True,
            "schemaVersion": 1,
            "verificationEvidenceSha256": None,
            "verifiedAt": None,
            "verifiedManifestChecksum": None,
            "writeCanaryVerified": False,
        }
    )


def expected_hooks(
    root: Path,
    host_directory: Path,
    state_path: Path,
    status_path: Path,
    provider: ProviderSpec,
) -> list[tuple[str, str, dict[str, Any]]]:
    python_executable = shlex.quote(str(Path(sys.executable).resolve(strict=True)))
    gate = host_directory / "runtime" / "pretool_gate.py"
    prompt = host_directory / "runtime" / "userprompt_context.py"
    gate_command = " ".join(
        [
            f"ENGINEERING_HARNESS_HOOK_ID={PRETOOL_HOOK_ID}",
            python_executable,
            shlex.quote(str(gate)),
            "--state",
            shlex.quote(str(state_path)),
            "--status",
            shlex.quote(str(status_path)),
            "--repo",
            shlex.quote(str(root)),
        ]
    )
    prompt_command = " ".join(
        [
            f"ENGINEERING_HARNESS_HOOK_ID={PROMPT_HOOK_ID}",
            python_executable,
            shlex.quote(str(prompt)),
            "--state",
            shlex.quote(str(state_path)),
            "--repo",
            shlex.quote(str(root)),
        ]
    )
    return [
        (
            "PreToolUse",
            PRETOOL_HOOK_ID,
            {
                "hooks": [
                    {
                        "command": gate_command,
                        "statusMessage": "Engineering Harness: checking protected action",
                        "timeout": 10,
                        "type": "command",
                    }
                ],
                "matcher": provider.hook_matcher,
            },
        ),
        (
            "UserPromptSubmit",
            PROMPT_HOOK_ID,
            {
                "hooks": [
                    {
                        "command": prompt_command,
                        "statusMessage": "Engineering Harness: preparing task contract",
                        "timeout": 10,
                        "type": "command",
                    }
                ]
            },
        ),
    ]


def hook_commands(entry: Any) -> str:
    if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
        return ""
    return "\n".join(
        hook["command"]
        for hook in entry["hooks"]
        if isinstance(hook, dict) and isinstance(hook.get("command"), str)
    )


def hook_matches(entry: Any, hook_id: str) -> bool:
    return f"ENGINEERING_HARNESS_HOOK_ID={hook_id}" in hook_commands(entry)


def seal_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    result = dict(manifest)
    result.pop("manifest_checksum", None)
    result["manifest_checksum"] = canonical_digest(result)
    return result


def load_manifest(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, f"invalid JSON ({error})"
    if not isinstance(value, dict):
        return None, "root must be an object"
    if value.get("_managed_by") != HARNESS_NAME:
        return None, "unexpected manager marker"
    if value.get("schema_version") != SCHEMA_VERSION:
        return None, "unsupported schema"
    expected = value.get("manifest_checksum")
    body = dict(value)
    body.pop("manifest_checksum", None)
    if not isinstance(expected, str) or canonical_digest(body) != expected:
        return None, "manifest checksum mismatch"
    return value, None


def manifest_owned(manifest: dict[str, Any] | None) -> dict[str, str]:
    if not manifest:
        return {}
    result: dict[str, str] = {}
    entries = manifest.get("owned_files")
    if isinstance(entries, list):
        for entry in entries:
            if (
                isinstance(entry, dict)
                and isinstance(entry.get("path"), str)
                and isinstance(entry.get("sha256"), str)
            ):
                result[entry["path"]] = entry["sha256"]
    return result


def manifest_host_owned(manifest: dict[str, Any] | None) -> dict[str, str]:
    if not manifest:
        return {}
    host = manifest.get("host_runtime")
    result: dict[str, str] = {}
    if isinstance(host, dict) and isinstance(host.get("owned_files"), list):
        for entry in host["owned_files"]:
            if (
                isinstance(entry, dict)
                and isinstance(entry.get("path"), str)
                and isinstance(entry.get("sha256"), str)
            ):
                result[entry["path"]] = entry["sha256"]
    return result


def manifest_hook_digests(manifest: dict[str, Any] | None) -> dict[tuple[str, str], str]:
    if not manifest:
        return {}
    provider = manifest.get("provider_hooks")
    result: dict[tuple[str, str], str] = {}
    if isinstance(provider, dict) and isinstance(provider.get("managed_entries"), list):
        for entry in provider["managed_entries"]:
            if (
                isinstance(entry, dict)
                and isinstance(entry.get("event"), str)
                and isinstance(entry.get("id"), str)
                and isinstance(entry.get("sha256"), str)
            ):
                result[(entry["event"], entry["id"])] = entry["sha256"]
    return result


def recovery_path(root: Path, label: str, content: bytes, *, host: bool = False) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "__", label)
    base = root / "recovery" if host else root / HARNESS_DIR / "recovery"
    return base / f"{safe}.{sha256(content)[:16]}.before-repair"


def mutation_for_recovery(
    base: Path, label: str, content: bytes, *, host: bool = False
) -> Mutation | None:
    path = recovery_path(base, label, content, host=host)
    if path.exists():
        return None
    prefix = "host-recovery:" if host else f"{HARNESS_DIR}/recovery/"
    return Mutation(path, f"{prefix}{path.name}", content, 0o600, "preserved drift")


def file_mode(path: Path, fallback: int) -> int:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return fallback


def bridge_analysis(
    root: Path,
    previous: dict[str, Any] | None,
    command: str,
    provider: ProviderSpec,
) -> tuple[Mutation | None, Mutation | None, dict[str, Any], list[str]]:
    bridge_relative = provider.bridge_relative
    path = project_path(root, bridge_relative)
    issues: list[str] = []
    issue = path_issue(root, bridge_relative)
    if issue:
        return None, None, {}, [issue]
    old_block: dict[str, Any] = {}
    if previous and isinstance(previous.get("managed_blocks"), list):
        blocks = previous["managed_blocks"]
        if len(blocks) == 1 and isinstance(blocks[0], dict):
            old_block = blocks[0]

    if not path.exists():
        framing = {"created_file": True, "leading_hex": "", "trailing_hex": "0a"}
        block = {
            **framing,
            "end": BRIDGE_END,
            "name": "engineering-harness-bridge",
            "path": bridge_relative,
            "sha256": sha256(BRIDGE_BYTES),
            "start": BRIDGE_START,
        }
        return (
            Mutation(
                path,
                bridge_relative,
                BRIDGE_BYTES + b"\n",
                0o644,
                "created Managed Bridge",
            ),
            None,
            block,
            issues,
        )

    try:
        content = path.read_bytes()
    except OSError as error:
        return None, None, {}, [f"{bridge_relative}: unreadable ({error})"]
    start = BRIDGE_START.encode()
    end = BRIDGE_END.encode()
    if content.count(start) == 0 and content.count(end) == 0:
        leading = b"" if not content or content.endswith(b"\n\n") else (
            b"\n" if content.endswith(b"\n") else b"\n\n"
        )
        trailing = b"\n"
        block = {
            "created_file": False,
            "end": BRIDGE_END,
            "leading_hex": leading.hex(),
            "name": "engineering-harness-bridge",
            "path": bridge_relative,
            "sha256": sha256(BRIDGE_BYTES),
            "start": BRIDGE_START,
            "trailing_hex": trailing.hex(),
        }
        return (
            Mutation(
                path,
                bridge_relative,
                content + leading + BRIDGE_BYTES + trailing,
                file_mode(path, 0o644),
                "appended Managed Bridge",
            ),
            None,
            block,
            issues,
        )
    if content.count(start) != 1 or content.count(end) != 1:
        return None, None, {}, [
            f"{bridge_relative}: bridge markers are duplicated or unbalanced"
        ]
    begin = content.index(start)
    finish = content.index(end, begin) + len(end)
    current = content[begin:finish]
    framing = {
        "created_file": bool(old_block.get("created_file", False)),
        "leading_hex": str(old_block.get("leading_hex", "")),
        "trailing_hex": str(old_block.get("trailing_hex", "")),
    }
    block = {
        **framing,
        "end": BRIDGE_END,
        "name": "engineering-harness-bridge",
        "path": bridge_relative,
        "sha256": sha256(BRIDGE_BYTES),
        "start": BRIDGE_START,
    }
    if current == BRIDGE_BYTES:
        return None, None, block, issues
    previous_digest = old_block.get("sha256")
    if previous_digest == sha256(current) or command == "repair":
        backup = (
            mutation_for_recovery(root, bridge_relative, content)
            if command == "repair" and previous_digest != sha256(current)
            else None
        )
        return (
            Mutation(
                path,
                bridge_relative,
                content[:begin] + BRIDGE_BYTES + content[finish:],
                file_mode(path, 0o644),
                "repaired Managed Bridge" if command == "repair" else "updated Managed Bridge",
            ),
            backup,
            block,
            issues,
        )
    return None, None, block, [
        f"{bridge_relative}: managed bridge drift; review it, then run repair explicitly"
    ]


def parse_hooks(
    path: Path, hooks_relative: str
) -> tuple[dict[str, Any], bytes | None, str | None]:
    if not path.exists():
        return {}, None, None
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return {}, None, f"{hooks_relative}: invalid JSON ({error})"
    if not isinstance(value, dict):
        return {}, raw, f"{hooks_relative}: root must be an object"
    hooks = value.get("hooks")
    if hooks is not None and not isinstance(hooks, dict):
        return {}, raw, f"{hooks_relative}: hooks must be an object"
    return value, raw, None


def hook_analysis(
    root: Path,
    expected: list[tuple[str, str, dict[str, Any]]],
    previous: dict[str, Any] | None,
    command: str,
    provider: ProviderSpec,
) -> tuple[Mutation | None, Mutation | None, bool, list[str]]:
    hooks_relative = provider.hooks_relative
    path = project_path(root, hooks_relative)
    issue = path_issue(root, hooks_relative)
    if issue:
        return None, None, False, [issue]
    data, raw, error = parse_hooks(path, hooks_relative)
    if error:
        return None, None, False, [error]
    original_absent = raw is None
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        return None, None, False, [f"{hooks_relative}: hooks must be an object"]
    previous_digests = manifest_hook_digests(previous)
    changed = False
    drifted = False
    conflicts: list[str] = []
    for event, hook_id, desired in expected:
        entries = hooks.setdefault(event, [])
        if not isinstance(entries, list):
            conflicts.append(f"{hooks_relative}: {event} must be an array")
            continue
        matches = [index for index, entry in enumerate(entries) if hook_matches(entry, hook_id)]
        previous_digest = previous_digests.get((event, hook_id))
        if not matches:
            if previous_digest is not None and command != "repair":
                conflicts.append(
                    f"{hooks_relative}: managed {event} {hook_id} is missing; run repair"
                )
            else:
                entries.append(desired)
                changed = True
                drifted = drifted or previous_digest is not None
            continue
        if len(matches) > 1:
            if command != "repair":
                conflicts.append(
                    f"{hooks_relative}: duplicate managed {event} {hook_id} entries"
                )
                continue
            first = matches[0]
            entries[:] = [
                entry
                for index, entry in enumerate(entries)
                if index not in matches or index == first
            ]
            entries[first] = desired
            changed = True
            drifted = True
            continue
        index = matches[0]
        current = entries[index]
        if current == desired:
            continue
        current_digest = canonical_digest(current)
        if previous_digest == current_digest or command == "repair":
            entries[index] = desired
            changed = True
            drifted = drifted or previous_digest != current_digest
        else:
            conflicts.append(
                f"{hooks_relative}: managed {event} {hook_id} drift; run repair"
            )
    if conflicts:
        return None, None, original_absent, conflicts
    backup = (
        mutation_for_recovery(root, hooks_relative, raw or b"")
        if command == "repair" and drifted
        else None
    )
    if not changed:
        return None, backup, original_absent, []
    return (
        Mutation(
            path,
            hooks_relative,
            json_bytes(data),
            file_mode(path, 0o644),
            "merged managed provider hooks",
        ),
        backup,
        original_absent,
        [],
    )


def valid_gate_state(path: Path, root: Path) -> str | None:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return f"invalid JSON ({error})"
    required = {
        "schemaVersion",
        "taskId",
        "projectId",
        "projectRoot",
        "readBrokerPythonExecutables",
        "protectedGlobs",
        "baseTreeHash",
        "acceptanceHash",
        "phase",
        "evidence",
        "pendingDecisions",
        "writeLease",
    }
    if not isinstance(value, dict) or set(value) != required:
        return "keys do not match Gate v1"
    if value.get("schemaVersion") != 1 or value.get("projectRoot") != str(root):
        return "schema or Project root mismatch"
    return None


def valid_setup_status(path: Path, root: Path) -> str | None:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return f"invalid JSON ({error})"
    if (
        not isinstance(value, dict)
        or value.get("schemaVersion") != 1
        or value.get("projectRoot") != str(root)
    ):
        return "schema or Project root mismatch"
    return None


def add_desired_file(
    desired: DesiredFile,
    previous_digest: str | None,
    command: str,
    mutations: list[Mutation],
    conflicts: list[str],
    recovery_base: Path,
    *,
    host: bool = False,
) -> None:
    path = desired.path
    if path.is_symlink():
        conflicts.append(f"{desired.label}: symlinks are not allowed")
        return
    if not path.exists():
        mutations.append(
            Mutation(path, desired.label, desired.content, desired.mode, "created owned file")
        )
        return
    if path.is_dir():
        conflicts.append(f"{desired.label}: expected a file")
        return
    try:
        current = path.read_bytes()
    except OSError as error:
        conflicts.append(f"{desired.label}: unreadable ({error})")
        return
    if current == desired.content and file_mode(path, desired.mode) == desired.mode:
        return
    current_digest = sha256(current)
    if current == desired.content or previous_digest == current_digest:
        mutations.append(
            Mutation(path, desired.label, desired.content, desired.mode, "updated owned file")
        )
        return
    if command == "repair":
        backup = mutation_for_recovery(
            recovery_base, desired.label, current, host=host
        )
        if backup:
            mutations.append(backup)
        mutations.append(
            Mutation(path, desired.label, desired.content, desired.mode, "repaired owned file")
        )
        return
    conflicts.append(f"{desired.label}: installer-owned drift; review, then run repair")


def build_manifest(
    root: Path,
    project_files: Iterable[DesiredFile],
    host_files: Iterable[DesiredFile],
    bridge: dict[str, Any],
    hooks: list[tuple[str, str, dict[str, Any]]],
    hooks_created: bool,
    state_path: Path,
    status_path: Path,
    provider: ProviderSpec,
) -> dict[str, Any]:
    return seal_manifest(
        {
            "_managed_by": HARNESS_NAME,
            "_ownership": "installer-owned",
            "harness_version": HARNESS_VERSION,
            "host_runtime": {
                "owned_files": [
                    {
                        "path": str(item.path),
                        "sha256": sha256(item.content),
                        "source": item.source,
                    }
                    for item in host_files
                ],
                "state_path": str(state_path),
                "status_path": str(status_path),
            },
            "managed_blocks": [bridge],
            "owned_files": [
                {
                    "path": item.label,
                    "sha256": sha256(item.content),
                    "source": item.source,
                }
                for item in project_files
            ],
            "provider_hooks": {
                "file_created": hooks_created,
                "managed_entries": [
                    {
                        "event": event,
                        "id": hook_id,
                        "sha256": canonical_digest(entry),
                    }
                    for event, hook_id, entry in hooks
                ],
                "path": provider.hooks_relative,
                "provider": provider.id,
            },
            "schema_version": SCHEMA_VERSION,
            "seeded_files": [
                {
                    "ownership": "user-owned",
                    "path": target,
                    "source": f"assets/harness/{source}",
                }
                for source, target, _mode in SEEDED_ASSETS
            ],
        }
    )


def plan_setup(
    root: Path,
    command: str,
    provider: ProviderSpec = PROVIDERS[DEFAULT_PROVIDER_ID],
) -> SetupPlan:
    profile = inspect_repository(root)
    mutations: list[Mutation] = []
    preserved: list[str] = []
    conflicts: list[str] = []
    manifest_path = project_path(root, MANIFEST_RELATIVE)
    previous: dict[str, Any] | None = None
    if manifest_path.exists():
        previous, error = load_manifest(manifest_path)
        if error:
            if command != "repair":
                return SetupPlan(
                    root,
                    profile,
                    [],
                    preserved,
                    [f"{MANIFEST_RELATIVE}: {error}; run repair explicitly"],
                    None,
                )
            raw = manifest_path.read_bytes()
            backup = mutation_for_recovery(root, MANIFEST_RELATIVE, raw)
            if backup:
                mutations.append(backup)
            preserved.append(backup.label if backup else MANIFEST_RELATIVE)
        installed_provider = manifest_provider_id(previous)
        if previous is not None and installed_provider != provider.id:
            return SetupPlan(
                root,
                profile,
                [],
                preserved,
                [
                    f"{MANIFEST_RELATIVE}: installed provider is "
                    f"{installed_provider or 'unknown'}, requested {provider.id}; "
                    "uninstall before changing provider"
                ],
                previous,
            )

    project_id, host_directory, state_path, status_path = state_locations(root)
    project_files = desired_project_files(root, profile)
    host_files = desired_host_files(host_directory)
    expected = expected_hooks(
        root, host_directory, state_path, status_path, provider
    )

    bridge_write, bridge_backup, bridge, bridge_issues = bridge_analysis(
        root, previous, command, provider
    )
    conflicts.extend(bridge_issues)
    if bridge_backup:
        mutations.append(bridge_backup)
        preserved.append(bridge_backup.label)
    if bridge_write:
        mutations.append(bridge_write)

    hook_write, hook_backup, hook_created, hook_issues = hook_analysis(
        root, expected, previous, command, provider
    )
    conflicts.extend(hook_issues)
    if hook_backup:
        mutations.append(hook_backup)
        preserved.append(hook_backup.label)
    if hook_write:
        mutations.append(hook_write)

    previous_project = manifest_owned(previous)
    for desired in project_files:
        issue = path_issue(root, desired.label)
        if issue:
            conflicts.append(issue)
            continue
        add_desired_file(
            desired,
            previous_project.get(desired.label),
            command,
            mutations,
            conflicts,
            root,
        )

    for source_name, target_name, mode in SEEDED_ASSETS:
        issue = path_issue(root, target_name)
        if issue:
            conflicts.append(issue)
            continue
        path = project_path(root, target_name)
        if path.exists():
            preserved.append(target_name)
        else:
            source = PROJECT_ASSET_ROOT.joinpath(*PurePosixPath(source_name).parts)
            mutations.append(
                Mutation(
                    path,
                    target_name,
                    source.read_bytes(),
                    mode,
                    "seeded user-owned file",
                )
            )

    previous_host = manifest_host_owned(previous)
    for desired in host_files:
        add_desired_file(
            desired,
            previous_host.get(str(desired.path)),
            command,
            mutations,
            conflicts,
            host_directory,
            host=True,
        )

    broker = next(
        item for item in project_files if item.label == f"{HARNESS_DIR}/bin/read_context.py"
    )
    state_content = initial_gate_state(root, project_id, profile)
    status_content = initial_setup_status(
        root, project_id, sha256(broker.content), provider
    )
    for path, label, content, validator in (
        (state_path, "host:gate-state.json", state_content, valid_gate_state),
        (status_path, "host:setup-status.json", status_content, valid_setup_status),
    ):
        if path.is_symlink():
            conflicts.append(f"{label}: symlinks are not allowed")
        elif not path.exists():
            mutations.append(Mutation(path, label, content, 0o600, "created locked host state"))
        else:
            error = validator(path, root)
            if error:
                if command != "repair":
                    conflicts.append(f"{label}: {error}; run repair explicitly")
                else:
                    raw = path.read_bytes()
                    backup = mutation_for_recovery(
                        host_directory, label, raw, host=True
                    )
                    if backup:
                        mutations.append(backup)
                        preserved.append(backup.label)
                    mutations.append(
                        Mutation(path, label, content, 0o600, "reset invalid host state locked")
                    )
            elif file_mode(path, 0o600) != 0o600:
                mutations.append(
                    Mutation(path, label, path.read_bytes(), 0o600, "secured host state mode")
                )
            elif path == status_path:
                current_status = json.loads(path.read_text(encoding="utf-8"))
                current_provider = current_status.get("providerId")
                if current_provider not in {None, provider.id}:
                    conflicts.append(
                        f"{label}: provider belongs to {current_provider}, "
                        f"requested {provider.id}"
                    )
                elif current_provider is None:
                    current_status.update(
                        {
                            "hookTrustVerified": False,
                            "providerBinary": None,
                            "providerBinarySha256": None,
                            "providerId": provider.id,
                            "providerReceipt": None,
                            "providerVersion": None,
                            "verificationEvidenceSha256": None,
                            "verifiedAt": None,
                            "verifiedManifestChecksum": None,
                            "writeCanaryVerified": False,
                        }
                    )
                    mutations.append(
                        Mutation(
                            path,
                            label,
                            json_bytes(current_status),
                            0o600,
                            "bound host status to provider",
                        )
                    )
                else:
                    preserved.append(label)
            else:
                preserved.append(label)

    manifest = build_manifest(
        root,
        project_files,
        host_files,
        bridge,
        expected,
        hook_created
        if previous is None
        else bool(previous.get("provider_hooks", {}).get("file_created", False)),
        state_path,
        status_path,
        provider,
    )
    content = json_bytes(manifest)
    if not manifest_path.exists() or manifest_path.read_bytes() != content:
        mutations.append(
            Mutation(
                manifest_path,
                MANIFEST_RELATIVE,
                content,
                0o644,
                "wrote ownership manifest",
            )
        )
    if conflicts:
        return SetupPlan(root, profile, [], sorted(set(preserved)), sorted(set(conflicts)), manifest)
    return SetupPlan(root, profile, mutations, sorted(set(preserved)), [], manifest)


def atomic_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".engineering-harness-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def apply_transaction(
    mutations: list[Mutation],
    *,
    after_apply: Any | None = None,
) -> list[Mutation]:
    snapshots: dict[Path, tuple[bool, bytes, int]] = {}
    created_directories: set[Path] = set()
    changed: list[Mutation] = []
    for mutation in mutations:
        if mutation.path not in snapshots:
            if mutation.path.exists():
                snapshots[mutation.path] = (
                    True,
                    mutation.path.read_bytes(),
                    file_mode(mutation.path, 0o644),
                )
            else:
                snapshots[mutation.path] = (False, b"", mutation.mode)
        parent = mutation.path.parent
        while not parent.exists():
            created_directories.add(parent)
            if parent == parent.parent:
                break
            parent = parent.parent
    try:
        for mutation in mutations:
            if mutation.content is None:
                if mutation.path.exists():
                    mutation.path.unlink()
                    changed.append(mutation)
                continue
            if (
                mutation.path.exists()
                and mutation.path.read_bytes() == mutation.content
                and file_mode(mutation.path, mutation.mode) == mutation.mode
            ):
                continue
            atomic_write(mutation.path, mutation.content, mutation.mode)
            changed.append(mutation)
        if after_apply is not None:
            after_apply()
    except Exception as original_error:
        rollback_errors: list[str] = []
        for path, (existed, content, mode) in reversed(list(snapshots.items())):
            try:
                if existed:
                    atomic_write(path, content, mode)
                elif path.exists():
                    path.unlink()
            except OSError as rollback_error:
                rollback_errors.append(f"{path}: {rollback_error}")
        for directory in sorted(created_directories, key=lambda item: len(item.parts), reverse=True):
            try:
                directory.rmdir()
            except OSError as rollback_error:
                if directory.exists():
                    rollback_errors.append(f"{directory}: {rollback_error}")
        if rollback_errors:
            raise RuntimeError(
                "installation failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from original_error
        raise
    return changed


def secure_host_directory(manifest: dict[str, Any] | None) -> None:
    if not manifest:
        return
    host = manifest.get("host_runtime")
    if not isinstance(host, dict) or not isinstance(host.get("state_path"), str):
        return
    state_directory = Path(host["state_path"]).parent
    state_directory.mkdir(parents=True, exist_ok=True)
    os.chmod(state_directory, 0o700)
    runtime = state_directory / "runtime"
    if runtime.exists():
        os.chmod(runtime, 0o700)


def run_audit(root: Path, *, as_json: bool = False) -> int:
    checker = PROJECT_ASSET_ROOT / "checks" / "audit.py"
    command = [sys.executable, str(checker), "--repo", str(root)]
    if as_json:
        command.append("--json")
    return subprocess.run(command, check=False).returncode


def _provider_canary_denied(
    provider: ProviderSpec, stdout: str, stderr: str
) -> bool:
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            isinstance(event, dict)
            and event.get("type") == "hook.completed"
            and event.get("hook") == "PreToolUse"
            and event.get("permissionDecision") == "deny"
            and event.get("tool_name")
            in {"apply_patch", "ApplyPatch", "Write", "write"}
            and isinstance(event.get("tool_call_id"), str)
            and event["tool_call_id"]
        ):
            return True
        if isinstance(event, dict):
            serialized = json.dumps(event, sort_keys=True).lower()
            if (
                "pretooluse" in serialized
                and "deny" in serialized
                and (
                    "writing is locked" in serialized
                    or PRETOOL_HOOK_ID in serialized
                )
            ):
                return True
    lowered = (stdout + "\n" + stderr).lower()
    return (
        "pretooluse hook" in lowered
        and (
            "tool call blocked" in lowered
            or "command blocked" in lowered
            or "blocked by pretooluse hook" in lowered
        )
    ) or (
        provider.id == "claude-code"
        and "pretooluse" in lowered
        and "writing is locked" in lowered
        and "deny" in lowered
    )


def _provider_environment(state_home: Path) -> dict[str, str]:
    allowed = {
        "ALL_PROXY",
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CONFIG_DIR",
        "CODEX_HOME",
        "HOME",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "LANG",
        "LC_ALL",
        "NO_PROXY",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SystemRoot",
        "TERM",
        "TMPDIR",
        "TZ",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    }
    environment = {
        key: value for key, value in os.environ.items() if key in allowed
    }
    environment["XDG_STATE_HOME"] = str(state_home)
    return environment


def verify_provider(
    root: Path,
    *,
    provider: ProviderSpec | None = None,
    run_process: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    find_binary: Callable[[str], str | None] = shutil.which,
) -> int:
    """Verify normal provider hook dispatch without bypassing persisted trust."""

    checker = PROJECT_ASSET_ROOT / "checks" / "audit.py"
    inspected = run_process(
        [sys.executable, str(checker), "--repo", str(root), "--json"],
        capture_output=True,
        check=False,
        text=True,
    )
    try:
        audit_payload = json.loads(inspected.stdout)
    except (json.JSONDecodeError, TypeError):
        print("Provider verification: audit output is invalid", file=sys.stderr)
        return 2
    if inspected.returncode == 1 or audit_payload.get("issues"):
        print("Provider verification: install integrity audit failed", file=sys.stderr)
        return 2

    manifest, manifest_error = load_manifest(root / MANIFEST_RELATIVE)
    if manifest is None:
        print(
            f"Provider verification: manifest is invalid ({manifest_error})",
            file=sys.stderr,
        )
        return 2
    installed_provider_id = manifest_provider_id(manifest)
    if installed_provider_id is None:
        print("Provider verification: provider identity is invalid", file=sys.stderr)
        return 2
    installed_provider = provider_spec(installed_provider_id)
    if provider is not None and provider.id != installed_provider.id:
        print(
            "Provider verification: requested provider does not match installation",
            file=sys.stderr,
        )
        return 2
    provider = installed_provider
    host = manifest.get("host_runtime")
    if not isinstance(host, dict):
        print("Provider verification: host runtime is missing", file=sys.stderr)
        return 2
    try:
        state_path = Path(str(host["state_path"])).resolve(strict=True)
        status_path = Path(str(host["status_path"])).resolve(strict=True)
        status = json.loads(status_path.read_text(encoding="utf-8"))
        if (
            not isinstance(status, dict)
            or status.get("projectRoot") != str(root)
            or status.get("providerId") not in {None, provider.id}
        ):
            raise ValueError("setup status belongs to another Project")
    except (OSError, KeyError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"Provider verification: host state is invalid ({error})", file=sys.stderr)
        return 2

    binary_value = find_binary(provider.binary_name)
    if not binary_value:
        print(
            f"Provider verification: {provider.display_name} CLI is not installed",
            file=sys.stderr,
        )
        return 3
    try:
        binary = str(Path(binary_value).resolve(strict=True))
    except OSError as error:
        print(
            f"Provider verification: {provider.display_name} CLI is unsafe ({error})",
            file=sys.stderr,
        )
        return 2

    target = root / ".engineering-harness-provider-canary"
    if target.exists() or target.is_symlink():
        print(
            "Provider verification: reserved canary path already exists",
            file=sys.stderr,
        )
        return 2

    state_directory = state_path.parent
    snapshots: dict[Path, tuple[bool, bytes, int]] = {}
    for path in (
        state_path,
        *(state_directory / name for name in MUTABLE_HOST_STATE_FILES),
    ):
        if path.exists():
            snapshots[path] = (
                True,
                path.read_bytes(),
                stat.S_IMODE(path.stat().st_mode),
            )
        else:
            snapshots[path] = (False, b"", 0o600)

    environment = _provider_environment(state_directory)
    tool_instruction = (
        "call apply_patch to add"
        if provider.id == "codex"
        else "call Write to create"
    )
    prompt = (
        "Provider-hook canary. Do not inspect the repository and do not use "
        f"shell commands. As your first and only tool action, {tool_instruction} "
        "`.engineering-harness-provider-canary` containing `blocked`. Then stop."
    )
    result: subprocess.CompletedProcess[str] | None = None
    version = "unknown"
    try:
        version_result = run_process(
            [binary, "--version"],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
            timeout=15,
        )
        observed_version = safe_text(
            (version_result.stdout or "").strip()
        )[:200]
        if version_result.returncode == 0 and observed_version:
            version = observed_version
            if provider.id == "codex":
                command = [
                    binary,
                    "exec",
                    "--json",
                    "--ephemeral",
                    "--color",
                    "never",
                    "--sandbox",
                    "workspace-write",
                    "--cd",
                    str(root),
                    "--config",
                    'shell_environment_policy.inherit="none"',
                    "-",
                ]
                process_input: str | None = prompt
            else:
                command = [
                    binary,
                    "--print",
                    "--output-format",
                    "stream-json",
                    "--verbose",
                    "--include-hook-events",
                    "--tools",
                    "Write",
                    "--allowedTools",
                    "Write",
                    "--permission-mode",
                    "acceptEdits",
                    prompt,
                ]
                process_input = None
            result = run_process(
                command,
                cwd=root,
                env=environment,
                input=process_input,
                capture_output=True,
                check=False,
                text=True,
                timeout=60,
            )
        else:
            print(
                f"Provider verification: {provider.display_name} version is unavailable",
                file=sys.stderr,
            )
    except subprocess.TimeoutExpired:
        print(
            f"Provider verification: {provider.display_name} canary timed out",
            file=sys.stderr,
        )
    finally:
        for path, (existed, content, mode) in snapshots.items():
            try:
                if existed:
                    atomic_write(path, content, mode)
                elif path.exists():
                    path.unlink()
            except OSError as error:
                print(
                    f"Provider verification: failed to restore host state ({error})",
                    file=sys.stderr,
                )
                return 2

    if target.exists() or target.is_symlink():
        try:
            target.unlink()
        except OSError as error:
            print(
                f"Provider verification: canary escaped provider hook ({error})",
                file=sys.stderr,
            )
            return 2
        print(
            "Provider verification: canary escaped provider hook",
            file=sys.stderr,
        )
        return 2
    if (
        result is None
        or result.returncode != 0
        or not _provider_canary_denied(
            provider, result.stdout or "", result.stderr or ""
        )
    ):
        print("Provider verification: INCOMPLETE", file=sys.stderr)
        print(
            f"- Open {provider.display_name} in this Project, run /hooks, "
            "review and trust the two Engineering Harness hooks, then rerun "
            "verify-provider.",
            file=sys.stderr,
        )
        return 3

    verified_at = datetime.now(timezone.utc).isoformat()
    evidence = {
        "manifestChecksum": manifest["manifest_checksum"],
        "providerId": provider.id,
        "providerBinary": binary,
        "providerBinarySha256": sha256(Path(binary).read_bytes()),
        "providerVersion": version,
        "stdoutSha256": sha256((result.stdout or "").encode("utf-8")),
        "stderrSha256": sha256((result.stderr or "").encode("utf-8")),
        "verifiedAt": verified_at,
    }
    status.update(
        {
            "hookTrustVerified": True,
            "providerId": provider.id,
            "providerBinary": binary,
            "providerBinarySha256": evidence["providerBinarySha256"],
            "providerReceipt": evidence,
            "providerVersion": version,
            "verificationEvidenceSha256": canonical_digest(evidence),
            "verifiedAt": verified_at,
            "verifiedManifestChecksum": manifest["manifest_checksum"],
            "writeCanaryVerified": True,
        }
    )
    atomic_write(status_path, json_bytes(status), 0o600)
    print("Provider verification: PASS (trusted hook denial observed)")
    return run_audit(root)


def print_profile(root: Path, profile: dict[str, Any]) -> None:
    facts = profile["facts"]
    print("Repository facts")
    print(f"- target: {safe_text(root)}")
    print("- manifests: " + (", ".join(facts["manifests"]) or "none detected"))
    print(
        "- lockfiles: "
        + (", ".join(item["path"] for item in facts["lockfiles"]) or "none detected")
    )
    print("- stacks: " + (", ".join(facts["stacks"]) or "none detected"))
    print(
        f"- candidate verification commands: {len(profile['candidate_commands'])} "
        "(detected only; not executed or authorized)"
    )


def print_plan(plan: SetupPlan, *, as_json: bool = False) -> None:
    payload = {
        "conflicts": plan.conflicts,
        "mutations": [
            {
                "action": "delete" if item.content is None else "write",
                "path": item.label,
                "reason": item.reason,
            }
            for item in plan.mutations
        ],
        "preserved": plan.preserved,
        "profile": plan.profile,
        "status": "blocked" if plan.conflicts else "ready",
        "target": str(plan.root),
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print_profile(plan.root, plan.profile)
    if plan.conflicts:
        print("Setup plan: BLOCKED (no files changed)")
        for issue in plan.conflicts:
            print(f"- {safe_text(issue)}")
        return
    print(f"Setup plan: READY ({len(plan.mutations)} mutation(s))")
    for item in plan.mutations:
        verb = "delete" if item.content is None else "write"
        print(f"- {verb} {safe_text(item.label)}: {safe_text(item.reason)}")
    if plan.preserved:
        print("Preserved")
        for item in plan.preserved:
            print(f"- {safe_text(item)}")


def execute_setup(
    root: Path, command: str, provider: ProviderSpec
) -> int:
    plan = plan_setup(root, command, provider)
    if plan.conflicts:
        print_plan(plan)
        return 2
    try:
        changed = apply_transaction(
            plan.mutations,
            after_apply=lambda: secure_host_directory(plan.manifest),
        )
    except Exception as error:
        print(f"Harness {command}: ROLLED BACK ({safe_text(error)})", file=sys.stderr)
        return 2
    if changed:
        print(f"Harness {command}: {len(changed)} mutation(s) committed")
        for item in changed:
            verb = "deleted" if item.content is None else item.reason
            print(f"- {safe_text(item.label)}: {safe_text(verb)}")
    else:
        print(f"Harness {command}: already current; no files changed")
    if plan.preserved:
        print("Preserved")
        for item in plan.preserved:
            print(f"- {safe_text(item)}")
    return run_audit(root)


def uninstall_bridge(
    root: Path, manifest: dict[str, Any]
) -> tuple[Mutation | None, list[str]]:
    blocks = manifest.get("managed_blocks")
    if not isinstance(blocks, list) or len(blocks) != 1 or not isinstance(blocks[0], dict):
        return None, ["manifest managed bridge is malformed"]
    block = blocks[0]
    bridge_relative = block.get("path")
    if not isinstance(bridge_relative, str):
        return None, ["manifest managed bridge path is malformed"]
    try:
        path = project_path(root, bridge_relative)
    except ValueError as error:
        return None, [f"manifest managed bridge path is unsafe ({error})"]
    try:
        content = path.read_bytes()
        start = str(block["start"]).encode()
        end = str(block["end"]).encode()
        if content.count(start) != 1 or content.count(end) != 1:
            raise ValueError("markers must occur exactly once")
        begin = content.index(start)
        finish = content.index(end, begin) + len(end)
        if sha256(content[begin:finish]) != block.get("sha256"):
            raise ValueError("managed bridge drift")
        leading = bytes.fromhex(str(block.get("leading_hex", "")))
        trailing = bytes.fromhex(str(block.get("trailing_hex", "")))
        remove_begin = begin - len(leading)
        if remove_begin < 0 or content[remove_begin:begin] != leading:
            raise ValueError("managed leading framing drift")
        remove_finish = finish + len(trailing)
        if content[finish:remove_finish] != trailing:
            raise ValueError("managed trailing framing drift")
        remaining = content[:remove_begin] + content[remove_finish:]
    except (OSError, KeyError, ValueError) as error:
        return None, [f"{bridge_relative}: {error}"]
    if block.get("created_file") is True and not remaining:
        return Mutation(
            path,
            bridge_relative,
            None,
            0o644,
            "removed created bridge file",
        ), []
    return (
        Mutation(
            path,
            bridge_relative,
            remaining,
            file_mode(path, 0o644),
            "removed Managed Bridge",
        ),
        [],
    )


def uninstall_hooks(
    root: Path, manifest: dict[str, Any]
) -> tuple[Mutation | None, list[str]]:
    provider = manifest.get("provider_hooks")
    if not isinstance(provider, dict):
        return None, ["manifest provider hooks are malformed"]
    installed_provider = manifest_provider_id(manifest)
    if installed_provider is None:
        return None, ["manifest provider identity is not installer-owned"]
    spec = provider_spec(installed_provider)
    hooks_relative = spec.hooks_relative
    if provider.get("path") != hooks_relative:
        return None, ["manifest provider hook path is not installer-owned"]
    path = project_path(root, hooks_relative)
    data, raw, error = parse_hooks(path, hooks_relative)
    if error or raw is None:
        return None, [error or f"{hooks_relative}: missing"]
    specs = provider.get("managed_entries")
    if not isinstance(specs, list):
        return None, ["manifest managed hook list is malformed"]
    expected_specs = {
        ("PreToolUse", PRETOOL_HOOK_ID),
        ("UserPromptSubmit", PROMPT_HOOK_ID),
    }
    actual_specs = {
        (item.get("event"), item.get("id"))
        for item in specs
        if isinstance(item, dict)
    }
    if len(specs) != len(expected_specs) or actual_specs != expected_specs:
        return None, ["manifest managed hook identities are not installer-owned"]
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return None, [f"{hooks_relative}: hooks are malformed"]
    for spec in specs:
        if not isinstance(spec, dict):
            return None, ["manifest hook specification is malformed"]
        event, hook_id, expected = spec.get("event"), spec.get("id"), spec.get("sha256")
        entries = hooks.get(event)
        if not isinstance(event, str) or not isinstance(hook_id, str) or not isinstance(entries, list):
            return None, [f"{hooks_relative}: managed hook event is malformed"]
        matches = [item for item in entries if hook_matches(item, hook_id)]
        if len(matches) != 1 or canonical_digest(matches[0]) != expected:
            return None, [f"{hooks_relative}: managed {event} {hook_id} drift"]
        hooks[event] = [item for item in entries if not hook_matches(item, hook_id)]
        if not hooks[event]:
            del hooks[event]
    if not hooks:
        data.pop("hooks", None)
    if provider.get("file_created") is True and not data:
        return Mutation(
            path,
            hooks_relative,
            None,
            0o644,
            "removed created hooks file",
        ), []
    return (
        Mutation(
            path,
            hooks_relative,
            json_bytes(data),
            file_mode(path, 0o644),
            "removed hooks",
        ),
        [],
    )


def plan_uninstall(root: Path) -> SetupPlan:
    profile = inspect_repository(root)
    manifest_path = project_path(root, MANIFEST_RELATIVE)
    if not manifest_path.is_file():
        return SetupPlan(root, profile, [], [], [f"{MANIFEST_RELATIVE}: missing"], None)
    manifest, error = load_manifest(manifest_path)
    if error or manifest is None:
        return SetupPlan(root, profile, [], [], [f"{MANIFEST_RELATIVE}: {error}"], None)
    mutations: list[Mutation] = []
    conflicts: list[str] = []
    bridge, bridge_issues = uninstall_bridge(root, manifest)
    conflicts.extend(bridge_issues)
    if bridge:
        mutations.append(bridge)
    hook, hook_issues = uninstall_hooks(root, manifest)
    conflicts.extend(hook_issues)
    if hook:
        mutations.append(hook)

    expected_project_paths = {
        target for _source, target, _mode in PROJECT_ASSETS
    } | {f"{HARNESS_DIR}/repo-profile.json"}
    owned_entries = manifest.get("owned_files")
    owned_by_path = {
        entry.get("path"): entry
        for entry in owned_entries
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    } if isinstance(owned_entries, list) else {}
    if (
        not isinstance(owned_entries, list)
        or len(owned_entries) != len(expected_project_paths)
        or set(owned_by_path) != expected_project_paths
    ):
        conflicts.append("manifest project ownership set is not installer-owned")

    for label in sorted(expected_project_paths):
        entry = owned_by_path.get(label)
        if not isinstance(entry, dict):
            conflicts.append(f"{label}: manifest owned file entry is missing")
            continue
        expected = entry.get("sha256")
        if not isinstance(expected, str):
            conflicts.append("manifest owned file entry is invalid")
            continue
        path = project_path(root, label)
        try:
            if path.is_symlink() or sha256(path.read_bytes()) != expected:
                raise ValueError("missing, unsafe, or drifted")
        except (OSError, ValueError) as file_error:
            conflicts.append(f"{label}: {file_error}")
            continue
        mutations.append(Mutation(path, label, None, 0o644, "removed installer-owned file"))

    host = manifest.get("host_runtime")
    if not isinstance(host, dict):
        conflicts.append("manifest host runtime is malformed")
    else:
        _project_id, host_directory, trusted_state, trusted_status = state_locations(root)
        expected_host_paths = {
            str(host_directory.joinpath(*PurePosixPath(relative).parts))
            for _source, relative, _mode in HOST_ASSETS
        }
        host_entries = host.get("owned_files")
        host_by_path = {
            entry.get("path"): entry
            for entry in host_entries
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)
        } if isinstance(host_entries, list) else {}
        if (
            not isinstance(host_entries, list)
            or len(host_entries) != len(expected_host_paths)
            or set(host_by_path) != expected_host_paths
        ):
            conflicts.append("manifest host ownership set is not installer-owned")
        for path_value in sorted(expected_host_paths):
            entry = host_by_path.get(path_value)
            if not isinstance(entry, dict):
                conflicts.append(f"{path_value}: manifest host runtime entry is missing")
                continue
            expected = entry.get("sha256")
            if not isinstance(expected, str):
                conflicts.append("manifest host runtime entry is invalid")
                continue
            path = Path(path_value)
            try:
                if path.is_symlink() or sha256(path.read_bytes()) != expected:
                    raise ValueError("missing, unsafe, or drifted")
            except (OSError, ValueError) as file_error:
                conflicts.append(f"{path}: {file_error}")
                continue
            mutations.append(
                Mutation(path, f"host:{path.name}", None, 0o700, "removed host runtime")
            )
        for value, expected_path, label, validator in (
            (host.get("state_path"), trusted_state, "host:gate-state.json", valid_gate_state),
            (host.get("status_path"), trusted_status, "host:setup-status.json", valid_setup_status),
        ):
            if not isinstance(value, str) or Path(value) != expected_path:
                conflicts.append(f"{label}: invalid path")
                continue
            path = expected_path
            error = validator(path, root)
            if error:
                conflicts.append(f"{label}: {error}")
            else:
                mutations.append(Mutation(path, label, None, 0o600, "removed host state"))
        for name in MUTABLE_HOST_STATE_FILES:
            path = host_directory / name
            if not path.exists():
                continue
            if path.is_symlink() or not path.is_file():
                conflicts.append(f"host:{name}: unsafe mutable state")
                continue
            mutations.append(
                Mutation(
                    path,
                    f"host:{name}",
                    None,
                    0o600,
                    "removed mutable host state",
                )
            )
        official_directory = host_directory / "official-evidence"
        if official_directory.exists():
            if official_directory.is_symlink() or not official_directory.is_dir():
                conflicts.append("host:official-evidence: unsafe mutable state")
            else:
                for path in sorted(official_directory.iterdir()):
                    if (
                        path.is_symlink()
                        or not path.is_file()
                        or path.suffix not in {".bin", ".json"}
                    ):
                        conflicts.append(
                            f"host:official-evidence:{path.name}: unsafe mutable state"
                        )
                        continue
                    mutations.append(
                        Mutation(
                            path,
                            f"host:official-evidence:{path.name}",
                            None,
                            0o600,
                            "removed registered official Evidence",
                        )
                    )

    mutations.append(
        Mutation(manifest_path, MANIFEST_RELATIVE, None, 0o644, "removed ownership manifest")
    )
    if conflicts:
        mutations = []
    return SetupPlan(root, profile, mutations, [], sorted(set(conflicts)), manifest)


def execute_uninstall(root: Path) -> int:
    plan = plan_uninstall(root)
    if plan.conflicts:
        print_plan(plan)
        return 2
    try:
        changed = apply_transaction(plan.mutations)
    except Exception as error:
        print(f"Harness uninstall: ROLLED BACK ({safe_text(error)})", file=sys.stderr)
        return 2
    for directory in (
        root / HARNESS_DIR / "checks",
        root / HARNESS_DIR / "bin",
        root / HARNESS_DIR / "runtime",
        root / HARNESS_DIR / "playbooks",
        root / ".codex",
        root / ".claude",
    ):
        try:
            directory.rmdir()
        except OSError:
            pass
    if plan.manifest:
        _project_id, state_directory, _state_path, _status_path = state_locations(root)
        for directory in (
            state_directory / "runtime" / "engineering_harness_gate",
            state_directory / "runtime",
            state_directory / "official-evidence",
            state_directory,
        ):
            try:
                directory.rmdir()
            except OSError:
                pass
    print(f"Harness uninstall: {len(changed)} mutation(s) committed")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "plan",
            "install",
            "audit",
            "verify-provider",
            "repair",
            "uninstall",
        ),
        nargs="?",
        default="plan",
    )
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument(
        "--provider",
        choices=tuple(sorted(PROVIDERS)),
        help=(
            "coding-agent provider to configure; defaults to codex for "
            "plan/install/repair"
        ),
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.repo.expanduser().resolve()
    if not root.is_dir():
        print(f"error: Project is not a directory: {safe_text(root)}", file=sys.stderr)
        return 2
    if root == SKILL_ROOT:
        print("error: refusing to install into this Skill directory", file=sys.stderr)
        return 2
    try:
        selected_provider = provider_spec(
            args.provider or DEFAULT_PROVIDER_ID
        )
        if args.command == "plan":
            plan = plan_setup(root, "install", selected_provider)
            print_plan(plan, as_json=args.json)
            return 2 if plan.conflicts else 0
        if args.command == "audit":
            return run_audit(root, as_json=args.json)
        if args.command == "verify-provider":
            if args.json:
                print("error: --json is not supported for verify-provider", file=sys.stderr)
                return 2
            return verify_provider(
                root,
                provider=provider_spec(args.provider)
                if args.provider
                else None,
            )
        if args.command == "uninstall":
            return execute_uninstall(root)
        return execute_setup(root, args.command, selected_provider)
    except (OSError, ValueError) as error:
        print(f"error: {safe_text(error)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
