#!/usr/bin/env python3
# engineering-harness:installer-owned
"""Bounded, read-only repository context broker."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path

MAX_FILE_BYTES = 256 * 1024
MAX_LINES = 400
MAX_RESULTS = 100
GIT_TIMEOUT_SECONDS = 15
DENIED_PARTS = {
    ".git",
    ".hg",
    ".svn",
    ".ssh",
    ".aws",
    ".gnupg",
    ".env-store",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "__pycache__",
}
DENIED_NAMES = {
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
    "known_hosts",
}
DENIED_GLOBS = (
    ".env*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*private-key*.txt",
    "*private_key*.txt",
    "*private-key*.json",
    "*private_key*.json",
    "*private-key*.yaml",
    "*private_key*.yaml",
    "*private-key*.yml",
    "*private_key*.yml",
)
HARNESS_READABLE = (
    ".agent-harness/router.md",
    ".agent-harness/repo-profile.json",
    ".agent-harness/config.json",
    ".agent-harness/local.md",
    ".agent-harness/playbooks/*.md",
    ".agent-harness/runtime/runtime-contract.json",
)
HARNESS_TRAVERSABLE = {
    ".agent-harness",
    ".agent-harness/playbooks",
    ".agent-harness/runtime",
}
DEPENDENCY_ROOT_PARTS = {
    "node_modules",
    "site-packages",
    "dist-packages",
}
DEPENDENCY_FILE_NAMES = {
    "package.json",
    "METADATA",
    "PKG-INFO",
    "README",
    "README.md",
    "CHANGELOG",
    "CHANGELOG.md",
}
DEPENDENCY_SUFFIXES = {
    ".d.ts",
    ".pyi",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".py",
    ".rs",
}


class BrokerError(ValueError):
    pass


def is_protected(relative: Path) -> bool:
    rendered = relative.as_posix()
    if any(fnmatch.fnmatch(rendered, pattern) for pattern in HARNESS_READABLE):
        return False
    if rendered in HARNESS_TRAVERSABLE:
        return False
    if relative.parts and relative.parts[0] == ".agent-harness":
        return True
    lowered = [part.lower() for part in relative.parts]
    if any(part in DENIED_PARTS for part in lowered):
        return True
    if any(part in DENIED_NAMES for part in lowered):
        return True
    return any(
        fnmatch.fnmatch(part, pattern)
        for part in lowered
        for pattern in DENIED_GLOBS
    )


def safe_path(root: Path, value: str, *, require_file: bool = False) -> Path:
    requested = Path(value)
    if requested.is_absolute():
        raise BrokerError("absolute paths are not allowed")
    lexical = root.joinpath(requested)
    current = root
    for part in requested.parts:
        if part in {"", ".", ".."}:
            raise BrokerError("path traversal is not allowed")
        current = current / part
        if current.is_symlink():
            raise BrokerError("symlinks are not allowed")
    try:
        resolved = lexical.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise BrokerError("path is missing or outside the repository") from error
    if is_protected(relative):
        raise BrokerError("protected paths are not readable through the broker")
    if require_file and not resolved.is_file():
        raise BrokerError("path is not a regular file")
    return resolved


def safe_dependency_file(root: Path, value: str) -> Path:
    requested = Path(value)
    if (
        requested.is_absolute()
        or any(character in value for character in "\0\n\r")
        or any(
            part in {"", ".", ".."} for part in requested.parts
        )
    ):
        raise BrokerError("dependency path must be safe and project-relative")
    package_root = installed_dependency_root(root, requested)
    current = root
    for part in requested.parts:
        current = current / part
        if current.is_symlink():
            raise BrokerError("dependency paths cannot contain symlinks")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(package_root)
    except (OSError, ValueError) as error:
        raise BrokerError(
            "dependency path is missing or outside its installed package root"
        ) from error
    if not resolved.is_file():
        raise BrokerError("dependency path is not a regular file")
    name = resolved.name
    suffix_match = any(name.endswith(suffix) for suffix in DEPENDENCY_SUFFIXES)
    if name not in DEPENDENCY_FILE_NAMES and not suffix_match:
        raise BrokerError("dependency file type is not allowlisted")
    if any(
        fnmatch.fnmatch(part.lower(), pattern)
        for part in requested.parts
        for pattern in DENIED_GLOBS
    ):
        raise BrokerError("dependency path appears secret-bearing")
    return resolved


def installed_dependency_root(root: Path, requested: Path) -> Path:
    """Resolve one exact installed package root from trusted package metadata."""

    lowered = [part.lower() for part in requested.parts]
    indexes = [
        index
        for index, part in enumerate(lowered)
        if part in DEPENDENCY_ROOT_PARTS
    ]
    if not indexes:
        raise BrokerError("dependency path is not in an installed package root")
    boundary = indexes[-1]
    if boundary + 1 >= len(requested.parts):
        raise BrokerError("dependency path does not name an installed package")

    installation_root = root.joinpath(*requested.parts[: boundary + 1])
    root_name = lowered[boundary]
    if root_name == "node_modules":
        package_parts = [requested.parts[boundary + 1]]
        if package_parts[0].startswith("@"):
            if boundary + 2 >= len(requested.parts):
                raise BrokerError("scoped dependency path is incomplete")
            package_parts.append(requested.parts[boundary + 2])
        package_root = installation_root.joinpath(*package_parts)
        reject_dependency_symlinks(root, package_root)
        metadata_path = package_root / "package.json"
        metadata = dependency_metadata_json(metadata_path)
        expected_name = "/".join(package_parts)
        if (
            not isinstance(metadata.get("name"), str)
            or metadata["name"].casefold() != expected_name.casefold()
            or not isinstance(metadata.get("version"), str)
            or not metadata["version"].strip()
        ):
            raise BrokerError(
                "dependency package.json does not identify the installed package"
            )
    else:
        top_level = requested.parts[boundary + 1]
        top_level_path = installation_root / top_level
        reject_dependency_symlinks(root, top_level_path)
        package_root = (
            installation_root
            if top_level_path.is_file()
            else top_level_path
        )
        metadata_path = python_distribution_metadata(
            installation_root, top_level
        )
        dependency_metadata_headers(metadata_path)

    try:
        resolved_root = package_root.resolve(strict=True)
        resolved_root.relative_to(root)
    except (OSError, ValueError) as error:
        raise BrokerError(
            "installed package root is missing or outside the repository"
        ) from error
    if not resolved_root.is_dir():
        raise BrokerError("installed package root is not a directory")
    return resolved_root


def reject_dependency_symlinks(root: Path, target: Path) -> None:
    current = root
    try:
        parts = target.relative_to(root).parts
    except ValueError as error:
        raise BrokerError(
            "installed package root is outside the repository"
        ) from error
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise BrokerError("installed package roots cannot contain symlinks")


def dependency_metadata_json(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise BrokerError("installed package metadata is unavailable")
    try:
        value = json.loads(bounded_text(path))
    except json.JSONDecodeError as error:
        raise BrokerError("installed package metadata is invalid JSON") from error
    if not isinstance(value, dict):
        raise BrokerError("installed package metadata must be an object")
    return value


def dependency_metadata_headers(path: Path) -> tuple[str, str]:
    if path.is_symlink() or not path.is_file():
        raise BrokerError("installed distribution metadata is unavailable")
    name: str | None = None
    version: str | None = None
    for line in bounded_text(path).splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        if key.casefold() == "name":
            name = value.strip()
        elif key.casefold() == "version":
            version = value.strip()
        if name and version:
            return name, version
    raise BrokerError(
        "installed distribution metadata lacks exact name and version"
    )


def python_distribution_metadata(
    installation_root: Path, top_level: str
) -> Path:
    if top_level.endswith((".dist-info", ".egg-info")):
        directory = installation_root / top_level
        for name in ("METADATA", "PKG-INFO"):
            candidate = directory / name
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
        raise BrokerError("installed distribution metadata is unavailable")

    module_name = Path(top_level).stem.casefold()
    candidates: list[Path] = []
    try:
        children = sorted(installation_root.iterdir(), key=lambda item: item.name)
    except OSError as error:
        raise BrokerError("installed package directory is unreadable") from error
    for child in children:
        if (
            child.is_symlink()
            or not child.is_dir()
            or not child.name.endswith((".dist-info", ".egg-info"))
        ):
            continue
        metadata = next(
            (
                child / name
                for name in ("METADATA", "PKG-INFO")
                if (child / name).is_file() and not (child / name).is_symlink()
            ),
            None,
        )
        if metadata is None:
            continue
        try:
            distribution_name, _version = dependency_metadata_headers(
                metadata
            )
        except BrokerError:
            continue
        normalized = re.sub(r"[-_.]+", "-", distribution_name).casefold()
        normalized_module = re.sub(r"[-_.]+", "-", module_name).casefold()
        top_level_path = child / "top_level.txt"
        declared_modules: set[str] = set()
        if top_level_path.is_file() and not top_level_path.is_symlink():
            declared_modules = {
                line.strip().casefold()
                for line in bounded_text(top_level_path).splitlines()
                if line.strip()
            }
        if module_name in declared_modules or normalized == normalized_module:
            candidates.append(metadata)
    if len(candidates) != 1:
        raise BrokerError(
            "dependency path is not bound to one exact installed distribution"
        )
    return candidates[0]


def iter_files(root: Path, start: Path, glob_pattern: str) -> list[Path]:
    results: list[Path] = []
    for directory, names, filenames in os.walk(start, followlinks=False):
        base = Path(directory)
        kept_directories: list[str] = []
        for name in sorted(names):
            candidate = base / name
            try:
                relative = candidate.relative_to(root)
            except ValueError:
                continue
            if candidate.is_symlink() or is_protected(relative):
                continue
            kept_directories.append(name)
        names[:] = kept_directories
        for name in sorted(filenames):
            candidate = base / name
            try:
                relative = candidate.relative_to(root)
            except ValueError:
                continue
            if candidate.is_symlink() or is_protected(relative):
                continue
            if not fnmatch.fnmatch(relative.as_posix(), glob_pattern):
                continue
            results.append(candidate)
            if len(results) >= MAX_RESULTS:
                return results
    return results


def bounded_text(path: Path) -> str:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise BrokerError(f"file exceeds {MAX_FILE_BYTES} bytes")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeError as error:
        raise BrokerError("file is not UTF-8 text") from error


def command_map(args: argparse.Namespace, root: Path) -> int:
    start = safe_path(root, args.path)
    if not start.is_dir():
        raise BrokerError("map path must be a directory")
    for path in iter_files(root, start, args.glob):
        print(path.relative_to(root).as_posix())
    return 0


def command_read(args: argparse.Namespace, root: Path) -> int:
    path = safe_path(root, args.path, require_file=True)
    text = bounded_text(path)
    lines = text.splitlines()
    start = args.start
    count = min(args.lines, MAX_LINES)
    if start < 1:
        raise BrokerError("--start must be at least 1")
    for number, line in enumerate(lines[start - 1 : start - 1 + count], start=start):
        print(f"{number:>6}  {line[:2000]}")
    return 0


def command_search(args: argparse.Namespace, root: Path) -> int:
    start = safe_path(root, args.path)
    files = [start] if start.is_file() else iter_files(root, start, args.glob)
    try:
        pattern = re.compile(args.pattern if args.regex else re.escape(args.pattern))
    except re.error as error:
        raise BrokerError(f"invalid regular expression: {error}") from error
    hits = 0
    for path in files:
        try:
            text = bounded_text(path)
        except (OSError, BrokerError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                print(f"{path.relative_to(root).as_posix()}:{number}:{line[:1600]}")
                hits += 1
                if hits >= min(args.limit, MAX_RESULTS):
                    return 0
    return 0


def command_facts(_args: argparse.Namespace, root: Path) -> int:
    profile = safe_path(
        root, ".agent-harness/repo-profile.json", require_file=True
    )
    value = bounded_text(profile)
    print(value, end="" if value.endswith("\n") else "\n")
    return 0


def command_dependency_read(args: argparse.Namespace, root: Path) -> int:
    path = safe_dependency_file(root, args.path)
    text = bounded_text(path)
    lines = text.splitlines()
    start = args.start
    if start < 1:
        raise BrokerError("--start must be at least 1")
    if args.lines < 1:
        raise BrokerError("--lines must be at least 1")
    count = min(args.lines, MAX_LINES)
    for number, line in enumerate(
        lines[start - 1 : start - 1 + count], start=start
    ):
        print(f"{number:>6}  {line[:2000]}")
    return 0


def command_dependency_search(args: argparse.Namespace, root: Path) -> int:
    if (
        not args.pattern
        or len(args.pattern) > 256
        or any(character in args.pattern for character in "\0\n\r")
    ):
        raise BrokerError("dependency search pattern is empty or unsafe")
    path = safe_dependency_file(root, args.path)
    text = bounded_text(path)
    limit = min(args.limit, MAX_RESULTS)
    if limit < 1:
        raise BrokerError("--limit must be at least 1")
    hits = 0
    for number, line in enumerate(text.splitlines(), start=1):
        if args.pattern in line:
            print(f"{path.relative_to(root).as_posix()}:{number}:{line[:1600]}")
            hits += 1
            if hits >= limit:
                break
    return 0


def safe_git_relative(root: Path, value: str) -> Path:
    """Validate a Git-reported path without requiring a deleted path to exist."""

    requested = Path(value)
    if requested.is_absolute() or any(
        part in {"", ".", ".."} for part in requested.parts
    ):
        raise BrokerError("Git reported an unsafe path")
    if is_protected(requested):
        raise BrokerError("Git path is protected")

    current = root
    for part in requested.parts:
        current = current / part
        if current.is_symlink():
            raise BrokerError("Git path traverses a symlink")
        if not current.exists():
            break
    if current.exists():
        try:
            resolved = current.resolve(strict=True)
            resolved_relative = resolved.relative_to(root)
        except (OSError, ValueError) as error:
            raise BrokerError("Git path resolves outside the repository") from error
        if is_protected(resolved_relative):
            raise BrokerError("Git path resolves to a protected path")
    return requested


def run_git_bytes(
    prefix: list[str],
    arguments: list[str],
    environment: dict[str, str],
) -> bytes:
    try:
        completed = subprocess.run(
            [*prefix, *arguments],
            capture_output=True,
            check=False,
            env=environment,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise BrokerError("Git inspection timed out") from error
    if completed.returncode:
        message = completed.stderr[:4000].decode("utf-8", errors="replace")
        raise BrokerError(f"Git inspection failed: {message.strip()}")
    return completed.stdout


def decode_git_paths(payload: bytes) -> list[str]:
    values = payload.split(b"\0")
    if values and values[-1] == b"":
        values.pop()
    paths = [os.fsdecode(value) for value in values]
    if len(paths) > MAX_RESULTS:
        raise BrokerError(f"Git result exceeds {MAX_RESULTS} paths")
    return paths


def filtered_diff_paths(
    root: Path,
    prefix: list[str],
    environment: dict[str, str],
    *,
    cached: bool,
) -> list[Path]:
    arguments = [
        "diff",
        "--name-only",
        "-z",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=all",
    ]
    if cached:
        arguments.append("--cached")
    reported = decode_git_paths(run_git_bytes(prefix, arguments, environment))
    return [
        safe_git_relative(root, value)
        for value in reported
        if not is_protected(Path(value))
    ]


def filtered_status_lines(
    root: Path,
    prefix: list[str],
    environment: dict[str, str],
) -> list[str]:
    payload = run_git_bytes(
        prefix,
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=all",
        ],
        environment,
    )
    records = payload.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    lines: list[str] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if len(record) < 4 or record[2:3] != b" ":
            raise BrokerError("Git returned malformed porcelain output")
        status = record[:2].decode("ascii", errors="strict")
        paths = [os.fsdecode(record[3:])]
        if "R" in status or "C" in status:
            if index >= len(records):
                raise BrokerError("Git returned an incomplete rename record")
            paths.append(os.fsdecode(records[index]))
            index += 1
        if any(is_protected(Path(value)) for value in paths):
            continue
        validated = [safe_git_relative(root, value) for value in paths]
        rendered = " -> ".join(
            json.dumps(path.as_posix(), ensure_ascii=True) for path in validated
        )
        lines.append(f"{status} {rendered}")
        if len(lines) > MAX_RESULTS:
            raise BrokerError(f"Git result exceeds {MAX_RESULTS} paths")
    return lines


def command_git(args: argparse.Namespace, root: Path) -> int:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_PAGER"] = "cat"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_ATTR_NOSYSTEM"] = "1"
    prefix = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "--no-optional-locks",
        "-C",
        str(root),
    ]
    if args.command == "git-status":
        for line in filtered_status_lines(root, prefix, environment):
            print(line)
        return 0

    changed_paths = filtered_diff_paths(
        root,
        prefix,
        environment,
        cached=args.cached,
    )
    if args.paths:
        requested = {
            safe_git_relative(root, value).as_posix() for value in args.paths
        }
        changed_paths = [
            path for path in changed_paths if path.as_posix() in requested
        ]
    if not changed_paths:
        return 0
    command = [
            *prefix,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--ignore-submodules=all",
    ]
    if args.cached:
        command.append("--cached")
    command.append("--")
    command.extend(path.as_posix() for path in changed_paths)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            env=environment,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise BrokerError("Git diff timed out") from error
    output = completed.stdout[:MAX_FILE_BYTES].decode("utf-8", errors="replace")
    print(output, end="" if not output or output.endswith("\n") else "\n")
    if completed.returncode:
        error_output = completed.stderr[:4000].decode(
            "utf-8", errors="replace"
        )
        print(
            error_output,
            end="" if error_output.endswith("\n") else "\n",
            file=sys.stderr,
        )
    return completed.returncode


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)

    map_parser = subparsers.add_parser("map")
    map_parser.add_argument("--path", default=".")
    map_parser.add_argument("--glob", default="*")

    read_parser = subparsers.add_parser("read")
    read_parser.add_argument("path")
    read_parser.add_argument("--start", type=int, default=1)
    read_parser.add_argument("--lines", type=int, default=200)

    search_parser = subparsers.add_parser("search")
    search_parser.add_argument("pattern")
    search_parser.add_argument("--path", default=".")
    search_parser.add_argument("--glob", default="*")
    search_parser.add_argument("--limit", type=int, default=50)
    search_parser.add_argument("--regex", action="store_true")

    subparsers.add_parser("facts")
    dependency = subparsers.add_parser("dependency-read")
    dependency.add_argument("path")
    dependency.add_argument("--start", type=int, default=1)
    dependency.add_argument("--lines", type=int, default=200)
    dependency_search = subparsers.add_parser("dependency-search")
    dependency_search.add_argument("path")
    dependency_search.add_argument("pattern")
    dependency_search.add_argument("--limit", type=int, default=50)
    subparsers.add_parser("git-status")
    diff_parser = subparsers.add_parser("git-diff")
    diff_parser.add_argument("--cached", action="store_true")
    diff_parser.add_argument("paths", nargs="*")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        root = Path(__file__).resolve(strict=True).parents[2]
        if not root.is_dir():
            raise BrokerError("repository root is not a directory")
        if args.command == "map":
            return command_map(args, root)
        if args.command == "read":
            return command_read(args, root)
        if args.command == "search":
            return command_search(args, root)
        if args.command == "facts":
            return command_facts(args, root)
        if args.command == "dependency-read":
            return command_dependency_read(args, root)
        if args.command == "dependency-search":
            return command_dependency_search(args, root)
        return command_git(args, root)
    except (OSError, BrokerError) as error:
        print(f"context broker: denied ({error})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
