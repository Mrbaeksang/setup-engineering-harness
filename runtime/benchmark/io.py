from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .model import (
    METRIC_APPLICABILITY_KEYS,
    ArtifactValidationError,
    RunArtifact,
)


class ArtifactLoadError(ValueError):
    """Raised when a replay artifact file cannot be imported."""


def _objects_from_json(value: Any, source: Path) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and "runs" in value:
        runs = value["runs"]
        if not isinstance(runs, list):
            raise ArtifactLoadError(f"{source}: 'runs' must be an array")
        return runs
    if isinstance(value, dict):
        return [value]
    raise ArtifactLoadError(f"{source}: expected an object, array, or {{'runs': []}}")


def _load_file(
    path: Path, *, trust_test_synthetic_projection: bool = False
) -> list[RunArtifact]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ArtifactLoadError(f"{path}: {error}") from error

    try:
        if path.suffix.lower() == ".jsonl":
            objects = [
                json.loads(line)
                for line in text.splitlines()
                if line.strip()
            ]
        else:
            objects = _objects_from_json(json.loads(text), path)
    except json.JSONDecodeError as error:
        raise ArtifactLoadError(
            f"{path}:{error.lineno}:{error.colno}: invalid JSON: {error.msg}"
        ) from error

    artifacts: list[RunArtifact] = []
    for index, value in enumerate(objects):
        try:
            if trust_test_synthetic_projection:
                if not isinstance(value, dict):
                    raise ArtifactValidationError(
                        "synthetic fixture run must be an object"
                    )
                metadata = value.get("metadata")
                if (
                    not isinstance(metadata, dict)
                    or metadata.get("evidence_kind") != "synthetic"
                ):
                    raise ArtifactValidationError(
                        "test-only projected loader accepts only explicitly "
                        "synthetic fixtures"
                    )
                projected = dict(value)
                projected.setdefault(
                    "metric_applicability",
                    {
                        key: True
                        for key in METRIC_APPLICABILITY_KEYS
                    },
                )
                artifacts.append(
                    RunArtifact._from_trusted_projection(
                        projected,
                        scenario_definition={
                            "scenario_id": projected.get("scenario_id"),
                            "fixture_kind": "synthetic",
                            "metric_applicability": projected[
                                "metric_applicability"
                            ],
                        },
                        projection_source=(
                            "test-only-synthetic-unattested"
                        ),
                    )
                )
            else:
                artifacts.append(RunArtifact.from_mapping(value))
        except ArtifactValidationError as error:
            raise ArtifactLoadError(f"{path}[{index}]: {error}") from error
    return artifacts


def _artifact_files(paths: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            files.extend(
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file()
                and candidate.suffix.lower() in {".json", ".jsonl"}
            )
        elif path.is_file():
            files.append(path)
        else:
            raise ArtifactLoadError(f"{path}: path does not exist")
    return sorted(set(files))


def load_artifacts(*paths: str | Path) -> list[RunArtifact]:
    """Fail closed on serialized projected facts.

    A scoreable RunArtifact must be created from a RawRunObservation by a
    trusted scenario oracle in the current process. A JSON projection has no
    host attestation, so accepting its ``facts`` would make the file author the
    benchmark judge.
    """

    if not paths:
        raise ArtifactLoadError("at least one artifact path is required")
    files = _artifact_files(paths)
    if not files:
        raise ArtifactLoadError("no .json or .jsonl artifact files found")
    artifacts = [
        artifact
        for path in files
        for artifact in _load_file(path)
    ]
    run_ids = [artifact.run_id for artifact in artifacts]
    if len(run_ids) != len(set(run_ids)):
        raise ArtifactLoadError("run_id values must be unique across imported files")
    return artifacts


def _load_trusted_synthetic_fixtures_for_test(
    *paths: str | Path,
) -> list[RunArtifact]:
    """Load repository-owned synthetic examples for deterministic unit tests.

    This deliberately private escape hatch does not make the projections
    empirical or attested. Production replay and the default CLI must use
    ``load_artifacts`` and therefore reject these preprojected facts.
    """

    if not paths:
        raise ArtifactLoadError("at least one artifact path is required")
    files = _artifact_files(paths)
    if not files:
        raise ArtifactLoadError("no .json or .jsonl artifact files found")
    artifacts = [
        artifact
        for path in files
        for artifact in _load_file(
            path, trust_test_synthetic_projection=True
        )
    ]
    run_ids = [artifact.run_id for artifact in artifacts]
    if len(run_ids) != len(set(run_ids)):
        raise ArtifactLoadError(
            "run_id values must be unique across imported files"
        )
    return artifacts
