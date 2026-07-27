"""Deterministic benchmark engine for Engineering Harness run artifacts."""

from .engine import BenchmarkEngine, BenchmarkReport
from .io import load_artifacts
from .model import RunArtifact, TokenUsage
from .runner import (
    ObservationProjector,
    ObservationRunner,
    RawRunObservation,
    RunRequest,
    ScenarioOracle,
    ScenarioSpec,
    VariantSpec,
    execute_matrix,
)
from .scoring import METRIC_KEYS, RunScore, score_run

__all__ = [
    "BenchmarkEngine",
    "BenchmarkReport",
    "METRIC_KEYS",
    "ObservationProjector",
    "ObservationRunner",
    "RawRunObservation",
    "RunArtifact",
    "RunRequest",
    "RunScore",
    "ScenarioOracle",
    "ScenarioSpec",
    "TokenUsage",
    "VariantSpec",
    "execute_matrix",
    "load_artifacts",
    "score_run",
]
