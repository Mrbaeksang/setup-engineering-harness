from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from .model import (
    METRIC_APPLICABILITY_KEYS,
    ArtifactValidationError,
    RunArtifact,
    TokenUsage,
)


@dataclass(frozen=True, slots=True)
class VariantSpec:
    name: str
    configuration: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    scenario_id: str
    prompt: str
    fixture_path: Path | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RunRequest:
    variant: VariantSpec
    scenario: ScenarioSpec
    repetition: int


@dataclass(frozen=True, slots=True)
class RawRunObservation:
    """Provider-neutral observations captured without agent-supplied facts.

    A live adapter may record the agent's final text and tool output as untrusted
    observations. It MUST NOT ask the agent for metric scores or accept an
    agent-produced ``facts`` object. Trusted facts are derived later by an
    ObservationProjector using a ScenarioOracle.
    """

    run_id: str
    variant: str
    scenario_id: str
    repetition: int
    final_text: str | None = None
    tool_calls: tuple[Mapping[str, Any], ...] = ()
    changed_paths: tuple[str, ...] = ()
    diff_stats: Mapping[str, Any] | None = None
    command_evidence: tuple[Mapping[str, Any], ...] = ()
    hook_denials: tuple[Mapping[str, Any], ...] = ()
    duration_ms: int | None = None
    token_usage: TokenUsage | None = None
    exit_status: int | None = None
    context_bytes: Mapping[str, Any] | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> RawRunObservation:
        """Load only unprojected observations; executable facts are forbidden."""

        if not isinstance(data, Mapping):
            raise ArtifactValidationError("raw observation must be an object")
        allowed = {
            "artifact_kind",
            "schema_version",
            "run_id",
            "variant",
            "scenario_id",
            "repetition",
            "final_text",
            "tool_calls",
            "changed_paths",
            "diff_stats",
            "command_evidence",
            "hook_denials",
            "duration_ms",
            "token_usage",
            "exit_status",
            "context_bytes",
            "metadata",
        }
        extra = set(data) - allowed
        if extra:
            raise ArtifactValidationError(
                "raw observation contains untrusted fields: "
                + ", ".join(sorted(map(str, extra)))
            )
        if data.get("artifact_kind") != "raw-run-observation":
            raise ArtifactValidationError(
                "'artifact_kind' must be 'raw-run-observation'"
            )
        if data.get("schema_version") != 1:
            raise ArtifactValidationError("unsupported raw observation schema")

        def required_string(key: str) -> str:
            value = data.get(key)
            if not isinstance(value, str) or not value:
                raise ArtifactValidationError(
                    f"{key!r} must be a non-empty string"
                )
            return value

        repetition = data.get("repetition")
        if (
            isinstance(repetition, bool)
            or not isinstance(repetition, int)
            or repetition < 1
        ):
            raise ArtifactValidationError("'repetition' must be an integer >= 1")

        def mappings(key: str) -> tuple[Mapping[str, Any], ...]:
            value = data.get(key, [])
            if not isinstance(value, list) or any(
                not isinstance(item, Mapping) for item in value
            ):
                raise ArtifactValidationError(f"{key!r} must be an object array")
            return tuple(dict(item) for item in value)

        changed = data.get("changed_paths", [])
        if not isinstance(changed, list) or any(
            not isinstance(item, str) or not item for item in changed
        ):
            raise ArtifactValidationError(
                "'changed_paths' must be a string array"
            )
        final_text = data.get("final_text")
        if final_text is not None and not isinstance(final_text, str):
            raise ArtifactValidationError("'final_text' must be a string")
        duration = data.get("duration_ms")
        if duration is not None and (
            isinstance(duration, bool)
            or not isinstance(duration, int)
            or duration < 0
        ):
            raise ArtifactValidationError(
                "'duration_ms' must be a non-negative integer"
            )
        exit_status = data.get("exit_status")
        if exit_status is not None and (
            isinstance(exit_status, bool) or not isinstance(exit_status, int)
        ):
            raise ArtifactValidationError("'exit_status' must be an integer")
        diff_stats = data.get("diff_stats")
        context_bytes = data.get("context_bytes")
        metadata = data.get("metadata", {})
        for key, value in (
            ("diff_stats", diff_stats),
            ("context_bytes", context_bytes),
            ("metadata", metadata),
        ):
            if value is not None and not isinstance(value, Mapping):
                raise ArtifactValidationError(f"{key!r} must be an object")
        return cls(
            run_id=required_string("run_id"),
            variant=required_string("variant"),
            scenario_id=required_string("scenario_id"),
            repetition=repetition,
            final_text=final_text,
            tool_calls=mappings("tool_calls"),
            changed_paths=tuple(changed),
            diff_stats=dict(diff_stats) if diff_stats is not None else None,
            command_evidence=mappings("command_evidence"),
            hook_denials=mappings("hook_denials"),
            duration_ms=duration,
            token_usage=TokenUsage.from_mapping(data.get("token_usage")),
            exit_status=exit_status,
            context_bytes=(
                dict(context_bytes) if context_bytes is not None else None
            ),
            metadata=dict(metadata),
        )

    def to_mapping(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "artifact_kind": "raw-run-observation",
            "schema_version": 1,
            "run_id": self.run_id,
            "variant": self.variant,
            "scenario_id": self.scenario_id,
            "repetition": self.repetition,
            "final_text": self.final_text,
            "tool_calls": [dict(item) for item in self.tool_calls],
            "changed_paths": list(self.changed_paths),
            "command_evidence": [
                dict(item) for item in self.command_evidence
            ],
            "hook_denials": [dict(item) for item in self.hook_denials],
            "metadata": dict(self.metadata),
        }
        if self.diff_stats is not None:
            value["diff_stats"] = dict(self.diff_stats)
        if self.duration_ms is not None:
            value["duration_ms"] = self.duration_ms
        if self.token_usage is not None:
            value["token_usage"] = self.token_usage.to_dict()
        if self.exit_status is not None:
            value["exit_status"] = self.exit_status
        if self.context_bytes is not None:
            value["context_bytes"] = dict(self.context_bytes)
        return value


class ObservationRunner(Protocol):
    """Port implemented by a live provider adapter.

    The provider process boundary ends at RawRunObservation. In particular,
    implementations must never forward agent self-evaluations as benchmark
    facts.
    """

    def run(self, request: RunRequest) -> RawRunObservation:
        ...


class ScenarioOracle(Protocol):
    """Trusted, scenario-owned definition and deterministic fact projection."""

    def expectations_for(self, scenario: ScenarioSpec) -> Mapping[str, Any]:
        ...

    def project(
        self,
        observation: RawRunObservation,
        expectations: Mapping[str, Any],
    ) -> Mapping[str, Mapping[str, Any]]:
        ...


class ObservationProjector(Protocol):
    """Deprecated shape retained for import compatibility.

    ``execute_matrix`` only accepts this projector when it is the exact same
    object as the trusted ScenarioOracle. A runner-side or caller-selected
    projector is not an authority for benchmark facts.
    """

    def project(
        self,
        observation: RawRunObservation,
        expectations: Mapping[str, Any],
    ) -> Mapping[str, Mapping[str, Any]]:
        ...


def _scenario_metric_applicability(
    expectations: Mapping[str, Any],
) -> dict[str, bool]:
    explicit = expectations.get("metric_applicability")
    if explicit is not None:
        if not isinstance(explicit, Mapping):
            raise ArtifactValidationError(
                "'metric_applicability' in the scenario definition must be an object"
            )
        return {str(key): value for key, value in explicit.items()}

    applicability = {key: True for key in METRIC_APPLICABILITY_KEYS}
    dependency_applicable = expectations.get("dependency_applicable", True)
    if type(dependency_applicable) is not bool:
        raise ArtifactValidationError(
            "'dependency_applicable' in the scenario definition must be boolean"
        )
    applicability["exact_version_evidence"] = dependency_applicable
    applicability["native_capability_preference"] = dependency_applicable
    return applicability


def project_observation(
    observation: RawRunObservation,
    oracle: ScenarioOracle,
    expectations: Mapping[str, Any],
) -> RunArtifact:
    """Turn one raw observation into a scoreable artifact at the trust boundary."""

    if not isinstance(observation, RawRunObservation):
        raise TypeError("only RawRunObservation can be projected")
    if not isinstance(expectations, Mapping):
        raise TypeError("trusted scenario expectations must be an object")
    project = getattr(oracle, "project", None)
    if not callable(project):
        raise TypeError(
            "trusted scenario oracle must own the observation projector"
        )
    facts = project(observation, expectations)
    if not isinstance(facts, Mapping):
        raise TypeError("trusted scenario oracle must project a facts object")
    applicability = _scenario_metric_applicability(expectations)
    oracle_type = type(oracle)
    projection_source = (
        f"{oracle_type.__module__}.{oracle_type.__qualname__}"
    )
    scenario_definition = {
        "scenario_id": observation.scenario_id,
        "expectations": dict(expectations),
        "metric_applicability": applicability,
    }
    return RunArtifact._from_trusted_projection(
        {
            **observation.to_mapping(),
            "facts": facts,
            "metric_applicability": applicability,
        },
        scenario_definition=scenario_definition,
        projection_source=projection_source,
    )


def execute_matrix(
    runner: ObservationRunner,
    projector: ObservationProjector,
    oracle: ScenarioOracle,
    *,
    variants: Sequence[VariantSpec],
    scenarios: Sequence[ScenarioSpec],
    repetitions: int,
) -> list[RunArtifact]:
    """Execute and project a balanced variant × scenario × repetition matrix."""

    if not variants:
        raise ValueError("at least one variant is required")
    if not scenarios:
        raise ValueError("at least one scenario is required")
    if repetitions < 1:
        raise ValueError("repetitions must be >= 1")
    variant_names = [variant.name for variant in variants]
    if len(variant_names) != len(set(variant_names)):
        raise ValueError("variant names must be unique")
    scenario_ids = [scenario.scenario_id for scenario in scenarios]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ValueError("scenario ids must be unique")
    if projector is not oracle:
        raise TypeError(
            "the observation projector must be owned by the trusted scenario "
            "oracle (pass the same object for both arguments)"
        )

    artifacts: list[RunArtifact] = []
    for scenario in scenarios:
        expectations = oracle.expectations_for(scenario)
        if not isinstance(expectations, Mapping):
            raise TypeError("trusted scenario expectations must be an object")
        for repetition in range(1, repetitions + 1):
            for variant in variants:
                request = RunRequest(variant, scenario, repetition)
                observation = runner.run(request)
                if not isinstance(observation, RawRunObservation):
                    raise TypeError(
                        "live runners must return RawRunObservation; "
                        "RunArtifact/facts may only come from the trusted projector"
                    )
                if observation.variant != variant.name:
                    raise ValueError(
                        f"runner returned variant {observation.variant!r}; "
                        f"expected {variant.name!r}"
                    )
                if observation.scenario_id != scenario.scenario_id:
                    raise ValueError(
                        f"runner returned scenario {observation.scenario_id!r}; "
                        f"expected {scenario.scenario_id!r}"
                    )
                if observation.repetition != repetition:
                    raise ValueError(
                        f"runner returned repetition {observation.repetition}; "
                        f"expected {repetition}"
                    )
                artifacts.append(
                    project_observation(observation, oracle, expectations)
                )
    return artifacts
