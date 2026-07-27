from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from types import MappingProxyType
from typing import Any, Mapping


class ArtifactValidationError(ValueError):
    """Raised when an imported run artifact is not observable benchmark input."""


FACT_SECTIONS = frozenset(
    {
        "requirements",
        "dependency",
        "scope",
        "verification",
        "context",
        "gate",
        "documentation",
        "architecture",
    }
)

METRIC_APPLICABILITY_KEYS = frozenset(
    {
        "requirements_discipline",
        "exact_version_evidence",
        "native_capability_preference",
        "scope_control",
        "verification_proof",
        "context_efficiency",
        "write_gate_enforcement",
        "documentation_hygiene",
        "architecture_proportionality",
    }
)

_SELF_REPORTED_SCORE_KEYS = frozenset(
    {
        "score",
        "scores",
        "rating",
        "ratings",
        "grade",
        "grades",
        "metric_score",
        "metric_scores",
        "self_reported_score",
        "self_reported_scores",
    }
)


def _reject_self_reported_scores(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in _SELF_REPORTED_SCORE_KEYS:
                raise ArtifactValidationError(
                    f"{path}.{key}: self-reported scores are not benchmark facts"
                )
            _reject_self_reported_scores(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_self_reported_scores(nested, f"{path}[{index}]")


def _required_string(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ArtifactValidationError(f"{key!r} must be a non-empty string")
    return value.strip()


def _optional_non_negative_int(
    data: Mapping[str, Any], key: str
) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ArtifactValidationError(f"{key!r} must be a non-negative integer")
    return value


def _optional_string(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ArtifactValidationError(f"{key!r} must be a string")
    return value


def _string_tuple(data: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ArtifactValidationError(
            f"{key!r} must be an array of non-empty strings"
        )
    return tuple(value)


def _mapping_tuple(
    data: Mapping[str, Any], key: str
) -> tuple[Mapping[str, Any], ...]:
    value = data.get(key, [])
    if not isinstance(value, list) or any(
        not isinstance(item, Mapping) for item in value
    ):
        raise ArtifactValidationError(f"{key!r} must be an array of objects")
    return tuple(dict(item) for item in value)


def _optional_mapping(
    data: Mapping[str, Any], key: str
) -> Mapping[str, Any] | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ArtifactValidationError(f"{key!r} must be an object")
    return dict(value)


def _deep_freeze(value: Any, path: str = "$") -> Any:
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ArtifactValidationError(
                    f"{path}: object keys must be strings"
                )
            frozen[key] = _deep_freeze(nested, f"{path}.{key}")
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(
            _deep_freeze(nested, f"{path}[{index}]")
            for index, nested in enumerate(value)
        )
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise ArtifactValidationError(
        f"{path}: unsupported projected value {type(value).__name__}"
    )


def _deep_thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _deep_thaw(nested) for key, nested in value.items()}
    if isinstance(value, tuple):
        return [_deep_thaw(nested) for nested in value]
    return value


def _digest(value: Any) -> str:
    encoded = json.dumps(
        _deep_thaw(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_metric_applicability(
    value: Any,
) -> Mapping[str, bool]:
    if not isinstance(value, Mapping):
        raise ArtifactValidationError(
            "'metric_applicability' must be an object owned by the scenario oracle"
        )
    missing = METRIC_APPLICABILITY_KEYS.difference(value)
    extra = set(value).difference(METRIC_APPLICABILITY_KEYS)
    if missing:
        raise ArtifactValidationError(
            "'metric_applicability' is missing metrics: "
            + ", ".join(sorted(missing))
        )
    if extra:
        raise ArtifactValidationError(
            "'metric_applicability' has unknown metrics: "
            + ", ".join(sorted(extra))
        )
    if any(type(value[key]) is not bool for key in METRIC_APPLICABILITY_KEYS):
        raise ArtifactValidationError(
            "'metric_applicability' values must be booleans"
        )
    return MappingProxyType(
        {
            key: bool(value[key])
            for key in sorted(METRIC_APPLICABILITY_KEYS)
        }
    )


def _normalize_facts(value: Any) -> Mapping[str, Mapping[str, Any]]:
    if not isinstance(value, Mapping):
        raise ArtifactValidationError("'facts' must be an object")
    missing = FACT_SECTIONS.difference(value)
    extra = set(value).difference(FACT_SECTIONS)
    if missing:
        raise ArtifactValidationError(
            "'facts' is missing sections: " + ", ".join(sorted(missing))
        )
    if extra:
        raise ArtifactValidationError(
            "'facts' has unknown sections: " + ", ".join(sorted(extra))
        )
    normalized: dict[str, Mapping[str, Any]] = {}
    for section in sorted(FACT_SECTIONS):
        section_value = value[section]
        if not isinstance(section_value, Mapping):
            raise ArtifactValidationError(
                f"'facts.{section}' must be an object"
            )
        if "applicable" in section_value:
            raise ArtifactValidationError(
                f"'facts.{section}.applicable' is forbidden; metric "
                "applicability belongs to the trusted scenario oracle"
            )
        normalized[section] = _deep_freeze(
            section_value, f"$.facts.{section}"
        )
    return MappingProxyType(normalized)


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> TokenUsage | None:
        if data is None:
            return None
        if not isinstance(data, Mapping):
            raise ArtifactValidationError("'token_usage' must be an object")
        input_tokens = _optional_non_negative_int(data, "input_tokens")
        output_tokens = _optional_non_negative_int(data, "output_tokens")
        total_tokens = _optional_non_negative_int(data, "total_tokens")
        if total_tokens is None and input_tokens is not None and output_tokens is not None:
            total_tokens = input_tokens + output_tokens
        if input_tokens is None and output_tokens is None and total_tokens is None:
            return None
        return cls(input_tokens, output_tokens, total_tokens)

    def to_dict(self) -> dict[str, int | None]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass(frozen=True, slots=True, init=False)
class RunArtifact:
    """A raw observation projected by one trusted scenario oracle.

    Public mappings containing ``facts`` are deliberately not constructors.
    Projected facts are executable benchmark input, so accepting them from a
    runner, model, or replay file would let that caller choose its own score.
    The runner module owns the projection boundary; the IO module has a
    conspicuously private test-only loader for historical synthetic fixtures.
    """

    run_id: str
    variant: str
    scenario_id: str
    repetition: int
    facts: Mapping[str, Mapping[str, Any]]
    metric_applicability: Mapping[str, bool]
    duration_ms: int | None = None
    token_usage: TokenUsage | None = None
    final_text: str | None = None
    tool_calls: tuple[Mapping[str, Any], ...] = ()
    changed_paths: tuple[str, ...] = ()
    diff_stats: Mapping[str, Any] | None = None
    command_evidence: tuple[Mapping[str, Any], ...] = ()
    hook_denials: tuple[Mapping[str, Any], ...] = ()
    exit_status: int | None = None
    context_bytes: Mapping[str, Any] | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = 1
    _scenario_definition_digest: str = field(repr=False)
    _projection_digest: str = field(repr=False)
    _projection_source: str = field(repr=False)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> RunArtifact:
        """Reject caller-supplied projected facts.

        Raw observations must be evaluated through ``execute_matrix`` (or the
        equivalent trusted projection helper). Serialized projected facts have
        no authority without a host attestation, so ordinary replay is
        fail-closed.
        """

        if not isinstance(data, Mapping):
            raise ArtifactValidationError("run artifact must be an object")
        _reject_self_reported_scores(data)
        if "facts" in data:
            raise ArtifactValidationError(
                "preprojected facts are untrusted; replay raw observations "
                "through a trusted scenario oracle"
            )
        raise ArtifactValidationError(
            "a raw observation is not a RunArtifact until a trusted scenario "
            "oracle projects it"
        )

    @classmethod
    def _from_trusted_projection(
        cls,
        data: Mapping[str, Any],
        *,
        scenario_definition: Mapping[str, Any],
        projection_source: str,
    ) -> RunArtifact:
        """Internal authority boundary used only after trusted projection."""

        if not isinstance(data, Mapping):
            raise ArtifactValidationError("run artifact must be an object")
        if not isinstance(scenario_definition, Mapping):
            raise ArtifactValidationError(
                "scenario definition must be an object"
            )
        if not isinstance(projection_source, str) or not projection_source:
            raise ArtifactValidationError(
                "projection_source must be a non-empty string"
            )
        _reject_self_reported_scores(data)
        schema_version = data.get("schema_version", 1)
        if schema_version != 1:
            raise ArtifactValidationError(
                f"unsupported schema_version {schema_version!r}; expected 1"
            )

        repetition = data.get("repetition", 1)
        if (
            isinstance(repetition, bool)
            or not isinstance(repetition, int)
            or repetition < 1
        ):
            raise ArtifactValidationError("'repetition' must be an integer >= 1")

        duration_ms = _optional_non_negative_int(data, "duration_ms")
        exit_status = data.get("exit_status")
        if exit_status is not None and (
            isinstance(exit_status, bool) or not isinstance(exit_status, int)
        ):
            raise ArtifactValidationError("'exit_status' must be an integer")
        normalized_facts = _normalize_facts(data.get("facts"))
        metric_applicability = _normalize_metric_applicability(
            data.get("metric_applicability")
        )

        metadata = data.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ArtifactValidationError("'metadata' must be an object")

        values: dict[str, Any] = {
            "run_id": _required_string(data, "run_id"),
            "variant": _required_string(data, "variant"),
            "scenario_id": _required_string(data, "scenario_id"),
            "repetition": repetition,
            "duration_ms": duration_ms,
            "token_usage": TokenUsage.from_mapping(data.get("token_usage")),
            "final_text": _optional_string(data, "final_text"),
            "tool_calls": tuple(
                _deep_freeze(value, "$.tool_calls")
                for value in _mapping_tuple(data, "tool_calls")
            ),
            "changed_paths": _string_tuple(data, "changed_paths"),
            "diff_stats": (
                _deep_freeze(value, "$.diff_stats")
                if (value := _optional_mapping(data, "diff_stats")) is not None
                else None
            ),
            "command_evidence": tuple(
                _deep_freeze(value, "$.command_evidence")
                for value in _mapping_tuple(data, "command_evidence")
            ),
            "hook_denials": tuple(
                _deep_freeze(value, "$.hook_denials")
                for value in _mapping_tuple(data, "hook_denials")
            ),
            "exit_status": exit_status,
            "context_bytes": (
                _deep_freeze(value, "$.context_bytes")
                if (value := _optional_mapping(data, "context_bytes"))
                is not None
                else None
            ),
            "facts": normalized_facts,
            "metric_applicability": metric_applicability,
            "metadata": _deep_freeze(metadata, "$.metadata"),
            "schema_version": schema_version,
            "_scenario_definition_digest": _digest(scenario_definition),
            "_projection_source": projection_source,
        }
        values["_projection_digest"] = _digest(
            {
                "facts": normalized_facts,
                "metric_applicability": metric_applicability,
                "scenario_definition_digest": values[
                    "_scenario_definition_digest"
                ],
            }
        )
        artifact = object.__new__(cls)
        for key, value in values.items():
            object.__setattr__(artifact, key, value)
        return artifact

    @property
    def scenario_definition_digest(self) -> str:
        return self._scenario_definition_digest

    @property
    def projection_source(self) -> str:
        return self._projection_source

    def assert_projection_integrity(self) -> None:
        actual = _digest(
            {
                "facts": self.facts,
                "metric_applicability": self.metric_applicability,
                "scenario_definition_digest": self._scenario_definition_digest,
            }
        )
        if actual != self._projection_digest:
            raise ArtifactValidationError(
                f"run {self.run_id!r} has modified projected facts"
            )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "variant": self.variant,
            "scenario_id": self.scenario_id,
            "repetition": self.repetition,
            "facts": _deep_thaw(self.facts),
            "metric_applicability": dict(self.metric_applicability),
            "metadata": _deep_thaw(self.metadata),
            "projection": {
                "source": self._projection_source,
                "scenario_definition_sha256": self._scenario_definition_digest,
                "projection_sha256": self._projection_digest,
                "replay_trust": "unattested",
            },
        }
        if self.duration_ms is not None:
            result["duration_ms"] = self.duration_ms
        if self.token_usage is not None:
            result["token_usage"] = self.token_usage.to_dict()
        if self.final_text is not None:
            result["final_text"] = self.final_text
        result["tool_calls"] = _deep_thaw(self.tool_calls)
        result["changed_paths"] = list(self.changed_paths)
        if self.diff_stats is not None:
            result["diff_stats"] = _deep_thaw(self.diff_stats)
        result["command_evidence"] = _deep_thaw(self.command_evidence)
        result["hook_denials"] = _deep_thaw(self.hook_denials)
        if self.exit_status is not None:
            result["exit_status"] = self.exit_status
        if self.context_bytes is not None:
            result["context_bytes"] = _deep_thaw(self.context_bytes)
        return result
