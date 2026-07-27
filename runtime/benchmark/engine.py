from __future__ import annotations

from dataclasses import dataclass
from statistics import fmean, median
from typing import Any, Iterable, Mapping

from .model import RunArtifact
from .scoring import METRIC_KEYS, RunScore, score_run


@dataclass(frozen=True, slots=True)
class PairedComparison:
    sample_count: int
    wins: int
    ties: int
    losses: int

    def to_dict(self) -> dict[str, int]:
        return {
            "sample_count": self.sample_count,
            "wins": self.wins,
            "ties": self.ties,
            "losses": self.losses,
        }


@dataclass(frozen=True, slots=True)
class MetricAggregate:
    applicable_sample_count: int
    mean: float | None
    pass_rate: float | None
    delta_vs_control: float | None
    delta_vs_reference: float | None
    regression: bool
    paired_vs_control: PairedComparison

    def to_dict(self) -> dict[str, Any]:
        return {
            "applicable_sample_count": self.applicable_sample_count,
            "mean": self.mean,
            "pass_rate": self.pass_rate,
            "delta_vs_control": self.delta_vs_control,
            "delta_vs_reference": self.delta_vs_reference,
            "regression": self.regression,
            "paired_vs_control": self.paired_vs_control.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class UsageAggregate:
    sample_count: int
    duration_sample_count: int
    duration_ms_total: int | None
    duration_ms_mean: float | None
    token_sample_count: int
    input_tokens_total: int | None
    output_tokens_total: int | None
    total_tokens: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_count": self.sample_count,
            "duration": {
                "sample_count": self.duration_sample_count,
                "total_ms": self.duration_ms_total,
                "mean_ms": self.duration_ms_mean,
            },
            "tokens": {
                "sample_count": self.token_sample_count,
                "input_total": self.input_tokens_total,
                "output_total": self.output_tokens_total,
                "total": self.total_tokens,
            },
        }


@dataclass(frozen=True, slots=True)
class VariantAggregate:
    variant: str
    metrics: Mapping[str, MetricAggregate]
    overall_mean: float | None
    overall_median: float | None
    overall_min: float | None
    overall_max: float | None
    run_pass_rate: float | None
    complete_sample_count: int
    incomplete_sample_count: int
    incomplete_rate: float
    delta_vs_control: float | None
    delta_vs_reference: float | None
    regression_flags: tuple[str, ...]
    usage: UsageAggregate
    scenario_sample_counts: Mapping[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_mean": self.overall_mean,
            "overall_median": self.overall_median,
            "overall_min": self.overall_min,
            "overall_max": self.overall_max,
            "run_pass_rate": self.run_pass_rate,
            "complete_sample_count": self.complete_sample_count,
            "incomplete_sample_count": self.incomplete_sample_count,
            "incomplete_rate": self.incomplete_rate,
            "delta_vs_control": self.delta_vs_control,
            "delta_vs_reference": self.delta_vs_reference,
            "regression_flags": list(self.regression_flags),
            "usage": self.usage.to_dict(),
            "scenario_sample_counts": dict(self.scenario_sample_counts),
            "metrics": {
                key: aggregate.to_dict()
                for key, aggregate in self.metrics.items()
            },
        }


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    control_variant: str
    regression_reference_variant: str
    pass_threshold: float
    regression_tolerance: float
    variant_order: tuple[str, ...]
    variants: Mapping[str, VariantAggregate]
    run_scores: tuple[RunScore, ...]
    evidence_status: str
    decision_status: str
    schema_version: int = 1

    def to_dict(self, include_run_scores: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "control_variant": self.control_variant,
            "regression_reference_variant": self.regression_reference_variant,
            "pass_threshold": self.pass_threshold,
            "regression_tolerance": self.regression_tolerance,
            "evidence_status": self.evidence_status,
            "decision_status": self.decision_status,
            "metric_order": list(METRIC_KEYS),
            "variant_order": list(self.variant_order),
            "variants": {
                name: self.variants[name].to_dict() for name in self.variant_order
            },
        }
        if include_run_scores:
            result["run_scores"] = [score.to_dict() for score in self.run_scores]
        return result


def _round(value: float) -> float:
    return round(value, 2)


def _delta(value: float | None, baseline: float | None) -> float | None:
    if value is None or baseline is None:
        return None
    return _round(value - baseline)


def _paired(
    variant_scores: Mapping[tuple[str, int], RunScore],
    control_scores: Mapping[tuple[str, int], RunScore],
    metric_key: str,
) -> PairedComparison:
    wins = ties = losses = 0
    for cell, candidate in variant_scores.items():
        control = control_scores[cell]
        if not candidate.complete or not control.complete:
            continue
        candidate_metric = candidate.metrics[metric_key]
        control_metric = control.metrics[metric_key]
        if not candidate_metric.applicable or not control_metric.applicable:
            continue
        if candidate_metric.value is None or control_metric.value is None:
            continue
        if candidate_metric.value > control_metric.value:
            wins += 1
        elif candidate_metric.value < control_metric.value:
            losses += 1
        else:
            ties += 1
    return PairedComparison(
        sample_count=wins + ties + losses,
        wins=wins,
        ties=ties,
        losses=losses,
    )


def _usage(artifacts: list[RunArtifact]) -> UsageAggregate:
    durations = [
        artifact.duration_ms
        for artifact in artifacts
        if artifact.duration_ms is not None
    ]
    usages = [
        artifact.token_usage
        for artifact in artifacts
        if artifact.token_usage is not None
    ]

    def total_for(field: str) -> int | None:
        values = [
            getattr(usage, field)
            for usage in usages
            if getattr(usage, field) is not None
        ]
        return sum(values) if values else None

    return UsageAggregate(
        sample_count=len(artifacts),
        duration_sample_count=len(durations),
        duration_ms_total=sum(durations) if durations else None,
        duration_ms_mean=_round(fmean(durations)) if durations else None,
        token_sample_count=len(usages),
        input_tokens_total=total_for("input_tokens"),
        output_tokens_total=total_for("output_tokens"),
        total_tokens=total_for("total_tokens"),
    )


class BenchmarkEngine:
    """Scores replayed run facts and compares named variants."""

    def __init__(
        self,
        *,
        pass_threshold: float = 80.0,
        regression_tolerance: float = 2.0,
    ) -> None:
        if not 0.0 <= pass_threshold <= 100.0:
            raise ValueError("pass_threshold must be between 0 and 100")
        if regression_tolerance < 0.0:
            raise ValueError("regression_tolerance must be non-negative")
        self.pass_threshold = pass_threshold
        self.regression_tolerance = regression_tolerance

    def compare(
        self,
        artifacts: Iterable[RunArtifact],
        *,
        control_variant: str = "control",
        regression_reference_variant: str | None = None,
    ) -> BenchmarkReport:
        runs = list(artifacts)
        if not runs:
            raise ValueError("at least one run artifact is required")
        run_ids = [run.run_id for run in runs]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("run_id values must be unique")

        variants_in_order = tuple(dict.fromkeys(run.variant for run in runs))
        if control_variant not in variants_in_order:
            raise ValueError(f"control variant {control_variant!r} is missing")
        reference = regression_reference_variant
        if reference is None:
            reference = "stable" if "stable" in variants_in_order else control_variant
        if reference not in variants_in_order:
            raise ValueError(f"regression reference variant {reference!r} is missing")

        variant_order = (
            control_variant,
            *(
                name
                for name in variants_in_order
                if name != control_variant
            ),
        )
        cells_by_variant: dict[str, set[tuple[str, int]]] = {}
        for variant in variant_order:
            cells = [
                (run.scenario_id, run.repetition)
                for run in runs
                if run.variant == variant
            ]
            if len(cells) != len(set(cells)):
                raise ValueError(
                    f"variant {variant!r} has duplicate scenario/repetition cells"
                )
            cells_by_variant[variant] = set(cells)
        control_cells = cells_by_variant[control_variant]
        for variant in variant_order:
            if cells_by_variant[variant] != control_cells:
                missing = sorted(control_cells - cells_by_variant[variant])
                extra = sorted(cells_by_variant[variant] - control_cells)
                raise ValueError(
                    f"unbalanced run matrix for variant {variant!r}: "
                    f"missing={missing}, extra={extra}"
                )

        applicability_by_scenario: dict[str, Mapping[str, bool]] = {}
        definition_by_scenario: dict[str, str] = {}
        for run in runs:
            run.assert_projection_integrity()
            expected_applicability = applicability_by_scenario.setdefault(
                run.scenario_id, run.metric_applicability
            )
            if dict(run.metric_applicability) != dict(expected_applicability):
                raise ValueError(
                    "metric applicability must be scenario-owned and identical "
                    f"across variants/repetitions for {run.scenario_id!r}"
                )
            expected_definition = definition_by_scenario.setdefault(
                run.scenario_id, run.scenario_definition_digest
            )
            if run.scenario_definition_digest != expected_definition:
                raise ValueError(
                    "scenario oracle definition must be identical across "
                    f"variants/repetitions for {run.scenario_id!r}"
                )

        scores = tuple(
            score_run(run, self.pass_threshold)
            for run in runs
        )
        runs_by_variant = {
            variant: [run for run in runs if run.variant == variant]
            for variant in variant_order
        }
        scores_by_variant = {
            variant: [score for score in scores if score.variant == variant]
            for variant in variant_order
        }
        scores_by_cell = {
            variant: {
                (score.scenario_id, score.repetition): score
                for score in scores_by_variant[variant]
            }
            for variant in variant_order
        }

        metric_means: dict[str, dict[str, float | None]] = {}
        overall_means: dict[str, float | None] = {}
        for variant in variant_order:
            variant_scores = scores_by_variant[variant]
            complete_scores = [
                score for score in variant_scores if score.complete
            ]
            metric_means[variant] = {}
            for key in METRIC_KEYS:
                applicable_values = [
                    score.metrics[key].value
                    for score in complete_scores
                    if score.metrics[key].applicable
                    and score.metrics[key].value is not None
                ]
                metric_means[variant][key] = (
                    _round(fmean(applicable_values))
                    if applicable_values
                    else None
                )
            run_means = [
                score.mean
                for score in complete_scores
                if score.mean is not None
            ]
            overall_means[variant] = (
                _round(fmean(run_means))
                if run_means
                else None
            )

        aggregates: dict[str, VariantAggregate] = {}
        for variant in variant_order:
            variant_scores = scores_by_variant[variant]
            complete_scores = [
                score for score in variant_scores if score.complete
            ]
            run_means = [
                score.mean
                for score in complete_scores
                if score.mean is not None
            ]
            incomplete_count = len(variant_scores) - len(complete_scores)
            metric_aggregates: dict[str, MetricAggregate] = {}
            regression_flags: list[str] = []
            candidate_for_regression = variant not in {
                control_variant,
                reference,
            }
            for key in METRIC_KEYS:
                mean = metric_means[variant][key]
                applicable_scores = [
                    score.metrics[key]
                    for score in complete_scores
                    if score.metrics[key].applicable
                ]
                delta_control = _delta(
                    mean, metric_means[control_variant][key]
                )
                delta_reference = _delta(
                    mean, metric_means[reference][key]
                )
                regression = (
                    candidate_for_regression
                    and delta_reference is not None
                    and delta_reference < -self.regression_tolerance
                )
                if regression:
                    regression_flags.append(key)
                metric_aggregates[key] = MetricAggregate(
                    applicable_sample_count=len(applicable_scores),
                    mean=mean,
                    pass_rate=(
                        _round(
                            100.0
                            * sum(
                                metric.passed is True
                                for metric in applicable_scores
                            )
                            / len(applicable_scores)
                        )
                        if applicable_scores
                        else None
                    ),
                    delta_vs_control=delta_control,
                    delta_vs_reference=delta_reference,
                    regression=regression,
                    paired_vs_control=_paired(
                        scores_by_cell[variant],
                        scores_by_cell[control_variant],
                        key,
                    ),
                )

            overall_delta_control = _delta(
                overall_means[variant], overall_means[control_variant]
            )
            overall_delta_reference = _delta(
                overall_means[variant], overall_means[reference]
            )
            if (
                candidate_for_regression
                and overall_delta_reference is not None
                and overall_delta_reference < -self.regression_tolerance
            ):
                regression_flags.insert(0, "overall")

            scenario_counts: dict[str, int] = {}
            for run in runs_by_variant[variant]:
                scenario_counts[run.scenario_id] = (
                    scenario_counts.get(run.scenario_id, 0) + 1
                )
            aggregates[variant] = VariantAggregate(
                variant=variant,
                metrics=metric_aggregates,
                overall_mean=overall_means[variant],
                overall_median=(
                    _round(median(run_means)) if run_means else None
                ),
                overall_min=(
                    _round(min(run_means)) if run_means else None
                ),
                overall_max=(
                    _round(max(run_means)) if run_means else None
                ),
                run_pass_rate=_round(
                    100.0
                    * sum(score.passed for score in complete_scores)
                    / len(complete_scores)
                )
                if complete_scores
                else None,
                complete_sample_count=len(complete_scores),
                incomplete_sample_count=incomplete_count,
                incomplete_rate=_round(
                    100.0 * incomplete_count / len(variant_scores)
                ),
                delta_vs_control=overall_delta_control,
                delta_vs_reference=overall_delta_reference,
                regression_flags=tuple(regression_flags),
                usage=_usage(runs_by_variant[variant]),
                scenario_sample_counts=scenario_counts,
            )

        projection_sources = {run.projection_source for run in runs}
        capture_provenance = {
            run.metadata.get("capture_provenance") for run in runs
        }
        evidence_status = (
            "SYNTHETIC / UNATTESTED"
            if projection_sources == {"test-only-synthetic-unattested"}
            else (
                "LIVE CAPTURE / IN-MEMORY / TRUSTED ORACLE PROJECTION"
                if capture_provenance == {"live-in-memory"}
                else (
                    "HOST-HMAC ATTESTED RAW / TRUSTED ORACLE PROJECTION"
                    if capture_provenance == {"host-hmac-attested-replay"}
                    else (
                        "UNATTESTED RAW REPLAY / TRUSTED ORACLE PROJECTION / "
                        "DIAGNOSTIC ONLY"
                        if capture_provenance == {"unattested-replay"}
                        else (
                            "TRUSTED ORACLE PROJECTION"
                            if len(projection_sources) == 1
                            else "MIXED PROJECTION SOURCES"
                        )
                    )
                )
            )
        )
        scenario_repetitions: dict[str, set[int]] = {}
        for scenario_id, repetition in control_cells:
            scenario_repetitions.setdefault(scenario_id, set()).add(
                repetition
            )
        minimum_repetitions = min(
            (len(values) for values in scenario_repetitions.values()),
            default=0,
        )
        incomplete_runs = sum(not score.complete for score in scores)
        promotion_evidence_is_trusted = (
            len(projection_sources) == 1
            and "test-only-synthetic-unattested" not in projection_sources
            and capture_provenance
            in (
                {"live-in-memory"},
                {"host-hmac-attested-replay"},
            )
        )
        if not promotion_evidence_is_trusted:
            decision_status = (
                "UNATTESTED + INCOMPLETE / NO PROMOTION "
                f"({incomplete_runs} run(s))"
                if incomplete_runs
                else "UNATTESTED / NO PROMOTION"
            )
        elif incomplete_runs:
            decision_status = (
                f"INCOMPLETE / NO PROMOTION ({incomplete_runs} run(s))"
            )
        elif minimum_repetitions < 3:
            decision_status = (
                "SCREEN / NO PROMOTION "
                f"(minimum paired repetitions={minimum_repetitions}; need >=3)"
            )
        else:
            decision_status = (
                "EVALUATION / MANUAL PROMOTION REVIEW"
            )
        return BenchmarkReport(
            control_variant=control_variant,
            regression_reference_variant=reference,
            pass_threshold=self.pass_threshold,
            regression_tolerance=self.regression_tolerance,
            variant_order=variant_order,
            variants=aggregates,
            run_scores=scores,
            evidence_status=evidence_status,
            decision_status=decision_status,
        )
