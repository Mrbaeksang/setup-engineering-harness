from __future__ import annotations

import json
from typing import Any

from .engine import BenchmarkReport, VariantAggregate
from .scoring import METRIC_KEYS, METRIC_LABELS


def _delta(value: float) -> str:
    return f"{value:+.1f}"


def _cell(
    aggregate: VariantAggregate,
    metric_key: str | None,
    *,
    control: bool,
    reference: bool,
    distinct_reference: bool,
) -> str:
    if metric_key is None:
        mean = aggregate.overall_mean
        pass_rate = aggregate.run_pass_rate
        delta_control = aggregate.delta_vs_control
        delta_reference = aggregate.delta_vs_reference
        regression = "overall" in aggregate.regression_flags
        applicable_count = aggregate.complete_sample_count
    else:
        metric = aggregate.metrics[metric_key]
        mean = metric.mean
        pass_rate = metric.pass_rate
        delta_control = metric.delta_vs_control
        delta_reference = metric.delta_vs_reference
        regression = metric.regression
        applicable_count = metric.applicable_sample_count
    if mean is None or pass_rate is None:
        return f"N/A n={applicable_count}"
    parts = [f"{mean:5.1f}/{pass_rate:3.0f}%"]
    if applicable_count != aggregate.usage.sample_count:
        parts.append(f"n={applicable_count}")
    if not control and delta_control is not None:
        parts.append(f"ΔC{_delta(delta_control)}")
    if not control and metric_key is not None:
        paired = aggregate.metrics[metric_key].paired_vs_control
        parts.append(
            f"W{paired.wins}/T{paired.ties}/L{paired.losses}"
        )
    if (
        distinct_reference
        and not control
        and not reference
        and delta_reference is not None
    ):
        parts.append(f"ΔR{_delta(delta_reference)}")
    if regression:
        parts.append("!")
    return " ".join(parts)


def _format_tokens(value: int | None) -> str:
    if value is None:
        return "--"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}m"
    if value >= 1_000:
        return f"{value / 1_000:.1f}k"
    return str(value)


def _coverage_cell(aggregate: VariantAggregate) -> str:
    total = aggregate.usage.sample_count
    complete = aggregate.complete_sample_count
    marker = " !" if aggregate.incomplete_sample_count else ""
    return f"{complete}/{total} complete{marker}"


def render_table(report: BenchmarkReport) -> str:
    """Render scores with their completed-run denominator visible."""

    metric_width = max(
        len("Metric"),
        len("RUN COVERAGE"),
        len("OVERALL"),
        *(len(METRIC_LABELS[key]) for key in METRIC_KEYS),
    )
    distinct_reference = (
        report.regression_reference_variant != report.control_variant
    )
    cells: dict[tuple[str, str | None], str] = {}
    coverage_cells: dict[str, str] = {}
    column_widths: dict[str, int] = {}
    for variant in report.variant_order:
        aggregate = report.variants[variant]
        coverage_cells[variant] = _coverage_cell(aggregate)
        for metric_key in (*METRIC_KEYS, None):
            cells[(variant, metric_key)] = _cell(
                aggregate,
                metric_key,
                control=variant == report.control_variant,
                reference=variant == report.regression_reference_variant,
                distinct_reference=distinct_reference,
            )
        column_widths[variant] = max(
            len(variant),
            len(coverage_cells[variant]),
            *(len(cells[(variant, key)]) for key in (*METRIC_KEYS, None)),
        )

    def row(label: str, key: str | None) -> str:
        values = [label.ljust(metric_width)]
        values.extend(
            cells[(variant, key)].rjust(column_widths[variant])
            for variant in report.variant_order
        )
        return "  ".join(values)

    header = "  ".join(
        ["Metric".ljust(metric_width)]
        + [
            variant.rjust(column_widths[variant])
            for variant in report.variant_order
        ]
    )
    separator = "  ".join(
        ["-" * metric_width]
        + ["-" * column_widths[variant] for variant in report.variant_order]
    )
    lines = [
        (
            "Engineering Harness Benchmark  "
            f"pass≥{report.pass_threshold:g}  "
            f"control={report.control_variant}  "
            f"regression={report.regression_reference_variant}"
        ),
        f"Evidence: {report.evidence_status}",
        f"Decision: {report.decision_status}",
        header,
        separator,
        "  ".join(
            ["RUN COVERAGE".ljust(metric_width)]
            + [
                coverage_cells[variant].rjust(column_widths[variant])
                for variant in report.variant_order
            ]
        ),
        separator,
    ]
    lines.extend(row(METRIC_LABELS[key], key) for key in METRIC_KEYS)
    lines.extend([separator, row("OVERALL", None), ""])
    for variant in report.variant_order:
        usage = report.variants[variant].usage
        aggregate = report.variants[variant]
        duration = (
            f"{usage.duration_ms_total}ms"
            if usage.duration_ms_total is not None
            else "--"
        )
        lines.append(
            f"{variant}: n={usage.sample_count} "
            f"scenarios={len(aggregate.scenario_sample_counts)} "
            f"complete={aggregate.complete_sample_count} "
            f"incomplete={aggregate.incomplete_sample_count} "
            f"incomplete-rate={aggregate.incomplete_rate:.1f}% "
            f"median={aggregate.overall_median if aggregate.overall_median is not None else '--'} "
            f"range={aggregate.overall_min if aggregate.overall_min is not None else '--'}"
            f"..{aggregate.overall_max if aggregate.overall_max is not None else '--'} "
            f"duration={duration} "
            f"tokens={_format_tokens(usage.total_tokens)}"
        )
    lines.append(
        "Metric cell = completed-run mean/pass-rate; RUN COVERAGE supplies "
        "the planned denominator; ΔC = vs control; ΔR = vs regression "
        "reference; W/T/L = paired wins/ties/losses vs control; "
        "! = incomplete coverage or regression"
    )
    return "\n".join(lines)


def render_json(
    report: BenchmarkReport, *, include_run_scores: bool = True
) -> str:
    data: dict[str, Any] = report.to_dict(include_run_scores=include_run_scores)
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
