from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .engine import BenchmarkEngine
from .io import ArtifactLoadError, load_artifacts
from .render import render_json, render_table


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m runtime.benchmark",
        description="Replay raw run artifacts and compare Engineering Harness variants.",
    )
    parser.add_argument("artifacts", nargs="+", help="JSON/JSONL file or directory")
    parser.add_argument("--control", default="control", help="control variant name")
    parser.add_argument(
        "--regression-reference",
        help="variant used for regression flags (defaults to stable, then control)",
    )
    parser.add_argument("--pass-threshold", type=float, default=80.0)
    parser.add_argument("--regression-tolerance", type=float, default=2.0)
    parser.add_argument(
        "--format",
        choices=("table", "json", "both"),
        default="table",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help="also write the complete JSON report to this path",
    )
    parser.add_argument(
        "--without-run-scores",
        action="store_true",
        help="omit per-run scores from JSON output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        artifacts = load_artifacts(*args.artifacts)
        report = BenchmarkEngine(
            pass_threshold=args.pass_threshold,
            regression_tolerance=args.regression_tolerance,
        ).compare(
            artifacts,
            control_variant=args.control,
            regression_reference_variant=args.regression_reference,
        )
    except (ArtifactLoadError, ValueError) as error:
        print(f"benchmark error: {error}", file=sys.stderr)
        return 2

    json_text = render_json(
        report, include_run_scores=not args.without_run_scores
    )
    if args.format in {"table", "both"}:
        print(render_table(report))
    if args.format == "both":
        print()
    if args.format in {"json", "both"}:
        print(json_text)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json_text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
