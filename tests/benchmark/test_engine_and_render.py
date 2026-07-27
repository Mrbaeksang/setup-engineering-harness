from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from runtime.benchmark.__main__ import main
from runtime.benchmark.engine import BenchmarkEngine
from runtime.benchmark.io import (
    _load_trusted_synthetic_fixtures_for_test,
)
from runtime.benchmark.model import RunArtifact
from runtime.benchmark.render import render_json, render_table


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "benchmarks" / "fixtures" / "applied-vs-research.jsonl"


def load_fixture() -> list[RunArtifact]:
    return _load_trusted_synthetic_fixtures_for_test(FIXTURE)


def reproject_for_test(raw: dict) -> RunArtifact:
    return RunArtifact._from_trusted_projection(
        raw,
        scenario_definition={
            "scenario_id": raw["scenario_id"],
            "fixture_kind": "synthetic",
            "metric_applicability": raw["metric_applicability"],
        },
        projection_source="test-only-synthetic-unattested",
    )


class BenchmarkEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = BenchmarkEngine().compare(load_fixture())

    def test_compares_control_stable_and_research_repetitions(self) -> None:
        self.assertEqual(
            self.report.variant_order, ("control", "stable", "research")
        )
        self.assertEqual(
            self.report.regression_reference_variant, "stable"
        )
        self.assertEqual(self.report.variants["control"].usage.sample_count, 2)
        self.assertEqual(self.report.variants["stable"].run_pass_rate, 100.0)
        self.assertEqual(self.report.variants["research"].run_pass_rate, 100.0)
        self.assertEqual(
            self.report.variants["stable"].usage.total_tokens, 21400
        )
        self.assertEqual(
            self.report.variants["research"].usage.duration_ms_total, 149000
        )

    def test_reports_control_delta_and_stable_regression_separately(self) -> None:
        architecture = self.report.variants["research"].metrics[
            "architecture_proportionality"
        ]

        self.assertEqual(architecture.delta_vs_control, 73.75)
        self.assertEqual(architecture.delta_vs_reference, -25.0)
        self.assertTrue(architecture.regression)
        self.assertIn(
            "architecture_proportionality",
            self.report.variants["research"].regression_flags,
        )
        self.assertEqual(
            self.report.variants["stable"].regression_flags, ()
        )
        paired = self.report.variants["stable"].metrics[
            "requirements_discipline"
        ].paired_vs_control
        self.assertEqual(
            (paired.sample_count, paired.wins, paired.ties, paired.losses),
            (2, 2, 0, 0),
        )

    def test_renders_compact_table_and_machine_json(self) -> None:
        table = render_table(self.report)
        machine = json.loads(render_json(self.report))

        self.assertIn("Engineering Harness Benchmark", table)
        self.assertIn("Evidence: SYNTHETIC / UNATTESTED", table)
        self.assertIn("Decision: UNATTESTED / NO PROMOTION", table)
        self.assertIn("RUN COVERAGE", table)
        self.assertIn("2/2 complete", table)
        self.assertIn("Context efficiency", table)
        self.assertIn("ΔR-25.0 !", table)
        self.assertIn("stable: n=2", table)
        self.assertIn("W2/T0/L0", table)
        self.assertIn("incomplete-rate=0.0%", table)
        self.assertIn("range=", table)
        self.assertEqual(machine["variants"]["stable"]["usage"]["sample_count"], 2)
        paired = machine["variants"]["research"]["metrics"][
            "context_efficiency"
        ]["paired_vs_control"]
        self.assertEqual(
            paired,
            {"sample_count": 2, "wins": 2, "ties": 0, "losses": 0},
        )
        self.assertEqual(len(machine["run_scores"]), 6)

    def test_incomplete_capture_is_excluded_and_reported_as_failure(self) -> None:
        runs = load_fixture()
        updated = []
        for artifact in runs:
            if artifact.run_id != "stable-stream-1":
                updated.append(artifact)
                continue
            raw = artifact.to_dict()
            raw["facts"]["verification"]["capture_complete"] = False
            raw["facts"]["verification"]["capture_failure_reasons"] = [
                "terminal-event-missing"
            ]
            updated.append(reproject_for_test(raw))

        report = BenchmarkEngine().compare(updated)
        stable = report.variants["stable"]
        table = render_table(report)

        self.assertEqual(stable.complete_sample_count, 1)
        self.assertEqual(stable.incomplete_sample_count, 1)
        self.assertEqual(stable.incomplete_rate, 50.0)
        self.assertEqual(stable.run_pass_rate, 100.0)
        self.assertIn("INCOMPLETE / NO PROMOTION", report.decision_status)
        self.assertIn("1/2 complete !", table)
        self.assertIn("stable: n=2 scenarios=1 complete=1 incomplete=1", table)
        run = next(
            score
            for score in report.run_scores
            if score.run_id == "stable-stream-1"
        )
        self.assertFalse(run.complete)
        self.assertIsNone(run.mean)

    def test_zero_applicable_samples_render_as_na_and_are_not_averaged(self) -> None:
        runs = []
        for artifact in load_fixture():
            raw = artifact.to_dict()
            raw["metric_applicability"]["exact_version_evidence"] = False
            raw["metric_applicability"]["native_capability_preference"] = False
            runs.append(reproject_for_test(raw))

        report = BenchmarkEngine().compare(runs)
        exact = report.variants["stable"].metrics["exact_version_evidence"]
        table = render_table(report)

        self.assertEqual(exact.applicable_sample_count, 0)
        self.assertIsNone(exact.mean)
        self.assertIsNone(exact.pass_rate)
        self.assertEqual(exact.paired_vs_control.sample_count, 0)
        exact_line = next(
            line for line in table.splitlines() if line.startswith("Exact version")
        )
        self.assertEqual(exact_line.count("N/A n=0"), 3)

    def test_rejects_an_unbalanced_ab_matrix(self) -> None:
        runs = load_fixture()

        with self.assertRaisesRegex(ValueError, "unbalanced run matrix"):
            BenchmarkEngine().compare(runs[:-1])

    def test_rejects_variant_specific_metric_applicability(self) -> None:
        runs = load_fixture()[:2]
        candidate = runs[1].to_dict()
        candidate["metric_applicability"]["exact_version_evidence"] = False
        candidate["metric_applicability"]["native_capability_preference"] = False

        with self.assertRaisesRegex(
            ValueError, "metric applicability"
        ):
            BenchmarkEngine().compare(
                [runs[0], reproject_for_test(candidate)]
            )

    def test_cli_rejects_unattested_preprojected_fixture(self) -> None:
        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.json"
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        str(FIXTURE),
                        "--format",
                        "table",
                        "--json-out",
                        str(output_path),
                    ]
                )

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("preprojected facts are untrusted", stderr.getvalue())
            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
