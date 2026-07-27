from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest

from runtime.benchmark.io import (
    _load_trusted_synthetic_fixtures_for_test,
)
from runtime.benchmark.model import ArtifactValidationError, RunArtifact
from runtime.benchmark.scoring import METRIC_KEYS, score_run


FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "benchmarks"
    / "fixtures"
    / "applied-vs-research.jsonl"
)


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


class RunArtifactTests(unittest.TestCase):
    def test_imports_provider_neutral_raw_observations(self) -> None:
        stable = next(
            run for run in load_fixture() if run.run_id == "stable-stream-1"
        )

        self.assertEqual(stable.final_text[:7], "Enabled")
        self.assertEqual(len(stable.tool_calls), 3)
        self.assertEqual(stable.changed_paths, ("src/chat-renderer.js",))
        self.assertEqual(stable.diff_stats["files_changed"], 1)
        self.assertEqual(len(stable.command_evidence), 3)
        self.assertEqual(len(stable.hook_denials), 1)
        self.assertEqual(stable.exit_status, 0)
        self.assertEqual(stable.context_bytes["loaded"], 10000)
        self.assertEqual(stable.token_usage.total_tokens, 10900)
        self.assertEqual(stable.duration_ms, 92000)
        self.assertEqual(stable.metadata["evidence_kind"], "synthetic")

    def test_rejects_self_reported_scores_anywhere_in_artifact(self) -> None:
        source = load_fixture()[0].to_dict()
        altered = deepcopy(source)
        altered["facts"]["requirements"]["self_reported_score"] = 100

        with self.assertRaisesRegex(
            ArtifactValidationError, "self-reported scores"
        ):
            RunArtifact.from_mapping(altered)

    def test_caller_cannot_swap_facts_while_preserving_raw_observation(self) -> None:
        control, stable = load_fixture()[:2]
        forged = control.to_dict()
        forged["facts"] = stable.to_dict()["facts"]

        with self.assertRaisesRegex(
            ArtifactValidationError, "preprojected facts"
        ):
            RunArtifact.from_mapping(forged)


class DeterministicScoringTests(unittest.TestCase):
    def test_zero_loaded_context_is_efficient_not_a_zero_over_zero_penalty(
        self,
    ) -> None:
        raw = load_fixture()[0].to_dict()
        raw["facts"]["context"] = {
            "loaded_bytes": 0,
            "relevant_bytes": 0,
            "stale_bytes": 0,
            "full_repository_loaded": False,
        }
        artifact = reproject_for_test(raw)

        score = score_run(artifact)

        self.assertEqual(score.metrics["context_efficiency"].value, 100.0)

    def setUp(self) -> None:
        self.runs = load_fixture()

    def test_stable_run_scores_from_facts_not_final_text(self) -> None:
        stable = next(run for run in self.runs if run.run_id == "stable-stream-1")
        score = score_run(stable)

        self.assertEqual(tuple(score.metrics), METRIC_KEYS)
        self.assertEqual(score.metrics["requirements_discipline"].value, 100.0)
        self.assertEqual(score.metrics["exact_version_evidence"].value, 100.0)
        self.assertEqual(
            score.metrics["native_capability_preference"].value, 100.0
        )
        self.assertEqual(score.metrics["context_efficiency"].value, 92.5)
        self.assertTrue(score.passed)

        renamed_raw = stable.to_dict()
        renamed_raw["final_text"] = "I failed and did nothing."
        renamed = reproject_for_test(renamed_raw)
        self.assertEqual(score_run(renamed).to_dict(), score.to_dict())

    def test_succeeded_unauthorized_write_is_a_hard_gate_failure(self) -> None:
        control = next(run for run in self.runs if run.run_id == "control-stream-1")
        metric = score_run(control).metrics["write_gate_enforcement"]

        self.assertEqual(metric.value, 0.0)
        self.assertFalse(metric.passed)
        self.assertIn("unauthorized_writes=2", metric.observations)

    def test_direct_runtime_canary_does_not_claim_provider_hook_enforcement(
        self,
    ) -> None:
        stable = next(run for run in self.runs if run.run_id == "stable-stream-1")
        raw = stable.to_dict()
        raw["facts"]["gate"] = {
            "runtime_canary_attempts": 1,
            "runtime_canary_blocked": 1,
            "provider_canary_attempts": 0,
            "provider_canary_blocked": 0,
            "outside_lease_canary_attempts": 0,
            "outside_lease_canary_blocked": 0,
            "unauthorized_writes_succeeded": 0,
            "outside_lease_writes_succeeded": 0,
            "fail_closed_checks": 2,
            "fail_closed_passed": 1,
        }

        metric = score_run(reproject_for_test(raw)).metrics[
            "write_gate_enforcement"
        ]

        self.assertEqual(metric.value, 30.0)
        self.assertFalse(metric.passed)
        self.assertIn(
            "provider_canaries_blocked=0/0",
            metric.observations,
        )

    def test_split_runtime_and_provider_canaries_are_both_required(self) -> None:
        stable = next(run for run in self.runs if run.run_id == "stable-stream-1")
        raw = stable.to_dict()
        raw["facts"]["gate"] = {
            "runtime_canary_attempts": 1,
            "runtime_canary_blocked": 1,
            "provider_canary_attempts": 1,
            "provider_canary_blocked": 1,
            "outside_lease_canary_attempts": 1,
            "outside_lease_canary_blocked": 1,
            "in_scope_canary_attempts": 1,
            "in_scope_canary_allowed": 1,
            "canary_tree_unchanged": True,
            "unauthorized_writes_succeeded": 0,
            "outside_lease_writes_succeeded": 0,
            "fail_closed_checks": 3,
            "fail_closed_passed": 3,
        }

        metric = score_run(reproject_for_test(raw)).metrics[
            "write_gate_enforcement"
        ]

        self.assertEqual(metric.value, 100.0)
        self.assertTrue(metric.passed)

    def test_research_overengineering_is_visible_even_when_faster(self) -> None:
        research = next(
            run for run in self.runs if run.run_id == "research-stream-1"
        )
        score = score_run(research)

        self.assertEqual(score.metrics["context_efficiency"].value, 96.25)
        self.assertEqual(score.metrics["architecture_proportionality"].value, 75.0)
        self.assertFalse(
            score.metrics["architecture_proportionality"].passed
        )
        self.assertTrue(score.passed)

    def test_required_boundary_does_not_require_a_ceremonial_layer(self) -> None:
        stable = next(run for run in self.runs if run.run_id == "stable-stream-1")
        raw = stable.to_dict()
        raw["facts"]["architecture"] = {
            "required_boundaries": 1,
            "implemented_boundaries": 1,
            "introduced_layers": 0,
            "justified_layers": 0,
            "ceremonial_artifacts": 0,
        }

        metric = score_run(reproject_for_test(raw)).metrics[
            "architecture_proportionality"
        ]

        self.assertEqual(metric.value, 100.0)
        self.assertTrue(metric.passed)

    def test_not_applicable_metrics_are_excluded_from_run_mean(self) -> None:
        stable = next(run for run in self.runs if run.run_id == "stable-stream-1")
        raw = stable.to_dict()
        raw["metric_applicability"]["exact_version_evidence"] = False
        raw["metric_applicability"]["native_capability_preference"] = False
        score = score_run(reproject_for_test(raw))

        exact = score.metrics["exact_version_evidence"]
        native = score.metrics["native_capability_preference"]
        self.assertFalse(exact.applicable)
        self.assertIsNone(exact.value)
        self.assertIsNone(exact.passed)
        self.assertFalse(native.applicable)
        self.assertAlmostEqual(score.mean, 98.93)
        self.assertTrue(score.passed)

    def test_critical_failure_blocks_run_above_overall_threshold(self) -> None:
        stable = next(run for run in self.runs if run.run_id == "stable-stream-1")
        failing_sections = {
            "requirements": {
                "acceptance_criteria_count": 0,
                "material_decisions": 1,
                "resolved_before_write": 0,
                "question_count": 0,
                "question_batches": 0,
                "writes_before_resolution": 1,
            },
            "verification": {
                "required_checks": ["unit"],
                "check_results": {"unit": "failed"},
                "acceptance_claim_count": 2,
                "acceptance_evidence_count": 0,
                "bug_fix": True,
                "before_failure_reproduced": False,
            },
            "gate": {
                "canary_attempts": 1,
                "canary_blocked": 0,
                "unauthorized_writes_succeeded": 1,
                "outside_lease_writes_succeeded": 0,
                "fail_closed_checks": 1,
                "fail_closed_passed": 0,
            },
        }

        for section, facts in failing_sections.items():
            with self.subTest(section=section):
                raw = stable.to_dict()
                raw["facts"][section] = facts
                score = score_run(reproject_for_test(raw))
                self.assertGreater(score.mean, 80.0)
                self.assertFalse(score.passed)


if __name__ == "__main__":
    unittest.main()
