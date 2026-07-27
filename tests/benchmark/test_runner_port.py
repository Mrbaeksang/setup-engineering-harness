from __future__ import annotations

from pathlib import Path
import unittest

from runtime.benchmark.io import (
    _load_trusted_synthetic_fixtures_for_test,
)
from runtime.benchmark.model import ArtifactValidationError
from runtime.benchmark.runner import (
    RawRunObservation,
    RunRequest,
    ScenarioSpec,
    VariantSpec,
    execute_matrix,
)


FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "benchmarks"
    / "fixtures"
    / "applied-vs-research.jsonl"
)


class FakeObservationRunner:
    def __init__(self) -> None:
        self.requests: list[RunRequest] = []

    def run(self, request: RunRequest) -> RawRunObservation:
        self.requests.append(request)
        return RawRunObservation(
            run_id=(
                f"{request.variant.name}-{request.scenario.scenario_id}-"
                f"{request.repetition}"
            ),
            variant=request.variant.name,
            scenario_id=request.scenario.scenario_id,
            repetition=request.repetition,
            final_text='{"self_reported_score": 100, "facts": "trust me"}',
            tool_calls=({"name": "apply_patch", "outcome": "succeeded"},),
            changed_paths=("src/chat-renderer.js",),
            command_evidence=(
                {"command": "npm test", "exit_status": 0},
            ),
            hook_denials=(),
            exit_status=0,
        )


class FakeOracle:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.template_facts = (
            _load_trusted_synthetic_fixtures_for_test(FIXTURE)[1].facts
        )
        self.project_calls: list[
            tuple[RawRunObservation, object]
        ] = []

    def expectations_for(self, scenario: ScenarioSpec):
        self.calls.append(scenario.scenario_id)
        return {"fixture": "trusted"}

    def project(self, observation: RawRunObservation, expectations):
        self.project_calls.append((observation, expectations))
        self.assertable_expectations = expectations
        return self.template_facts


class FakeProjector:
    def __init__(self) -> None:
        self.template_facts = (
            _load_trusted_synthetic_fixtures_for_test(FIXTURE)[1].facts
        )
        self.calls: list[tuple[RawRunObservation, object]] = []

    def project(self, observation: RawRunObservation, expectations):
        self.calls.append((observation, expectations))
        self.assertable_expectations = expectations
        return self.template_facts


class RunnerPortTests(unittest.TestCase):
    def test_raw_observation_round_trip_rejects_projected_facts(self) -> None:
        original = RawRunObservation(
            run_id="control-scenario-1",
            variant="control",
            scenario_id="scenario",
            repetition=1,
            final_text="observed",
            metadata={"environment_fingerprint": "abc"},
        )

        restored = RawRunObservation.from_mapping(original.to_mapping())
        forged = original.to_mapping()
        forged["facts"] = {"requirements": {"question_count": 99}}

        self.assertEqual(restored, original)
        with self.assertRaisesRegex(
            ArtifactValidationError, "untrusted fields"
        ):
            RawRunObservation.from_mapping(forged)

    def test_projects_raw_observations_with_trusted_oracle(self) -> None:
        runner = FakeObservationRunner()
        oracle = FakeOracle()
        artifacts = execute_matrix(
            runner,
            oracle,
            oracle,
            variants=[VariantSpec("control"), VariantSpec("stable")],
            scenarios=[ScenarioSpec("dependency-bug", "Fix the bug")],
            repetitions=2,
        )

        self.assertEqual(len(artifacts), 4)
        self.assertEqual(
            [(run.variant, run.repetition) for run in artifacts],
            [
                ("control", 1),
                ("stable", 1),
                ("control", 2),
                ("stable", 2),
            ],
        )
        self.assertEqual(len(runner.requests), 4)
        self.assertEqual(len(oracle.project_calls), 4)
        self.assertEqual(oracle.calls, ["dependency-bug"])
        self.assertEqual(oracle.assertable_expectations, {"fixture": "trusted"})
        self.assertEqual(
            artifacts[0].facts["requirements"]["acceptance_criteria_count"], 2
        )
        self.assertIn("self_reported_score", artifacts[0].final_text)

    def test_live_runner_cannot_bypass_projector_with_an_artifact(self) -> None:
        artifact = _load_trusted_synthetic_fixtures_for_test(FIXTURE)[0]

        class BadRunner:
            def run(self, request):
                return artifact

        oracle = FakeOracle()
        with self.assertRaisesRegex(
            TypeError, "must return RawRunObservation"
        ):
            execute_matrix(
                BadRunner(),
                oracle,
                oracle,
                variants=[VariantSpec("control")],
                scenarios=[
                    ScenarioSpec("streaming-markdown-fix", "Fix the bug")
                ],
                repetitions=1,
            )

    def test_projection_must_be_owned_by_the_trusted_scenario_oracle(self) -> None:
        with self.assertRaisesRegex(
            TypeError, "trusted scenario oracle"
        ):
            execute_matrix(
                FakeObservationRunner(),
                FakeProjector(),
                FakeOracle(),
                variants=[VariantSpec("control")],
                scenarios=[ScenarioSpec("scenario", "prompt")],
                repetitions=1,
            )

    def test_rejects_unbalanced_definition_inputs(self) -> None:
        with self.assertRaisesRegex(ValueError, "variant names must be unique"):
            execute_matrix(
                FakeObservationRunner(),
                FakeProjector(),
                FakeOracle(),
                variants=[VariantSpec("same"), VariantSpec("same")],
                scenarios=[ScenarioSpec("scenario", "prompt")],
                repetitions=1,
            )


if __name__ == "__main__":
    unittest.main()
