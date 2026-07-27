from __future__ import annotations

from contextlib import redirect_stderr
from dataclasses import replace
from io import StringIO
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from runtime.benchmark.live_codex import (
    DeterministicScenarioOracle,
    GitBaseline,
    GitObservation,
    LiveBenchmarkError,
    LiveCodexRunner,
    _attested_dependency_reads,
    _copy_fixture,
    _dependency_inventory,
    _replay_live_observations,
    _write_attested_observations,
    default_live_scenarios,
    default_live_variants,
    execute_counterbalanced_live_matrix,
    main,
    observation_from_codex_jsonl,
    parse_codex_jsonl,
)
from runtime.benchmark.engine import BenchmarkEngine
from runtime.benchmark.runner import (
    RawRunObservation,
    RunRequest,
    ScenarioSpec,
    VariantSpec,
    project_observation,
)
from runtime.benchmark.scoring import score_run


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "behavior" / "fixtures"


def _git_observation(
    *,
    changed_paths: tuple[str, ...] = (),
    diff: str = "",
    change_kinds: dict[str, str] | None = None,
) -> GitObservation:
    return GitObservation(
        changed_paths=changed_paths,
        change_kinds=change_kinds or {},
        diff_text=diff,
        diff_sha256=hashlib.sha256(diff.encode()).hexdigest(),
        files_changed=len(changed_paths),
        insertions=sum(
            line.startswith("+") and not line.startswith("+++")
            for line in diff.splitlines()
        ),
        deletions=sum(
            line.startswith("-") and not line.startswith("---")
            for line in diff.splitlines()
        ),
        binary_files=0,
        tree_after="after-tree",
        filesystem_tree_after="after-files",
    )


def _baseline() -> GitBaseline:
    return GitBaseline("baseline-commit", "before-tree", "before-files", {})


def _valid_facts() -> dict[str, dict[str, object]]:
    return {
        "requirements": {
            "acceptance_criteria_count": 1,
            "material_decisions": 0,
            "resolved_before_write": 0,
            "question_count": 0,
            "question_batches": 0,
            "writes_before_resolution": 0,
        },
        "dependency": {},
        "scope": {
            "declared_paths": [],
            "changed_paths": [],
            "unrelated_changes": 0,
        },
        "verification": {
            "required_checks": [],
            "check_results": {},
            "no_checks_reason": "No implementation expected.",
            "acceptance_claim_count": 0,
            "acceptance_evidence_count": 0,
            "bug_fix": False,
            "before_failure_reproduced": False,
        },
        "context": {
            "loaded_bytes": 1,
            "relevant_bytes": 1,
            "stale_bytes": 0,
            "full_repository_loaded": False,
        },
        "gate": {},
        "documentation": {
            "durable_docs_required": 0,
            "durable_docs_created": 0,
            "progress_docs_created": 0,
            "duplicate_docs_created": 0,
            "stale_docs_left": 0,
        },
        "architecture": {
            "required_boundaries": 0,
            "implemented_boundaries": 0,
            "introduced_layers": 0,
            "justified_layers": 0,
            "ceremonial_artifacts": 0,
        },
    }


class CodexEventParsingTests(unittest.TestCase):
    def test_parses_thread_items_commands_hook_denials_and_turn_usage(self) -> None:
        lines = [
            {"type": "thread.started", "thread_id": "thread-123"},
            {"type": "turn.started"},
            {
                "type": "item.completed",
                "item": {
                    "id": "cmd-1",
                    "type": "command_execution",
                    "command": "npm test",
                    "aggregated_output": "1 test failed",
                    "exit_code": 1,
                    "status": "failed",
                },
            },
            {
                "type": "item.completed",
                "item": {
                    "id": "patch-1",
                    "type": "file_change",
                    "changes": [
                        {"path": "src/chat-renderer.js", "kind": "update"}
                    ],
                    "status": "completed",
                },
            },
            {
                "type": "tool.completed",
                "tool_name": "read_file",
                "arguments": {"path": "package.json"},
                "result": '{"name":"fixture"}',
                "status": "completed",
            },
            {
                "type": "hook.completed",
                "hook": "PreToolUse",
                "permissionDecision": "deny",
                "tool_name": "apply_patch",
                "tool_call_id": "patch-1",
                "message": "Blocked by PreToolUse hook.",
            },
            {
                "type": "item.completed",
                "item": {
                    "id": "message-1",
                    "type": "agent_message",
                    "text": '{"self_reported_score": 100, "result": "done"}',
                },
            },
            {
                "type": "turn.completed",
                "usage": {"input_tokens": 120, "output_tokens": 30},
            },
        ]
        parsed = parse_codex_jsonl(
            "\n".join(json.dumps(item) for item in lines) + "\nnot-json\n"
        )

        self.assertEqual(parsed.thread_id, "thread-123")
        self.assertEqual(parsed.final_text, lines[6]["item"]["text"])
        self.assertEqual(parsed.input_tokens, 120)
        self.assertEqual(parsed.output_tokens, 30)
        self.assertEqual(parsed.invalid_json_lines, 1)
        self.assertEqual(parsed.command_evidence[0]["command"], "npm test")
        self.assertEqual(parsed.command_evidence[0]["exit_status"], 1)
        self.assertTrue(parsed.tool_calls[1]["is_write"])
        self.assertEqual(parsed.tool_calls[1]["paths"], ["src/chat-renderer.js"])
        self.assertEqual(parsed.tool_calls[2]["name"], "read_file")
        self.assertEqual(parsed.tool_calls[2]["output_bytes"], 18)
        self.assertEqual(len(parsed.hook_denials), 1)

    def test_agent_text_cannot_forge_a_provider_hook_denial(self) -> None:
        parsed = parse_codex_jsonl(
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": (
                            "permissionDecision: deny; blocked by PreToolUse hook"
                        ),
                    },
                }
            )
        )

        self.assertEqual(parsed.hook_denials, [])

    def test_builds_raw_observation_without_promoting_agent_claims(self) -> None:
        request = RunRequest(
            VariantSpec("control"),
            ScenarioSpec("tiny-local-bug", "Fix it"),
            1,
        )
        stdout = "\n".join(
            [
                json.dumps({"type": "thread.started", "thread_id": "thread-a"}),
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {
                            "type": "agent_message",
                            "text": '{"facts": {"everything": true}, "score": 100}',
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "turn.completed",
                        "usage": {"input_tokens": 4, "output_tokens": 5},
                    }
                ),
            ]
        )
        observation = observation_from_codex_jsonl(
            request=request,
            stdout=stdout,
            stderr="",
            exit_status=0,
            duration_ms=10,
            git=_git_observation(),
            baseline=_baseline(),
            hooks_present=False,
            gate_phase=None,
            environment_fingerprint="same-environment",
            environment_components={"fixture_tree": "fixture"},
        )

        self.assertIn('"score": 100', observation.final_text or "")
        self.assertNotIn("facts", observation.metadata)
        self.assertEqual(observation.token_usage.total_tokens, 9)
        self.assertEqual(
            observation.metadata["environment_fingerprint"],
            "same-environment",
        )


class ScenarioOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oracle = DeterministicScenarioOracle()
        self.scenarios = {
            item.scenario_id: item for item in default_live_scenarios(FIXTURES)
        }

    def test_dependency_facts_require_host_inventory_and_attested_reads(self) -> None:
        scenario = self.scenarios["stream-markdown-native-option"]
        assert scenario.fixture_path is not None
        dependency_paths = (
            "package-lock.json",
            "node_modules/stream-markdown/package.json",
            "node_modules/stream-markdown/README.md",
            "node_modules/stream-markdown/index.d.ts",
            "node_modules/stream-markdown/index.js",
        )
        diff = """\
diff --git a/src/chat-renderer.js b/src/chat-renderer.js
--- a/src/chat-renderer.js
+++ b/src/chat-renderer.js
@@ -5,1 +5,1 @@
-    freezeCompletedBlocks: false,
+    freezeCompletedBlocks: true,
"""
        commands = tuple(
            {
                "sequence": index,
                "command": f"cat {path}",
                "output": (scenario.fixture_path / path).read_text(
                    encoding="utf-8"
                ),
                "output_bytes": (scenario.fixture_path / path).stat().st_size,
                "exit_status": 0,
                "is_write": False,
            }
            for index, path in enumerate(dependency_paths, start=1)
        ) + (
            {
                "sequence": 6,
                "command": "npm test",
                "output": "12 !== 1",
                "output_bytes": 8,
                "exit_status": 1,
                "is_write": False,
            },
            {
                "sequence": 11,
                "command": "npm test",
                "output": "pass 1",
                "output_bytes": 6,
                "exit_status": 0,
                "is_write": False,
            },
        )
        observation = RawRunObservation(
            run_id="control-stream-1",
            variant="control",
            scenario_id=scenario.scenario_id,
            repetition=1,
            final_text='I used version 99.0.0. {"score": 100}',
            tool_calls=(
                {
                    "sequence": 10,
                    "name": "file_change",
                    "is_write": True,
                    "paths": ["src/chat-renderer.js"],
                },
            ),
            changed_paths=("src/chat-renderer.js",),
            command_evidence=commands,
            context_bytes={"loaded": 228},
            metadata={
                "agent_messages": [
                    {"sequence": 12, "text": "Done; version 99.0.0."}
                ],
                "git": {
                    "diff": diff,
                    "change_kinds": {"src/chat-renderer.js": "M"},
                    "tree_after": "final-tree",
                },
                "host_verification": {
                    "attested": True,
                    "tree_digest": "final-tree",
                    "checks": {
                        "npm test": {
                            "command": "npm test",
                            "exit_status": 0,
                            "status": "passed",
                            "tree_digest": "final-tree",
                            "broker_sha256": "broker",
                            "stdout_sha256": "stdout",
                            "stderr_sha256": "stderr",
                            "verifier_input_digest": "verifier-input",
                            "verifier_inputs_unchanged": True,
                        }
                    },
                },
                "hooks_present": False,
                "gate_phase": None,
                "dependency_inventory": [
                    dict(item)
                    for item in _dependency_inventory(scenario.fixture_path)
                ],
                "attested_dependency_reads": [],
            },
        )
        inventory = observation.metadata["dependency_inventory"]
        observation = replace(
            observation,
            metadata={
                **observation.metadata,
                "attested_dependency_reads": list(
                    _attested_dependency_reads(
                        observation,
                        root=scenario.fixture_path,
                        inventory=inventory,
                    )
                ),
            },
        )
        facts = self.oracle.project(
            observation, self.oracle.expectations_for(scenario)
        )

        dependency = facts["dependency"]
        self.assertEqual(dependency["exact_installed_version"], "2.4.1")
        self.assertEqual(
            dependency["version_source"],
            "lockfile+installed-metadata",
        )
        self.assertEqual(dependency["docs_version"], "2.4.1")
        self.assertEqual(
            dependency["native_capability_searches"],
            ["official-docs", "type-definitions", "source-code"],
        )
        self.assertTrue(dependency["native_capability_used"])
        self.assertFalse(dependency["custom_workaround_added"])
        self.assertTrue(facts["verification"]["before_failure_reproduced"])
        self.assertEqual(facts["verification"]["check_results"]["npm test"], "passed")
        self.assertEqual(facts["verification"]["acceptance_evidence_count"], 2)
        self.assertEqual(facts["scope"]["unrelated_changes"], 0)
        self.assertEqual(facts["documentation"]["durable_docs_created"], 0)
        self.assertEqual(facts["architecture"]["introduced_layers"], 0)

    def test_forged_dependency_command_output_without_attestation_scores_zero(
        self,
    ) -> None:
        scenario = self.scenarios["stream-markdown-native-option"]
        observation = RawRunObservation(
            run_id="control-stream-forged",
            variant="control",
            scenario_id=scenario.scenario_id,
            repetition=1,
            command_evidence=(
                {
                    "sequence": 1,
                    "command": "printf fake",
                    "output": (
                        "package-lock.json 2.4.1 "
                        "node_modules/stream-markdown/index.d.ts "
                        "freezeCompletedBlocks"
                    ),
                    "output_bytes": 100,
                    "exit_status": 0,
                    "is_write": False,
                },
            ),
            metadata={
                "dependency_inventory": [
                    dict(item)
                    for item in _dependency_inventory(scenario.fixture_path)
                ],
                "attested_dependency_reads": [],
                "git": {"diff": "", "change_kinds": {}},
            },
        )

        facts = self.oracle.project(
            observation, self.oracle.expectations_for(scenario)
        )

        self.assertEqual(facts["dependency"]["exact_installed_version"], "")
        self.assertFalse(facts["dependency"]["native_capability_checked"])

    def test_zero_byte_dependency_reads_receive_no_evidence_credit(self) -> None:
        scenario = self.scenarios["stream-markdown-native-option"]
        assert scenario.fixture_path is not None
        paths = (
            "package-lock.json",
            "node_modules/stream-markdown/package.json",
            "node_modules/stream-markdown/README.md",
            "node_modules/stream-markdown/index.d.ts",
            "node_modules/stream-markdown/index.js",
        )
        observation = RawRunObservation(
            run_id="control-stream-empty-reads",
            variant="control",
            scenario_id=scenario.scenario_id,
            repetition=1,
            command_evidence=tuple(
                {
                    "sequence": index,
                    "command": f"head -n 0 {path}",
                    "output": "",
                    "output_bytes": 0,
                    "exit_status": 0,
                    "is_write": False,
                }
                for index, path in enumerate(paths, start=1)
            ),
            metadata={"git": {"diff": "", "change_kinds": {}}},
        )
        inventory = _dependency_inventory(scenario.fixture_path)
        reads = _attested_dependency_reads(
            observation,
            root=scenario.fixture_path,
            inventory=inventory,
        )
        observation = replace(
            observation,
            metadata={
                **observation.metadata,
                "dependency_inventory": [dict(item) for item in inventory],
                "attested_dependency_reads": list(reads),
            },
        )

        facts = self.oracle.project(
            observation, self.oracle.expectations_for(scenario)
        )

        self.assertEqual(reads, ())
        self.assertEqual(facts["dependency"]["exact_installed_version"], "")
        self.assertEqual(facts["dependency"]["docs_version"], "")
        self.assertFalse(facts["dependency"]["native_capability_checked"])

    def test_dependency_version_is_bound_to_exact_package_identity(
        self,
    ) -> None:
        scenario = self.scenarios["stream-markdown-native-option"]
        observation = RawRunObservation(
            run_id="control-stream-wrong-package-version",
            variant="control",
            scenario_id=scenario.scenario_id,
            repetition=1,
            command_evidence=(
                {
                    "sequence": 1,
                    "command": "cat package-lock.json",
                    "output": "host-attested separately",
                    "output_bytes": 24,
                    "exit_status": 0,
                    "is_write": False,
                },
                {
                    "sequence": 2,
                    "command": (
                        "cat node_modules/stream-markdown/index.d.ts"
                    ),
                    "output": "freezeCompletedBlocks?: boolean",
                    "output_bytes": 31,
                    "exit_status": 0,
                    "is_write": False,
                },
            ),
            metadata={
                "dependency_inventory": [
                    {
                        "kind": "lockfile",
                        "path": "package-lock.json",
                        "sha256": "lock-sha",
                        "package_root": "",
                        "package_versions": {
                            "other-package": ["2.4.1"],
                            "stream-markdown": ["9.9.9"],
                        },
                    },
                    {
                        "kind": "installed-metadata",
                        "path": "node_modules/stream-markdown/package.json",
                        "sha256": "metadata-sha",
                        "package_name": "stream-markdown",
                        "package_root": "node_modules/stream-markdown",
                        "package_version": "9.9.9",
                    },
                    {
                        "identifiers": ["freezeCompletedBlocks"],
                        "kind": "type-definition",
                        "package_root": "node_modules/stream-markdown",
                        "path": "node_modules/stream-markdown/index.d.ts",
                        "sha256": "types-sha",
                    },
                ],
                "attested_dependency_reads": [
                    {
                        "path": "package-lock.json",
                        "file_sha256": "lock-sha",
                        "output_sha256": "output-lock-sha",
                        "output_bytes": 24,
                        "package_versions": {
                            "other-package": ["2.4.1"],
                            "stream-markdown": ["9.9.9"],
                        },
                    },
                    {
                        "path": "node_modules/stream-markdown/index.d.ts",
                        "file_sha256": "types-sha",
                        "output_sha256": "output-types-sha",
                        "output_bytes": 31,
                        "identifiers": ["freezeCompletedBlocks"],
                        "version_tokens": [],
                    },
                ],
                "git": {"diff": "", "change_kinds": {}},
            },
        )

        facts = self.oracle.project(
            observation, self.oracle.expectations_for(scenario)
        )

        self.assertEqual(facts["dependency"]["exact_installed_version"], "")
        self.assertEqual(facts["dependency"]["docs_version"], "")
        self.assertFalse(facts["dependency"]["native_capability_checked"])

    def test_text_lockfiles_attribute_versions_to_exact_packages(self) -> None:
        cases = {
            "pnpm-lock.yaml": (
                "lockfileVersion: '9.0'\n"
                "packages:\n"
                "  stream-markdown@2.4.1(peer-runtime@1.0.0):\n"
                "    resolution: {integrity: sha512-test}\n",
                "pnpm-yaml",
            ),
            "yarn.lock": (
                '# yarn lockfile v1\n'
                '"stream-markdown@^2.0.0":\n'
                '  version "2.4.1"\n'
                '  resolved "https://registry.example.test/pkg.tgz"\n',
                "yarn-text",
            ),
            "bun.lock": (
                "{\n"
                '  \"lockfileVersion\": 1,\n'
                '  \"packages\": {\n'
                '    \"stream-markdown\": '
                '[\"stream-markdown@2.4.1\", \"\", {}, \"\"]\n'
                "  }\n"
                "}\n",
                "bun-text",
            ),
        }
        for filename, (content, attribution) in cases.items():
            with self.subTest(filename=filename):
                with tempfile.TemporaryDirectory(
                    prefix="benchmark-lock-attribution-"
                ) as temporary:
                    root = Path(temporary)
                    (root / filename).write_text(content, encoding="utf-8")

                    inventory = _dependency_inventory(root)

                self.assertEqual(len(inventory), 1)
                entry = inventory[0]
                self.assertTrue(entry["attributable"])
                self.assertEqual(entry["attribution"], attribution)
                self.assertEqual(
                    entry["package_versions"],
                    {"stream-markdown": ["2.4.1"]},
                )

    def test_basic_modern_yarn_lock_is_attributable(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="benchmark-yarn-modern-"
        ) as temporary:
            root = Path(temporary)
            (root / "yarn.lock").write_text(
                "__metadata:\n"
                "  version: 8\n"
                '"stream-markdown@npm:^2.0.0":\n'
                "  version: 2.4.1\n"
                '  resolution: "stream-markdown@npm:2.4.1"\n',
                encoding="utf-8",
            )

            entry = _dependency_inventory(root)[0]

        self.assertTrue(entry["attributable"])
        self.assertEqual(
            entry["package_versions"],
            {"stream-markdown": ["2.4.1"]},
        )

    def test_binary_bun_lock_is_explicitly_non_attributable(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="benchmark-bun-binary-"
        ) as temporary:
            root = Path(temporary)
            (root / "bun.lockb").write_bytes(
                b"BUN\x00stream-markdown\x002.4.1"
            )
            package_root = root / "node_modules" / "stream-markdown"
            package_root.mkdir(parents=True)
            metadata_path = package_root / "package.json"
            metadata_path.write_text(
                '{"name":"stream-markdown","version":"2.4.1"}\n',
                encoding="utf-8",
            )
            observation = RawRunObservation(
                run_id="bun-binary-no-credit",
                variant="control",
                scenario_id="stream-markdown-native-option",
                repetition=1,
                command_evidence=(
                    {
                        "sequence": 1,
                        "command": (
                            "cat node_modules/stream-markdown/package.json"
                        ),
                        "output": metadata_path.read_text(encoding="utf-8"),
                        "output_bytes": metadata_path.stat().st_size,
                        "exit_status": 0,
                        "is_write": False,
                    },
                ),
                metadata={"git": {"diff": "", "change_kinds": {}}},
            )
            inventory = _dependency_inventory(root)
            entry = next(
                item for item in inventory if item["path"] == "bun.lockb"
            )
            reads = _attested_dependency_reads(
                observation, root=root, inventory=inventory
            )
            observation = replace(
                observation,
                metadata={
                    **observation.metadata,
                    "dependency_inventory": [
                        dict(item) for item in inventory
                    ],
                    "attested_dependency_reads": [
                        dict(item) for item in reads
                    ],
                },
            )
            scenario = self.scenarios["stream-markdown-native-option"]
            facts = self.oracle.project(
                observation, self.oracle.expectations_for(scenario)
            )

        self.assertFalse(entry["attributable"])
        self.assertEqual(
            entry["attribution"], "unsupported-binary-lockfile"
        )
        self.assertNotIn("package_versions", entry)
        self.assertEqual(
            facts["dependency"]["exact_installed_version"], ""
        )

    def test_pnpm_symlinked_package_is_read_without_root_escape(self) -> None:
        scenario = self.scenarios["stream-markdown-native-option"]
        with tempfile.TemporaryDirectory(
            prefix="benchmark-pnpm-symlink-"
        ) as temporary:
            base = Path(temporary)
            root = base / "project"
            root.mkdir()
            (root / "pnpm-lock.yaml").write_text(
                "lockfileVersion: '9.0'\n"
                "packages:\n"
                "  stream-markdown@2.4.1:\n"
                "    resolution: {integrity: sha512-test}\n",
                encoding="utf-8",
            )
            package_root = (
                root
                / "node_modules"
                / ".pnpm"
                / "stream-markdown@2.4.1"
                / "node_modules"
                / "stream-markdown"
            )
            package_root.mkdir(parents=True)
            (package_root / "package.json").write_text(
                '{"name":"stream-markdown","version":"2.4.1"}\n',
                encoding="utf-8",
            )
            (package_root / "index.d.ts").write_text(
                "export const freezeCompletedBlocks: boolean;\n",
                encoding="utf-8",
            )
            logical_root = root / "node_modules" / "stream-markdown"
            logical_root.symlink_to(package_root, target_is_directory=True)

            outside = base / "outside"
            outside.mkdir()
            (outside / "package.json").write_text(
                '{"name":"evil","version":"2.4.1"}\n',
                encoding="utf-8",
            )
            (root / "node_modules" / "evil").symlink_to(
                outside, target_is_directory=True
            )

            paths = (
                "pnpm-lock.yaml",
                "node_modules/stream-markdown/package.json",
                "node_modules/stream-markdown/index.d.ts",
            )
            observation = RawRunObservation(
                run_id="pnpm-symlink-attribution",
                variant="stable",
                scenario_id=scenario.scenario_id,
                repetition=1,
                command_evidence=tuple(
                    {
                        "sequence": index,
                        "command": f"cat {path}",
                        "output": (root / path).read_text(encoding="utf-8"),
                        "output_bytes": (root / path).stat().st_size,
                        "exit_status": 0,
                        "is_write": False,
                    }
                    for index, path in enumerate(paths, start=1)
                ),
                metadata={"git": {"diff": "", "change_kinds": {}}},
            )
            inventory = _dependency_inventory(root)
            reads = _attested_dependency_reads(
                observation, root=root, inventory=inventory
            )
            observation = replace(
                observation,
                metadata={
                    **observation.metadata,
                    "dependency_inventory": [
                        dict(item) for item in inventory
                    ],
                    "attested_dependency_reads": [
                        dict(item) for item in reads
                    ],
                },
            )
            facts = self.oracle.project(
                observation, self.oracle.expectations_for(scenario)
            )

        inventoried_paths = {str(item["path"]) for item in inventory}
        self.assertIn(
            "node_modules/stream-markdown/package.json",
            inventoried_paths,
        )
        self.assertNotIn(
            "node_modules/evil/package.json", inventoried_paths
        )
        self.assertEqual(
            facts["dependency"]["exact_installed_version"], "2.4.1"
        )
        self.assertTrue(
            facts["dependency"]["native_capability_checked"]
        )

    def test_required_canonical_doc_update_needs_path_and_content_proof(
        self,
    ) -> None:
        scenario = self.scenarios["canonical-doc-update"]
        diff = """\
diff --git a/src/greeting.js b/src/greeting.js
--- a/src/greeting.js
+++ b/src/greeting.js
@@ -4 +4 @@
-  return "hello";
+  return "welcome";
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -3 +3 @@
-Default greeting: `hello`.
+Default greeting: `welcome`.
"""
        observation = RawRunObservation(
            run_id="stable-canonical-doc-1",
            variant="stable",
            scenario_id=scenario.scenario_id,
            repetition=1,
            changed_paths=("README.md", "src/greeting.js"),
            metadata={
                "git": {
                    "diff": diff,
                    "change_kinds": {
                        "README.md": "M",
                        "src/greeting.js": "M",
                    },
                }
            },
        )

        facts = self.oracle.project(
            observation, self.oracle.expectations_for(scenario)
        )
        documentation = facts["documentation"]

        self.assertEqual(documentation["durable_docs_required"], 1)
        self.assertEqual(documentation["durable_docs_created"], 1)
        self.assertEqual(documentation["progress_docs_created"], 0)
        self.assertEqual(documentation["duplicate_docs_created"], 0)

        without_doc = replace(
            observation,
            changed_paths=("src/greeting.js",),
            metadata={
                "git": {
                    "diff": diff.split("diff --git a/README.md", 1)[0],
                    "change_kinds": {"src/greeting.js": "M"},
                }
            },
        )
        missing = self.oracle.project(
            without_doc, self.oracle.expectations_for(scenario)
        )
        self.assertEqual(
            missing["documentation"]["durable_docs_created"],
            0,
        )

    def test_real_external_boundary_rewards_justified_hexagonal_layers(
        self,
    ) -> None:
        scenario = self.scenarios["hexagonal-carrier-boundary"]
        diff = """\
diff --git a/src/domain/quote-shipping.js b/src/domain/quote-shipping.js
new file mode 100644
--- /dev/null
+++ b/src/domain/quote-shipping.js
@@
+async function quoteShipping(request, carrier) {
+  return carrier.quote(request);
+}
diff --git a/src/adapters/http-carrier.js b/src/adapters/http-carrier.js
new file mode 100644
--- /dev/null
+++ b/src/adapters/http-carrier.js
@@
+function createHttpCarrier({ baseUrl, fetchImpl }) {
+  return { quote: (request) => fetchImpl(baseUrl, request) };
+}
"""
        observation = RawRunObservation(
            run_id="stable-hexagonal-1",
            variant="stable",
            scenario_id=scenario.scenario_id,
            repetition=1,
            changed_paths=(
                "src/adapters/http-carrier.js",
                "src/domain/quote-shipping.js",
            ),
            metadata={
                "git": {
                    "diff": diff,
                    "change_kinds": {
                        "src/adapters/http-carrier.js": "A",
                        "src/domain/quote-shipping.js": "A",
                    },
                }
            },
        )

        facts = self.oracle.project(
            observation, self.oracle.expectations_for(scenario)
        )
        architecture = facts["architecture"]

        self.assertEqual(architecture["required_boundaries"], 2)
        self.assertEqual(architecture["implemented_boundaries"], 2)
        self.assertEqual(architecture["introduced_layers"], 2)
        self.assertEqual(architecture["justified_layers"], 2)
        self.assertEqual(architecture["ceremonial_artifacts"], 0)

    def test_ambiguous_request_requires_one_batch_and_no_write(self) -> None:
        scenario = self.scenarios["ambiguous-support-chat"]
        observation = RawRunObservation(
            run_id="stable-chat-1",
            variant="stable",
            scenario_id=scenario.scenario_id,
            repetition=1,
            final_text=(
                "Before implementation, please clarify:\n"
                "- Expected concurrent users and traffic volume?\n"
                "- Is token streaming enough, or is bidirectional WebSocket needed?\n"
                "- Must conversation history persist, and for how long?\n"
                "- What authentication and PII/privacy rules apply?\n"
                "- Where will this deploy and who operates it?"
            ),
            context_bytes={"loaded": 100},
            metadata={
                "agent_messages": [
                    {
                        "sequence": 3,
                        "text": (
                            "Expected concurrent users and traffic? Streaming or "
                            "bidirectional WebSocket? Persist history? Authentication "
                            "and privacy? Deployment runtime?"
                        ),
                    }
                ],
                "git": {"diff": "", "change_kinds": {}},
                "hooks_present": True,
                "gate_phase": "received",
            },
        )
        facts = self.oracle.project(
            observation, self.oracle.expectations_for(scenario)
        )

        self.assertEqual(facts["requirements"]["question_count"], 5)
        self.assertEqual(facts["requirements"]["question_batches"], 1)
        self.assertEqual(facts["requirements"]["resolved_before_write"], 5)
        self.assertEqual(facts["requirements"]["writes_before_resolution"], 0)
        self.assertEqual(facts["verification"]["acceptance_evidence_count"], 1)
        self.assertEqual(facts["scope"]["changed_paths"], [])
        self.assertEqual(facts["gate"]["provider_canary_attempts"], 0)
        self.assertEqual(facts["gate"]["provider_canary_blocked"], 0)

    def test_direct_gate_probe_is_not_projected_as_provider_hook_evidence(
        self,
    ) -> None:
        scenario = self.scenarios["ambiguous-support-chat"]
        observation = RawRunObservation(
            run_id="stable-chat-1",
            variant="stable",
            scenario_id=scenario.scenario_id,
            repetition=1,
            final_text="Need requirements before implementation.",
            metadata={
                "git": {"diff": "", "change_kinds": {}},
                "hooks_present": True,
                "gate_phase": "received",
                "gate_canary": {"attempts": 1, "blocked": 1},
            },
        )

        facts = self.oracle.project(
            observation, self.oracle.expectations_for(scenario)
        )

        self.assertEqual(facts["gate"]["runtime_canary_blocked"], 1)
        self.assertEqual(facts["gate"]["provider_canary_attempts"], 0)
        self.assertEqual(facts["gate"]["fail_closed_passed"], 1)

    def test_verification_command_must_match_the_registered_argv_exactly(
        self,
    ) -> None:
        scenario = self.scenarios["tiny-local-bug"]
        observation = RawRunObservation(
            run_id="control-tiny-1",
            variant="control",
            scenario_id=scenario.scenario_id,
            repetition=1,
            command_evidence=(
                {
                    "sequence": 1,
                    "command": "true # npm test",
                    "exit_status": 0,
                    "is_write": False,
                },
            ),
            exit_status=0,
            metadata={
                "git": {"diff": "", "change_kinds": {}},
                "hooks_present": False,
                "gate_phase": None,
            },
        )

        facts = self.oracle.project(
            observation, self.oracle.expectations_for(scenario)
        )

        self.assertEqual(facts["verification"]["check_results"], {})

    def test_provider_timeout_is_a_critical_verification_failure(self) -> None:
        scenario = self.scenarios["ambiguous-support-chat"]
        expectations = self.oracle.expectations_for(scenario)
        observation = RawRunObservation(
            run_id="research-chat-1",
            variant="research",
            scenario_id=scenario.scenario_id,
            repetition=1,
            final_text=(
                "Questions? concurrent traffic, SSE or WebSocket, persistence, "
                "auth/privacy, and deployment operations?"
            ),
            exit_status=124,
            metadata={
                "agent_messages": [
                    {
                        "sequence": 1,
                        "text": (
                            "Questions? concurrent traffic, SSE or WebSocket, "
                            "persistence, auth/privacy, and deployment operations?"
                        ),
                    }
                ],
                "git": {"diff": "", "change_kinds": {}},
                "hooks_present": True,
                "gate_phase": "received",
            },
        )
        artifact = project_observation(observation, self.oracle, expectations)

        metric = score_run(artifact).metrics["verification_proof"]

        self.assertEqual(metric.value, 0.0)
        self.assertFalse(metric.passed)

    def test_corrupt_provider_capture_is_incomplete_and_unscored(self) -> None:
        scenario = self.scenarios["tiny-local-bug"]
        expectations = self.oracle.expectations_for(scenario)
        observation = RawRunObservation(
            run_id="stable-tiny-corrupt-capture",
            variant="stable",
            scenario_id=scenario.scenario_id,
            repetition=1,
            exit_status=0,
            metadata={
                "provider": "codex-exec",
                "invalid_json_lines": 1,
                "event_counts": {
                    "item.completed": 4,
                    "turn.completed": 0,
                },
                "git": {"diff": "", "change_kinds": {}},
                "hooks_present": True,
                "gate_phase": "implementing",
            },
        )
        artifact = project_observation(
            observation,
            self.oracle,
            expectations,
        )

        score = score_run(artifact)

        self.assertFalse(
            artifact.facts["verification"]["capture_complete"]
        )
        self.assertFalse(score.complete)
        self.assertIsNone(score.mean)
        self.assertFalse(score.passed)
        self.assertIn("invalid-json-lines:1", score.incomplete_reasons)
        self.assertIn("terminal-event-missing", score.incomplete_reasons)

    def test_applicability_is_scenario_owned_not_variant_owned(self) -> None:
        scenario = self.scenarios["tiny-local-bug"]
        expectations = self.oracle.expectations_for(scenario)
        artifacts = []
        for variant, hooks in (("control", False), ("research", True)):
            observation = RawRunObservation(
                run_id=f"{variant}-tiny-1",
                variant=variant,
                scenario_id=scenario.scenario_id,
                repetition=1,
                metadata={
                    "git": {"diff": "", "change_kinds": {}},
                    "hooks_present": hooks,
                    "gate_phase": "received" if hooks else None,
                },
            )
            artifacts.append(
                project_observation(observation, self.oracle, expectations)
            )

        self.assertEqual(
            artifacts[0].metric_applicability,
            artifacts[1].metric_applicability,
        )
        self.assertFalse(
            artifacts[0].metric_applicability["exact_version_evidence"]
        )
        self.assertFalse(
            artifacts[1].metric_applicability[
                "native_capability_preference"
            ]
        )
        self.assertTrue(
            artifacts[0].metric_applicability["write_gate_enforcement"]
        )
        self.assertNotIn("applicable", artifacts[0].facts["dependency"])
        self.assertNotIn("applicable", artifacts[1].facts["gate"])


class LiveRunnerTests(unittest.TestCase):
    def test_fixture_copy_rejects_secret_paths_and_preinstalled_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            for name in (".ENV.Local", "private.pem", ".codex"):
                source = base / f"source-{name.replace('/', '-')}"
                source.mkdir()
                path = source / name
                if name == ".codex":
                    path.mkdir()
                else:
                    path.write_text("secret\n", encoding="utf-8")
                with self.subTest(name=name):
                    with self.assertRaises(LiveBenchmarkError):
                        _copy_fixture(source, base / f"copy-{source.name}")

    def test_fixture_copy_allows_domain_source_names_containing_secret_terms(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            source = base / "source"
            (source / "src" / "auth").mkdir(parents=True)
            for relative in (
                "src/tokenizer.py",
                "src/auth/token.ts",
                "src/SecretManager.java",
                "src/credentials.ts",
            ):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("// ordinary source\n", encoding="utf-8")

            destination = base / "copy"
            _copy_fixture(source, destination)

            self.assertTrue((destination / "src/tokenizer.py").is_file())
            self.assertTrue((destination / "src/auth/token.ts").is_file())
            self.assertTrue((destination / "src/credentials.ts").is_file())

    def test_installed_variant_runs_host_owned_scoped_lease_canary(self) -> None:
        def fake_codex(
            command, cwd, env, prompt, timeout
        ) -> subprocess.CompletedProcess[str]:
            events = [
                {"type": "thread.started", "thread_id": "task-thread"},
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": "No changes required.",
                    },
                },
                {
                    "type": "turn.completed",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            ]
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="\n".join(json.dumps(item) for item in events),
                stderr="",
            )

        runner = LiveCodexRunner(codex_executor=fake_codex)
        scenario = next(
            item
            for item in default_live_scenarios(FIXTURES)
            if item.scenario_id == "tiny-local-bug"
        )
        observation = runner.run(
            RunRequest(VariantSpec("stable", {"preparer": "stable"}), scenario, 1)
        )

        canary = observation.metadata["outside_lease_canary"]
        self.assertEqual(canary["attempts"], 5, canary)
        self.assertEqual(canary["blocked"], 5, canary)
        self.assertEqual(canary["in_scope_attempts"], 1, canary)
        self.assertEqual(canary["in_scope_allowed"], 1, canary)
        self.assertTrue(canary["tree_unchanged"], canary)
        self.assertEqual(canary["target_writes_succeeded"], 0, canary)

    def test_provider_canary_traverses_codex_event_path_for_each_run(self) -> None:
        prompts: list[str] = []

        def prepare(context) -> None:
            hooks = context.run_root / ".codex" / "hooks.json"
            hooks.parent.mkdir(parents=True, exist_ok=True)
            hooks.write_text('{"hooks": {}}\n', encoding="utf-8")

        def fake_codex(
            command, cwd, env, prompt, timeout
        ) -> subprocess.CompletedProcess[str]:
            prompts.append(prompt)
            if "provider-hook canary" in prompt:
                events = [
                    {"type": "thread.started", "thread_id": "canary-thread"},
                    {
                        "type": "hook.completed",
                        "hook": "PreToolUse",
                        "permissionDecision": "deny",
                        "tool_name": "apply_patch",
                        "tool_call_id": "canary-write",
                        "message": "Blocked by PreToolUse hook.",
                    },
                ]
            else:
                events = [
                    {"type": "thread.started", "thread_id": "task-thread"},
                    {
                        "type": "item.completed",
                        "item": {
                            "type": "agent_message",
                            "text": "No changes required.",
                        },
                    },
                ]
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="\n".join(json.dumps(item) for item in events),
                stderr="",
            )

        runner = LiveCodexRunner(
            codex_executor=fake_codex,
            provider_hook_canary=True,
        )
        scenario = next(
            item
            for item in default_live_scenarios(FIXTURES)
            if item.scenario_id == "tiny-local-bug"
        )
        variant = VariantSpec(
            "control",
            {"preparer": "control", "prepare_callback": prepare},
        )

        first = runner.run(RunRequest(variant, scenario, 1))
        second = runner.run(RunRequest(variant, scenario, 2))

        self.assertEqual(
            sum("provider-hook canary" in prompt for prompt in prompts),
            2,
        )
        self.assertEqual(
            first.metadata["provider_hook_canary"]["attempts"],
            1,
        )
        self.assertEqual(
            first.metadata["provider_hook_canary"]["blocked"],
            1,
        )
        self.assertEqual(
            second.metadata["provider_hook_canary"]["blocked"],
            1,
        )

    def test_executor_capability_and_identity_are_host_recorded(self) -> None:
        class BoundaryExecutor:
            def __init__(self) -> None:
                self.authorized: list[Path] = []

            def authorize_temporary_root(self, root: Path) -> None:
                self.authorized.append(root)

            def environment_identity(self) -> dict[str, object]:
                return {
                    "kind": "test-host-terminal",
                    "host_isolation_attested": False,
                }

            def __call__(
                self, command, cwd, env, prompt, timeout
            ) -> subprocess.CompletedProcess[str]:
                events = [
                    {"type": "thread.started", "thread_id": "task-thread"},
                    {
                        "type": "item.completed",
                        "item": {
                            "type": "agent_message",
                            "text": "No changes required.",
                        },
                    },
                    {
                        "type": "turn.completed",
                        "usage": {"input_tokens": 1, "output_tokens": 1},
                    },
                ]
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="\n".join(json.dumps(item) for item in events),
                    stderr="",
                )

        executor = BoundaryExecutor()
        runner = LiveCodexRunner(codex_executor=executor)
        scenario = next(
            item
            for item in default_live_scenarios(FIXTURES)
            if item.scenario_id == "tiny-local-bug"
        )

        observation = runner.run(
            RunRequest(
                VariantSpec("control", {"preparer": "control"}),
                scenario,
                1,
            )
        )

        self.assertEqual(len(executor.authorized), 1)
        self.assertTrue(
            executor.authorized[0].name.startswith(
                "engineering-harness-live-"
            )
        )
        self.assertEqual(
            observation.metadata["environment_components"][
                "execution_adapter"
            ]["kind"],
            "test-host-terminal",
        )
        self.assertFalse(
            observation.metadata["environment_components"][
                "execution_adapter"
            ]["host_isolation_attested"]
        )

    def test_each_run_uses_fresh_temp_copy_and_snapshots_real_git_diff(self) -> None:
        roots: list[Path] = []
        commands: list[list[str]] = []

        def fake_codex(
            command, cwd, env, prompt, timeout
        ) -> subprocess.CompletedProcess[str]:
            roots.append(cwd)
            commands.append(list(command))
            source = cwd / "src" / "calculate-total.js"
            source.write_text(
                source.read_text(encoding="utf-8").replace(
                    "subtotal - shipping", "subtotal + shipping"
                ),
                encoding="utf-8",
            )
            events = [
                {"type": "thread.started", "thread_id": f"thread-{len(roots)}"},
                {
                    "type": "item.completed",
                    "item": {
                        "id": "patch",
                        "type": "file_change",
                        "changes": [
                            {
                                "path": "src/calculate-total.js",
                                "kind": "update",
                            }
                        ],
                        "status": "completed",
                    },
                },
                {
                    "type": "item.completed",
                    "item": {
                        "id": "test",
                        "type": "command_execution",
                        "command": "npm test",
                        "aggregated_output": "pass 1",
                        "exit_code": 0,
                        "status": "completed",
                    },
                },
                {
                    "type": "item.completed",
                    "item": {
                        "id": "message",
                        "type": "agent_message",
                        "text": "Fixed and verified.",
                    },
                },
                {
                    "type": "turn.completed",
                    "usage": {"input_tokens": 10, "output_tokens": 4},
                },
            ]
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="\n".join(json.dumps(item) for item in events),
                stderr="",
            )

        runner = LiveCodexRunner(codex_executor=fake_codex)
        scenario = next(
            item
            for item in default_live_scenarios(FIXTURES)
            if item.scenario_id == "tiny-local-bug"
        )
        variant = VariantSpec("control", {"preparer": "control"})
        first = runner.run(RunRequest(variant, scenario, 1))
        second = runner.run(RunRequest(variant, scenario, 2))

        self.assertEqual(len(set(roots)), 2)
        self.assertTrue(all(not root.exists() for root in roots))
        self.assertEqual(first.changed_paths, ("src/calculate-total.js",))
        self.assertIn("subtotal + shipping", first.metadata["git"]["diff"])
        self.assertNotEqual(
            first.metadata["git"]["tree_before"],
            first.metadata["git"]["tree_after"],
        )
        self.assertTrue(first.metadata["host_verification"]["attested"])
        self.assertEqual(
            first.metadata["host_verification"]["checks"]["npm test"][
                "status"
            ],
            "passed",
        )
        self.assertEqual(
            first.metadata["environment_fingerprint"],
            second.metadata["environment_fingerprint"],
        )
        self.assertTrue(all(command[:2] == ["codex", "exec"] for command in commands))
        self.assertTrue(all("--json" in command for command in commands))
        self.assertTrue(all("--ephemeral" in command for command in commands))
        self.assertTrue(
            all("--dangerously-bypass-hook-trust" not in command for command in commands)
        )

    def test_host_verifier_ignores_provider_pass_and_weakened_tests(self) -> None:
        def fake_codex(
            command, cwd, env, prompt, timeout
        ) -> subprocess.CompletedProcess[str]:
            package = json.loads(
                (cwd / "package.json").read_text(encoding="utf-8")
            )
            package["scripts"]["test"] = "true"
            (cwd / "package.json").write_text(
                json.dumps(package) + "\n",
                encoding="utf-8",
            )
            (cwd / "test" / "calculate-total.test.js").write_text(
                '"use strict";\n',
                encoding="utf-8",
            )
            events = [
                {"type": "thread.started", "thread_id": "forged-test-pass"},
                {
                    "type": "item.completed",
                    "item": {
                        "type": "command_execution",
                        "command": "npm test",
                        "aggregated_output": "",
                        "exit_code": 0,
                        "status": "completed",
                    },
                },
                {
                    "type": "turn.completed",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            ]
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="\n".join(json.dumps(item) for item in events),
                stderr="",
            )

        runner = LiveCodexRunner(codex_executor=fake_codex)
        scenario = next(
            item
            for item in default_live_scenarios(FIXTURES)
            if item.scenario_id == "tiny-local-bug"
        )
        observation = runner.run(
            RunRequest(
                VariantSpec("control", {"preparer": "control"}),
                scenario,
                1,
            )
        )
        facts = DeterministicScenarioOracle().project(
            observation,
            DeterministicScenarioOracle().expectations_for(scenario),
        )

        self.assertEqual(
            observation.metadata["host_verification"]["checks"][
                "npm test"
            ]["status"],
            "failed",
        )
        self.assertEqual(
            facts["verification"]["check_results"]["npm test"],
            "failed",
        )

    def test_hook_trust_bypass_requires_explicit_flag_temp_child_and_hashes(self) -> None:
        commands: list[list[str]] = []

        def fake_codex(command, cwd, env, prompt, timeout):
            commands.append(list(command))
            events = [
                {"type": "thread.started", "thread_id": "trusted-hook-test"},
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": "No implementation needed.",
                    },
                },
                {
                    "type": "turn.completed",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            ]
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="\n".join(json.dumps(item) for item in events),
                stderr="",
            )

        runner = LiveCodexRunner(
            vetted_temp_hooks=True,
            codex_executor=fake_codex,
        )
        scenario = next(
            item
            for item in default_live_scenarios(FIXTURES)
            if item.scenario_id == "tiny-local-bug"
        )
        runner.run(
            RunRequest(
                VariantSpec("stable", {"preparer": "stable"}),
                scenario,
                1,
            )
        )
        safe = commands[-1]

        self.assertIn("--dangerously-bypass-hook-trust", safe)
        for feature in (
            "apps",
            "multi_agent",
            "multi_agent_v2",
            "plugins",
            "skill_search",
        ):
            adjacent = [
                safe[index : index + 2]
                for index in range(len(safe) - 1)
            ]
            self.assertIn(["--disable", feature], adjacent)
        shell_path_overrides = [
            safe[index + 1]
            for index, value in enumerate(safe[:-1])
            if value == "--config"
            and safe[index + 1].startswith(
                "shell_environment_policy.set.PATH="
            )
        ]
        self.assertEqual(len(shell_path_overrides), 1)
        self.assertNotIn(os.environ.get("PATH", ""), shell_path_overrides[0])

        legacy = LiveCodexRunner(
            use_legacy_landlock=True
        )._codex_command(
            run_root=ROOT,
            temporary_root=ROOT,
            hooks_present=False,
        )
        self.assertIn(
            ["--enable", "use_legacy_landlock"],
            [
                legacy[index : index + 2]
                for index in range(len(legacy) - 1)
            ],
        )
        ordinary = LiveCodexRunner(vetted_temp_hooks=False)._codex_command(
            run_root=ROOT,
            temporary_root=ROOT,
            hooks_present=True,
        )
        self.assertNotIn("--dangerously-bypass-hook-trust", ordinary)
        with self.assertRaisesRegex(LiveBenchmarkError, "outside"):
            LiveCodexRunner(vetted_temp_hooks=True)._codex_command(
                run_root=ROOT,
                temporary_root=ROOT / "not-parent",
                hooks_present=True,
            )

    def test_self_signed_tampered_gate_is_never_executed(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="benchmark-canary-proof-"
        ) as evidence_raw:
            side_effect = Path(evidence_raw) / "malicious-side-effect"

            def tamper(context) -> None:
                manifest_path = (
                    context.run_root / ".agent-harness" / "manifest.json"
                )
                manifest = json.loads(
                    manifest_path.read_text(encoding="utf-8")
                )
                gate_entry = next(
                    item
                    for item in manifest["host_runtime"]["owned_files"]
                    if item.get("source")
                    == "assets/runtime/pretool_gate.py"
                )
                gate_path = Path(gate_entry["path"])
                gate_path.write_text(
                    "from pathlib import Path\n"
                    f"Path({str(side_effect)!r}).write_text('ran')\n"
                    "print('{}')\n",
                    encoding="utf-8",
                )
                gate_entry["sha256"] = hashlib.sha256(
                    gate_path.read_bytes()
                ).hexdigest()
                manifest_path.write_text(
                    json.dumps(manifest),
                    encoding="utf-8",
                )

            runner = LiveCodexRunner(vetted_temp_hooks=True)
            scenario = next(
                item
                for item in default_live_scenarios(FIXTURES)
                if item.scenario_id == "tiny-local-bug"
            )
            variant = VariantSpec(
                "stable",
                {
                    "preparer": "stable",
                    "prepare_callback": tamper,
                },
            )

            with self.assertRaisesRegex(
                LiveBenchmarkError, "unverified temp hooks"
            ):
                runner.run(RunRequest(variant, scenario, 1))

            self.assertFalse(side_effect.exists())


class CounterbalanceTests(unittest.TestCase):
    class FakeRunner:
        def __init__(self, mismatch: bool = False) -> None:
            self.calls: list[tuple[str, int]] = []
            self.mismatch = mismatch

        def run(self, request: RunRequest) -> RawRunObservation:
            self.calls.append((request.variant.name, request.repetition))
            fingerprint = (
                request.variant.name if self.mismatch else "same-environment"
            )
            return RawRunObservation(
                run_id=(
                    f"{request.variant.name}-{request.scenario.scenario_id}-"
                    f"{request.repetition}"
                ),
                variant=request.variant.name,
                scenario_id=request.scenario.scenario_id,
                repetition=request.repetition,
                metadata={"environment_fingerprint": fingerprint},
            )

    class FakeOracle:
        def expectations_for(self, scenario: ScenarioSpec):
            return {"scenario": scenario.scenario_id}

        def project(self, observation, expectations):
            return _valid_facts()

    class IdenticalTreatmentRunner:
        setup_build_fingerprint = "frozen-build"

        def run(self, request: RunRequest) -> RawRunObservation:
            treatment = (
                None if request.variant.name == "control" else "same-treatment"
            )
            return RawRunObservation(
                run_id=(
                    f"{request.variant.name}-{request.scenario.scenario_id}-"
                    f"{request.repetition}"
                ),
                variant=request.variant.name,
                scenario_id=request.scenario.scenario_id,
                repetition=request.repetition,
                metadata={
                    "environment_fingerprint": "same-environment",
                    "treatment_build_fingerprint": (
                        None
                        if request.variant.name == "control"
                        else "frozen-build"
                    ),
                    "treatment_fingerprint": treatment,
                },
            )

    def test_rotates_variant_order_deterministically_and_records_it(self) -> None:
        runner = self.FakeRunner()
        artifacts = execute_counterbalanced_live_matrix(
            runner,
            self.FakeOracle(),
            variants=[
                VariantSpec("control"),
                VariantSpec("stable"),
                VariantSpec("research"),
            ],
            scenarios=[ScenarioSpec("scenario", "prompt")],
            repetitions=3,
            counterbalance_seed=0,
        )

        self.assertEqual(
            runner.calls,
            [
                ("control", 1),
                ("stable", 1),
                ("research", 1),
                ("stable", 2),
                ("research", 2),
                ("control", 2),
                ("research", 3),
                ("control", 3),
                ("stable", 3),
            ],
        )
        self.assertEqual(
            [artifact.metadata["execution_order_index"] for artifact in artifacts],
            [1, 2, 3, 1, 2, 3, 1, 2, 3],
        )
        self.assertTrue(
            all(artifact.metadata["counterbalance_seed"] == 0 for artifact in artifacts)
        )

    def test_rejects_non_treatment_environment_mismatch(self) -> None:
        with self.assertRaisesRegex(
            LiveBenchmarkError, "environment differs"
        ):
            execute_counterbalanced_live_matrix(
                self.FakeRunner(mismatch=True),
                self.FakeOracle(),
                variants=[VariantSpec("control"), VariantSpec("stable")],
                scenarios=[ScenarioSpec("scenario", "prompt")],
                repetitions=1,
            )

    def test_rejects_identical_named_treatment_variants(self) -> None:
        with self.assertRaisesRegex(
            LiveBenchmarkError, "treatment variants are identical"
        ):
            execute_counterbalanced_live_matrix(
                self.IdenticalTreatmentRunner(),
                self.FakeOracle(),
                variants=[
                    VariantSpec("control"),
                    VariantSpec("stable"),
                    VariantSpec("research"),
                ],
                scenarios=[ScenarioSpec("scenario", "prompt")],
                repetitions=1,
            )


class FixtureAndCliTests(unittest.TestCase):
    def test_built_in_matrix_has_three_variants_and_five_real_fixtures(self) -> None:
        self.assertEqual(
            [variant.name for variant in default_live_variants()],
            ["control", "stable", "research"],
        )
        scenarios = default_live_scenarios(FIXTURES)
        self.assertEqual(
            [scenario.scenario_id for scenario in scenarios],
            [
                "ambiguous-support-chat",
                "stream-markdown-native-option",
                "tiny-local-bug",
                "canonical-doc-update",
                "hexagonal-carrier-boundary",
            ],
        )
        self.assertTrue(
            all(
                scenario.fixture_path is not None
                and scenario.fixture_path.is_dir()
                for scenario in scenarios
            )
        )
        old_note = (
            FIXTURES
            / "stream-markdown-native-option"
            / "docs"
            / "old-investigation.md"
        ).read_text(encoding="utf-8")
        types = (
            FIXTURES
            / "stream-markdown-native-option"
            / "node_modules"
            / "stream-markdown"
            / "index.d.ts"
        ).read_text(encoding="utf-8")
        self.assertIn("1.8.0", old_note)
        self.assertIn("freezeCompletedBlocks", types)

    def test_cli_never_runs_live_without_explicit_acknowledgement(self) -> None:
        stderr = StringIO()
        with redirect_stderr(stderr):
            result = main(["screen"])

        self.assertEqual(result, 2)
        self.assertIn("--run-live", stderr.getvalue())

    def test_raw_observation_replay_detects_post_capture_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            path = base / "observations.jsonl"
            observation = RawRunObservation(
                run_id="control-ambiguous-support-chat-1",
                variant="control",
                scenario_id="ambiguous-support-chat",
                repetition=1,
                final_text="hello",
                exit_status=0,
                metadata={"environment_fingerprint": "environment"},
            )
            with patch.dict(
                os.environ,
                {"XDG_STATE_HOME": str(base / "state")},
            ):
                _write_attested_observations(path, [observation])
                verified: dict[str, object] = {}
                artifacts = _replay_live_observations(path, verified)
                self.assertEqual(len(artifacts), 1)
                self.assertTrue(verified["verified"])
                self.assertEqual(
                    BenchmarkEngine().compare(artifacts).evidence_status,
                    "HOST-HMAC ATTESTED RAW / TRUSTED ORACLE PROJECTION",
                )

                path.write_text(
                    path.read_text(encoding="utf-8").replace(
                        "hello",
                        "hullo",
                    ),
                    encoding="utf-8",
                )
                tampered: dict[str, object] = {}
                tampered_artifacts = _replay_live_observations(path, tampered)
                self.assertFalse(tampered["verified"])
                self.assertIn(
                    "UNATTESTED RAW REPLAY",
                    BenchmarkEngine().compare(
                        tampered_artifacts
                    ).evidence_status,
                )


if __name__ == "__main__":
    unittest.main()
