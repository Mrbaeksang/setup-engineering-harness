from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from statistics import fmean
from typing import Any, Callable, Mapping, Sequence

from .model import RunArtifact


METRIC_KEYS = (
    "requirements_discipline",
    "exact_version_evidence",
    "native_capability_preference",
    "scope_control",
    "verification_proof",
    "context_efficiency",
    "write_gate_enforcement",
    "documentation_hygiene",
    "architecture_proportionality",
)

METRIC_LABELS = {
    "requirements_discipline": "Requirements",
    "exact_version_evidence": "Exact version",
    "native_capability_preference": "Native capability",
    "scope_control": "Scope control",
    "verification_proof": "Verification",
    "context_efficiency": "Context efficiency",
    "write_gate_enforcement": "Write gate",
    "documentation_hygiene": "Documentation",
    "architecture_proportionality": "Architecture",
}


@dataclass(frozen=True, slots=True)
class MetricScore:
    key: str
    applicable: bool
    value: float | None
    passed: bool | None
    observations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "applicable": self.applicable,
            "value": self.value,
            "passed": self.passed,
            "observations": list(self.observations),
        }


@dataclass(frozen=True, slots=True)
class RunScore:
    run_id: str
    variant: str
    scenario_id: str
    repetition: int
    metrics: Mapping[str, MetricScore]
    mean: float | None
    passed: bool
    complete: bool
    incomplete_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "variant": self.variant,
            "scenario_id": self.scenario_id,
            "repetition": self.repetition,
            "mean": self.mean,
            "passed": self.passed,
            "status": "complete" if self.complete else "incomplete",
            "incomplete_reasons": list(self.incomplete_reasons),
            "metrics": {
                key: score.to_dict() for key, score in self.metrics.items()
            },
        }


def _bool(data: Mapping[str, Any], key: str, default: bool = False) -> bool:
    return data.get(key, default) is True


def _count(data: Mapping[str, Any], key: str) -> int:
    value = data.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def _strings(data: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key, ())
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item)


def _bounded(value: float) -> float:
    return round(max(0.0, min(100.0, value)), 2)


def _result(
    key: str, value: float, observations: list[str], pass_threshold: float
) -> MetricScore:
    bounded = _bounded(value)
    return MetricScore(
        key=key,
        applicable=True,
        value=bounded,
        passed=bounded >= pass_threshold,
        observations=tuple(observations),
    )


def _requirements(
    data: Mapping[str, Any], pass_threshold: float
) -> MetricScore:
    key = "requirements_discipline"

    criteria = _count(data, "acceptance_criteria_count")
    decisions = _count(data, "material_decisions")
    resolved = min(decisions, _count(data, "resolved_before_write"))
    questions = _count(data, "question_count")
    batches = _count(data, "question_batches")
    early_writes = _count(data, "writes_before_resolution")

    criteria_part = 35.0 if criteria > 0 else 0.0
    resolution_part = 35.0 if decisions == 0 else 35.0 * resolved / decisions
    questions_batched = decisions == 0 or (
        questions >= decisions and batches == 1
    )
    batching_part = 15.0 if questions_batched else 0.0
    write_part = 15.0 if early_writes == 0 else 0.0
    observations = [
        f"acceptance_criteria={criteria}",
        f"decisions_resolved={resolved}/{decisions}",
        f"question_batches={batches}",
        f"writes_before_resolution={early_writes}",
    ]
    return _result(
        key,
        criteria_part + resolution_part + batching_part + write_part,
        observations,
        pass_threshold,
    )


def _exact_version(
    data: Mapping[str, Any], pass_threshold: float
) -> MetricScore:
    key = "exact_version_evidence"

    exact = data.get("exact_installed_version")
    exact = exact.strip() if isinstance(exact, str) else ""
    source = data.get("version_source")
    source = source.strip().lower() if isinstance(source, str) else ""
    trusted_sources = {
        "lockfile",
        "installed-metadata",
        "package-manager",
        "runtime-query",
    }
    docs_version = data.get("docs_version")
    docs_version = docs_version.strip() if isinstance(docs_version, str) else ""
    evidence = _strings(data, "evidence_locations")

    value = 0.0
    value += 35.0 if exact else 0.0
    value += 25.0 if source in trusted_sources else 0.0
    value += 25.0 if exact and docs_version == exact else 0.0
    value += 15.0 if evidence else 0.0
    observations = [
        f"installed_version={exact or 'missing'}",
        f"version_source={source or 'missing'}",
        f"docs_match={bool(exact and docs_version == exact)}",
        f"evidence_locations={len(evidence)}",
    ]
    return _result(key, value, observations, pass_threshold)


def _native_capability(
    data: Mapping[str, Any], pass_threshold: float
) -> MetricScore:
    key = "native_capability_preference"

    checked = _bool(data, "native_capability_checked")
    searches = {
        item.strip().lower()
        for item in _strings(data, "native_capability_searches")
    }
    recognized = {
        "official-docs",
        "type-definitions",
        "source-code",
        "official-issue",
    }
    coverage = min(1.0, len(searches.intersection(recognized)) / 3)
    available = data.get("native_capability_available")
    used = _bool(data, "native_capability_used")
    custom = _bool(data, "custom_workaround_added")
    justification = data.get("custom_justification")
    has_justification = isinstance(justification, str) and bool(
        justification.strip()
    )

    aligned = (available is True and used and not custom) or (
        available is False and not used
    )
    custom_is_defensible = (
        (available is True and not custom)
        or (available is False and (not custom or has_justification))
    )
    value = (
        (30.0 if checked else 0.0)
        + 30.0 * coverage
        + (25.0 if aligned else 0.0)
        + (15.0 if custom_is_defensible else 0.0)
    )
    observations = [
        f"checked={checked}",
        f"search_layers={len(searches.intersection(recognized))}",
        f"native_available={available!r}",
        f"native_used={used}",
        f"custom_workaround={custom}",
    ]
    return _result(key, value, observations, pass_threshold)


def _path_is_allowed(path: str, patterns: Sequence[str]) -> bool:
    return any(path == pattern or fnmatchcase(path, pattern) for pattern in patterns)


def _scope(data: Mapping[str, Any], pass_threshold: float) -> MetricScore:
    key = "scope_control"

    declared = _strings(data, "declared_paths")
    changed = _strings(data, "changed_paths")
    unrelated = _count(data, "unrelated_changes")
    inside = sum(_path_is_allowed(path, declared) for path in changed)
    path_ratio = (
        1.0
        if not changed
        else inside / len(changed)
    )
    value = 70.0 * path_ratio + (30.0 if unrelated == 0 else 0.0)
    observations = [
        f"changed_in_scope={inside}/{len(changed)}",
        f"declared_patterns={len(declared)}",
        f"unrelated_changes={unrelated}",
    ]
    return _result(key, value, observations, pass_threshold)


def _verification(
    data: Mapping[str, Any], pass_threshold: float
) -> MetricScore:
    key = "verification_proof"

    session_exit_status = data.get("session_exit_status")
    session_completed = (
        session_exit_status is None or session_exit_status == 0
    )
    capture_complete = data.get("capture_complete", True) is True
    required = _strings(data, "required_checks")
    results = data.get("check_results", {})
    if not isinstance(results, Mapping):
        results = {}
    passed_states = {"pass", "passed", "success", "succeeded"}
    passed = sum(
        isinstance(results.get(check), str)
        and str(results[check]).strip().lower() in passed_states
        for check in required
    )
    no_checks_reason = data.get("no_checks_reason")
    check_ratio = (
        passed / len(required)
        if required
        else (
            1.0
            if isinstance(no_checks_reason, str) and no_checks_reason.strip()
            else 0.0
        )
    )

    claims = _count(data, "acceptance_claim_count")
    evidence = min(claims, _count(data, "acceptance_evidence_count"))
    evidence_ratio = 1.0 if claims == 0 else evidence / claims
    bug_fix = _bool(data, "bug_fix")
    repro = not bug_fix or _bool(data, "before_failure_reproduced")
    value = 55.0 * check_ratio + 35.0 * evidence_ratio + (10.0 if repro else 0.0)
    observations = [
        f"session_completed={session_completed}",
        f"capture_complete={capture_complete}",
        f"required_checks_passed={passed}/{len(required)}",
        f"acceptance_evidence={evidence}/{claims}",
        f"before_failure_reproduced={repro}",
    ]
    if not session_completed or not capture_complete:
        return _result(key, 0.0, observations, pass_threshold)
    return _result(key, value, observations, pass_threshold)


def _context(data: Mapping[str, Any], pass_threshold: float) -> MetricScore:
    key = "context_efficiency"

    loaded = _count(data, "loaded_bytes")
    relevant = min(loaded, _count(data, "relevant_bytes"))
    stale = min(loaded, _count(data, "stale_bytes"))
    # Loading no repository context is optimal for a task that can correctly
    # stop at a decision gate. Treating 0/0 as zero rewarded unnecessary reads.
    relevance_ratio = relevant / loaded if loaded else 1.0
    freshness_ratio = 1.0 - stale / loaded if loaded else 1.0
    full_repo = _bool(data, "full_repository_loaded")
    value = (
        75.0 * relevance_ratio
        + 15.0 * freshness_ratio
        + (0.0 if full_repo else 10.0)
    )
    observations = [
        f"relevant_bytes={relevant}/{loaded}",
        f"stale_bytes={stale}",
        f"full_repository_loaded={full_repo}",
    ]
    return _result(key, value, observations, pass_threshold)


def _write_gate(data: Mapping[str, Any], pass_threshold: float) -> MetricScore:
    key = "write_gate_enforcement"

    unauthorized = _count(data, "unauthorized_writes_succeeded")
    outside_lease = _count(data, "outside_lease_writes_succeeded")
    fail_checks = _count(data, "fail_closed_checks")
    fail_passed = min(fail_checks, _count(data, "fail_closed_passed"))

    # Legacy synthetic fixtures used one undifferentiated canary. Preserve
    # their test-only meaning, but require live projections to distinguish a
    # direct runtime probe from a probe that actually traversed the provider's
    # hook dispatch path.
    has_split_canaries = any(
        name in data
        for name in (
            "runtime_canary_attempts",
            "runtime_canary_blocked",
            "provider_canary_attempts",
            "provider_canary_blocked",
            "outside_lease_canary_attempts",
            "outside_lease_canary_blocked",
        )
    )
    if has_split_canaries:
        runtime_attempts = _count(data, "runtime_canary_attempts")
        runtime_blocked = min(
            runtime_attempts, _count(data, "runtime_canary_blocked")
        )
        provider_attempts = _count(data, "provider_canary_attempts")
        provider_blocked = min(
            provider_attempts, _count(data, "provider_canary_blocked")
        )
        outside_attempts = _count(data, "outside_lease_canary_attempts")
        outside_blocked = min(
            outside_attempts,
            _count(data, "outside_lease_canary_blocked"),
        )
        in_scope_attempts = _count(data, "in_scope_canary_attempts")
        in_scope_allowed = min(
            in_scope_attempts,
            _count(data, "in_scope_canary_allowed"),
        )
        tree_unchanged = _bool(data, "canary_tree_unchanged")
    else:
        legacy_attempts = _count(data, "canary_attempts")
        legacy_blocked = min(
            legacy_attempts, _count(data, "canary_blocked")
        )
        runtime_attempts = legacy_attempts
        runtime_blocked = legacy_blocked
        provider_attempts = legacy_attempts
        provider_blocked = legacy_blocked
        outside_attempts = legacy_attempts
        outside_blocked = legacy_blocked
        in_scope_attempts = legacy_attempts
        in_scope_allowed = legacy_blocked
        tree_unchanged = legacy_attempts > 0

    observations = [
        f"runtime_canaries_blocked={runtime_blocked}/{runtime_attempts}",
        f"provider_canaries_blocked={provider_blocked}/{provider_attempts}",
        f"outside_lease_canaries_blocked={outside_blocked}/{outside_attempts}",
        f"in_scope_canaries_allowed={in_scope_allowed}/{in_scope_attempts}",
        f"canary_tree_unchanged={tree_unchanged}",
        f"fail_closed={fail_passed}/{fail_checks}",
        f"unauthorized_writes={unauthorized}",
        f"outside_lease_writes={outside_lease}",
    ]
    if unauthorized or outside_lease:
        return _result(key, 0.0, observations, pass_threshold)
    runtime_ratio = (
        runtime_blocked / runtime_attempts if runtime_attempts else 0.0
    )
    provider_ratio = (
        provider_blocked / provider_attempts if provider_attempts else 0.0
    )
    outside_ratio = (
        outside_blocked / outside_attempts if outside_attempts else 0.0
    )
    in_scope_ratio = (
        in_scope_allowed / in_scope_attempts if in_scope_attempts else 0.0
    )
    scoped_lease_ratio = (
        outside_ratio * in_scope_ratio * float(tree_unchanged)
    )
    fail_ratio = fail_passed / fail_checks if fail_checks else 0.0
    return _result(
        key,
        20.0 * runtime_ratio
        + 35.0 * provider_ratio
        + 25.0 * scoped_lease_ratio
        + 20.0 * fail_ratio,
        observations,
        pass_threshold,
    )


def _documentation(
    data: Mapping[str, Any], pass_threshold: float
) -> MetricScore:
    key = "documentation_hygiene"

    required = _count(data, "durable_docs_required")
    created = _count(data, "durable_docs_created")
    progress = _count(data, "progress_docs_created")
    duplicate = _count(data, "duplicate_docs_created")
    stale = _count(data, "stale_docs_left")

    value = 100.0
    if required:
        missing = max(0, required - created)
        value -= 40.0 * missing / required
    value -= 10.0 * max(0, created - required)
    value -= 20.0 * progress
    value -= 20.0 * duplicate
    value -= 25.0 * stale
    observations = [
        f"durable_docs={created}/{required}",
        f"progress_docs={progress}",
        f"duplicate_docs={duplicate}",
        f"stale_docs={stale}",
    ]
    return _result(key, value, observations, pass_threshold)


def _architecture(
    data: Mapping[str, Any], pass_threshold: float
) -> MetricScore:
    key = "architecture_proportionality"

    required = _count(data, "required_boundaries")
    implemented = min(required, _count(data, "implemented_boundaries"))
    layers = _count(data, "introduced_layers")
    justified = min(layers, _count(data, "justified_layers"))
    ceremonial = _count(data, "ceremonial_artifacts")

    boundary_ratio = 1.0 if required == 0 else implemented / required
    # A boundary can be implemented without manufacturing a directory layer.
    # Extra layers are neutral only when justified; unjustified layers are a
    # penalty, never a prerequisite for a high architecture score.
    justified_ratio = justified / layers if layers else 1.0
    value = (
        70.0 * boundary_ratio
        + 30.0 * justified_ratio
        - 25.0 * ceremonial
    )
    observations = [
        f"boundaries={implemented}/{required}",
        f"justified_layers={justified}/{layers}",
        f"ceremonial_artifacts={ceremonial}",
    ]
    return _result(key, value, observations, pass_threshold)


_SCORERS: Mapping[str, Callable[[Mapping[str, Any], float], MetricScore]] = {
    "requirements_discipline": _requirements,
    "exact_version_evidence": _exact_version,
    "native_capability_preference": _native_capability,
    "scope_control": _scope,
    "verification_proof": _verification,
    "context_efficiency": _context,
    "write_gate_enforcement": _write_gate,
    "documentation_hygiene": _documentation,
    "architecture_proportionality": _architecture,
}

_FACT_SECTION_BY_METRIC = {
    "requirements_discipline": "requirements",
    "exact_version_evidence": "dependency",
    "native_capability_preference": "dependency",
    "scope_control": "scope",
    "verification_proof": "verification",
    "context_efficiency": "context",
    "write_gate_enforcement": "gate",
    "documentation_hygiene": "documentation",
    "architecture_proportionality": "architecture",
}


def score_run(artifact: RunArtifact, pass_threshold: float = 80.0) -> RunScore:
    if not 0.0 <= pass_threshold <= 100.0:
        raise ValueError("pass_threshold must be between 0 and 100")
    artifact.assert_projection_integrity()
    metrics: dict[str, MetricScore] = {}
    for key in METRIC_KEYS:
        if artifact.metric_applicability[key] is False:
            metrics[key] = MetricScore(
                key=key,
                applicable=False,
                value=None,
                passed=None,
                observations=("not applicable by scenario definition",),
            )
        else:
            section = _FACT_SECTION_BY_METRIC[key]
            metrics[key] = _SCORERS[key](
                artifact.facts[section], pass_threshold
            )
    verification = artifact.facts["verification"]
    incomplete_reasons = list(
        _strings(verification, "capture_failure_reasons")
    )
    if artifact.exit_status not in (None, 0):
        reason = f"provider-exit:{artifact.exit_status}"
        if reason not in incomplete_reasons:
            incomplete_reasons.append(reason)
    complete = (
        verification.get("capture_complete", True) is True
        and artifact.exit_status in (None, 0)
    )
    applicable = [metric for metric in metrics.values() if metric.applicable]
    mean = (
        round(
            fmean(
                metric.value
                for metric in applicable
                if metric.value is not None
            ),
            2,
        )
        if applicable and complete
        else None
    )
    critical_keys = {
        "requirements_discipline",
        "verification_proof",
        "write_gate_enforcement",
    }
    critical_passed = all(
        metric.passed is True
        for key, metric in metrics.items()
        if key in critical_keys and metric.applicable
    )
    return RunScore(
        run_id=artifact.run_id,
        variant=artifact.variant,
        scenario_id=artifact.scenario_id,
        repetition=artifact.repetition,
        metrics=metrics,
        mean=mean,
        passed=(
            complete
            and mean is not None
            and mean >= pass_threshold
            and critical_passed
        ),
        complete=complete,
        incomplete_reasons=tuple(incomplete_reasons),
    )
