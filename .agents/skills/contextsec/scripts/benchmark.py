#!/usr/bin/env python3
"""Run ContextSec regression, profile, mutation, and pinned real-repo suites."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterator, Mapping, Optional, Sequence, Tuple

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import check_controls  # noqa: E402
import control_ledger  # noqa: E402
import profile_repo  # noqa: E402

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_MANIFEST = REPOSITORY_ROOT / "benchmarks" / "scenarios.json"
DEFAULT_PROFILE_MANIFEST = REPOSITORY_ROOT / "benchmarks" / "profile-cases.json"
DEFAULT_MUTATION_MANIFEST = REPOSITORY_ROOT / "benchmarks" / "mutations.json"
DEFAULT_REAL_REPO_MANIFEST = REPOSITORY_ROOT / "benchmarks" / "real-repos.json"
DEFAULT_ADVERSARIAL_MANIFEST = (
    REPOSITORY_ROOT / "benchmarks" / "adversarial-performance" / "cases.json"
)
BENCHMARK_VERSION = "0.3.0"
ADVERSARIAL_SENTINEL = "CONTEXTSEC_PERF_SECRET_DO_NOT_EMIT_7d91"


def _fit_input(prefix: str, unit: str, suffix: str, size: int) -> str:
    if size < len(prefix) + len(suffix) or not unit:
        raise ValueError("Adversarial recipe has an invalid byte target.")
    repetitions = (size - len(prefix) - len(suffix)) // len(unit) + 1
    return (prefix + unit * repetitions + suffix)[:size]


def _adversarial_source(recipe: str, size: int) -> str:
    if recipe == "unterminated-js-string":
        return _fit_input('const value = "' + ADVERSARIAL_SENTINEL, "a", "", size)
    if recipe == "template-expressions":
        return _fit_input(
            "const value = `" + ADVERSARIAL_SENTINEL,
            "${lookup(value ?? `${fallback}`)}",
            "`;",
            size,
        )
    if recipe == "sql-boundaries":
        return _fit_input(
            "SELECT 1; # " + ADVERSARIAL_SENTINEL + "\n",
            "SELECT payload #- '{a}' -- comment\n/* near */ SELECT 2- -1;\n",
            "",
            size,
        )
    if recipe == "python-fstrings":
        return _fit_input(
            'seed = f"' + ADVERSARIAL_SENTINEL + ' {value!r:>{width}}"\n',
            'item = rf"literal {{brace}} {value!s:>{width}}"\n',
            "",
            size,
        )
    if recipe == "near-match-decoys":
        return _fit_input(
            "// " + ADVERSARIAL_SENTINEL + "\n",
            "openaiish.paymentIntentionally.retrievee organizationIdentifier secretiveToken;\n",
            "",
            size,
        )
    if recipe == "malformed-toml":
        return _fit_input(
            '[project]\nname = "case"\ndependencies = ["' + ADVERSARIAL_SENTINEL,
            "x",
            "",
            size,
        )
    raise ValueError("Unknown adversarial recipe: " + recipe)


def run_adversarial_performance(
    manifest_path: Path = DEFAULT_ADVERSARIAL_MANIFEST,
) -> Dict[str, Any]:
    manifest = profile_repo.strict_json_loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest.get("cases") if isinstance(manifest, dict) else None
    ceiling = manifest.get("max_seconds_per_case") if isinstance(manifest, dict) else None
    if (
        not isinstance(cases, list)
        or not cases
        or not isinstance(ceiling, (int, float))
        or ceiling <= 0
    ):
        raise ValueError("Adversarial manifest is invalid.")
    results = []
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
            "id",
            "recipe",
            "path",
            "bytes",
            "expected_coverage",
        }:
            raise ValueError("Adversarial case shape is invalid.")
        size = case["bytes"]
        if not isinstance(size, int) or size < 1 or size > profile_repo.DEFAULT_MAX_FILE_BYTES:
            raise ValueError("Adversarial case exceeds the published file bound.")
        source = _adversarial_source(str(case["recipe"]), size)
        language = profile_repo.language_for_path(str(case["path"]))
        started = time.perf_counter()
        masked = profile_repo.mask_comments_and_strings(source, language=language)
        with materialized_case(str(case["id"]), {str(case["path"]): source}) as root:
            profile = profile_repo.profile_repository(root)
            checks = check_controls.check_repository(root, profile=profile)
        elapsed = time.perf_counter() - started
        serialized = json.dumps(
            {"profile": profile, "checks": checks},
            sort_keys=True,
            ensure_ascii=False,
        )
        properties = {
            "within_time_bound": elapsed <= float(ceiling),
            "mask_preserves_length": len(masked) == len(source),
            "mask_does_not_disclose_seed": ADVERSARIAL_SENTINEL not in masked,
            "artifacts_do_not_disclose_seed": ADVERSARIAL_SENTINEL not in serialized,
            "coverage_fails_closed": profile["coverage"]["status"]
            == case["expected_coverage"],
        }
        results.append(
            {
                "id": case["id"],
                "bytes": len(source.encode("utf-8")),
                "elapsed_seconds": round(elapsed, 6),
                "status": "pass" if all(properties.values()) else "fail",
                "properties": properties,
            }
        )
    return {
        "schema_version": BENCHMARK_VERSION,
        "suite": "adversarial_performance",
        "manifest_version": manifest.get("version"),
        "status": "pass" if all(item["status"] == "pass" for item in results) else "fail",
        "max_seconds_per_case": ceiling,
        "case_count": len(results),
        "results": results,
        "method": manifest.get("method"),
    }


def ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 1.0


def _required_counts(expected: str, actual: str, counts: Dict[str, int]) -> None:
    expected_required = expected == "required"
    actual_required = actual == "required"
    if expected_required and actual_required:
        counts["true_positive"] += 1
    elif expected_required:
        counts["false_negative"] += 1
    elif actual_required:
        counts["false_positive"] += 1
    else:
        counts["true_negative"] += 1


def run_benchmark(manifest_path: Path = DEFAULT_MANIFEST) -> Dict[str, Any]:
    """Run the original authored regression corpus."""

    manifest = profile_repo.strict_json_loads(manifest_path.read_text(encoding="utf-8"))
    scenarios = manifest.get("automated")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("Benchmark manifest must contain automated scenarios.")

    pack_decisions = 0
    exact_states = 0
    exact_confidence = 0
    pack_counts = dict.fromkeys(
        ("true_positive", "false_positive", "false_negative", "true_negative"), 0
    )
    applicability_decisions = 0
    exact_applicability = 0
    applicability_counts = dict.fromkeys(pack_counts, 0)
    composition_decisions = 0
    exact_compositions = 0
    composition_counts = dict.fromkeys(pack_counts, 0)
    gate_decisions = 0
    exact_gates = 0
    results = []

    for scenario in scenarios:
        fixture = REPOSITORY_ROOT / scenario["fixture"]
        profile = profile_repo.profile_repository(fixture)
        checks = check_controls.check_repository(fixture, profile=profile)
        evaluation = control_ledger.build_ledger(profile, checks)
        routing = {item["pack"]: item["state"] for item in profile["routing"]}
        confidence = {
            item["pack"]: item["inference_confidence"] for item in profile["claims"]
        }
        ledger = {item["control_id"]: item for item in evaluation["ledger"]}
        mismatches = []

        for pack, expected in scenario["expected"].items():
            pack_decisions += 1
            actual_state = routing[pack]
            state_ok = actual_state == expected["routed_state"]
            exact_states += state_ok
            actual_confidence = (
                "not_applicable" if pack == "foundation" else confidence[pack]
            )
            confidence_ok = actual_confidence == expected["direct_evidence_state"]
            exact_confidence += confidence_ok
            _required_counts(expected["routed_state"], actual_state, pack_counts)
            if not state_ok or not confidence_ok:
                mismatches.append(
                    {
                        "dimension": "pack",
                        "id": pack,
                        "expected_state": expected["routed_state"],
                        "actual_state": actual_state,
                        "expected_confidence": expected["direct_evidence_state"],
                        "actual_confidence": actual_confidence,
                    }
                )

        for control_id, expected in scenario.get("expected_controls", {}).items():
            applicability_decisions += 1
            actual = ledger.get(control_id, {}).get("applicability", "not_emitted")
            exact_applicability += actual == expected
            _required_counts(expected, actual, applicability_counts)
            if actual != expected:
                mismatches.append(
                    {
                        "dimension": "control_applicability",
                        "id": control_id,
                        "expected": expected,
                        "actual": actual,
                    }
                )

        for control_id, expected in scenario.get("expected_compositions", {}).items():
            composition_decisions += 1
            actual = ledger.get(control_id, {}).get("applicability", "not_emitted")
            exact_compositions += actual == expected
            _required_counts(expected, actual, composition_counts)
            if actual != expected:
                mismatches.append(
                    {
                        "dimension": "composition_applicability",
                        "id": control_id,
                        "expected": expected,
                        "actual": actual,
                    }
                )

        if "expected_gate" in scenario:
            gate_decisions += 1
            actual_gate = evaluation["gate"]["status"]
            exact_gates += actual_gate == scenario["expected_gate"]
            if actual_gate != scenario["expected_gate"]:
                mismatches.append(
                    {
                        "dimension": "gate",
                        "expected": scenario["expected_gate"],
                        "actual": actual_gate,
                    }
                )

        results.append(
            {
                "id": scenario["id"],
                "fixture": scenario["fixture"],
                "status": "pass" if not mismatches else "fail",
                "mismatches": mismatches,
            }
        )

    return {
        "schema_version": BENCHMARK_VERSION,
        "suite": "authored_regression",
        "status": "pass"
        if all(item["status"] == "pass" for item in results)
        else "fail",
        "manifest_version": manifest.get("version"),
        "scenario_count": len(scenarios),
        "annotations": {
            "pack_decisions": pack_decisions,
            "control_applicability": applicability_decisions,
            "composition_applicability": composition_decisions,
            "gate_decisions": gate_decisions,
        },
        "metrics": {
            "exact_routed_state_accuracy": ratio(exact_states, pack_decisions),
            "exact_direct_evidence_accuracy": ratio(exact_confidence, pack_decisions),
            "pack_required_precision": ratio(
                pack_counts["true_positive"],
                pack_counts["true_positive"] + pack_counts["false_positive"],
            ),
            "pack_required_recall": ratio(
                pack_counts["true_positive"],
                pack_counts["true_positive"] + pack_counts["false_negative"],
            ),
            "control_applicability_accuracy": ratio(
                exact_applicability, applicability_decisions
            ),
            "control_required_precision": ratio(
                applicability_counts["true_positive"],
                applicability_counts["true_positive"]
                + applicability_counts["false_positive"],
            ),
            "control_required_recall": ratio(
                applicability_counts["true_positive"],
                applicability_counts["true_positive"]
                + applicability_counts["false_negative"],
            ),
            "composition_applicability_accuracy": ratio(
                exact_compositions, composition_decisions
            ),
            "composition_required_precision": ratio(
                composition_counts["true_positive"],
                composition_counts["true_positive"]
                + composition_counts["false_positive"],
            ),
            "composition_required_recall": ratio(
                composition_counts["true_positive"],
                composition_counts["true_positive"]
                + composition_counts["false_negative"],
            ),
            "gate_accuracy": ratio(exact_gates, gate_decisions),
        },
        "counts": {
            "packs": pack_counts,
            "controls": applicability_counts,
            "compositions": composition_counts,
        },
        "results": results,
        "method": (
            "Metrics cover only explicitly authored annotations. These fixtures are "
            "regression scenarios, not an independent held-out evaluation set."
        ),
    }


def _safe_case_files(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise ValueError("Each benchmark case must contain a non-empty files object.")
    result: Dict[str, str] = {}
    for raw_path, content in value.items():
        if not isinstance(raw_path, str) or not isinstance(content, str):
            raise ValueError("Benchmark file paths and contents must be strings.")
        path = PurePosixPath(raw_path)
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("Unsafe benchmark fixture path: " + raw_path)
        if "\\" in raw_path or ":" in raw_path:
            raise ValueError(
                "Benchmark fixture paths must be portable POSIX paths: " + raw_path
            )
        result[raw_path] = content
    return result


@contextmanager
def materialized_case(case_id: str, files: Any) -> Iterator[Path]:
    if (
        not isinstance(case_id, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", case_id) is None
    ):
        raise ValueError("Invalid benchmark case id.")
    safe_files = _safe_case_files(files)
    with tempfile.TemporaryDirectory(prefix="contextsec-benchmark-") as temporary:
        root = Path(temporary) / case_id
        root.mkdir()
        for relative, content in sorted(safe_files.items()):
            target = root.joinpath(*PurePosixPath(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="\n")
        yield root


def _empty_counts() -> Dict[str, int]:
    return dict.fromkeys(
        ("true_positive", "false_positive", "false_negative", "true_negative"), 0
    )


def _add_binary_counts(expected: bool, actual: bool, counts: Dict[str, int]) -> None:
    if expected and actual:
        counts["true_positive"] += 1
    elif expected:
        counts["false_negative"] += 1
    elif actual:
        counts["false_positive"] += 1
    else:
        counts["true_negative"] += 1


def _f1(counts: Mapping[str, int]) -> float:
    precision = ratio(
        counts["true_positive"], counts["true_positive"] + counts["false_positive"]
    )
    recall = ratio(
        counts["true_positive"], counts["true_positive"] + counts["false_negative"]
    )
    return (
        round(2 * precision * recall / (precision + recall), 4)
        if precision + recall
        else 0.0
    )


def _metric_block(
    counts: Mapping[str, int],
    per_pack: Mapping[str, Mapping[str, int]],
    exact: int,
    cases: int,
) -> Dict[str, Any]:
    supported_f1 = [
        _f1(item)
        for item in per_pack.values()
        if item["true_positive"] + item["false_negative"] > 0
    ]
    return {
        "case_count": cases,
        "exact_required_set_accuracy": ratio(exact, cases),
        "micro_precision": ratio(
            counts["true_positive"], counts["true_positive"] + counts["false_positive"]
        ),
        "micro_recall": ratio(
            counts["true_positive"], counts["true_positive"] + counts["false_negative"]
        ),
        "micro_f1": _f1(counts),
        "macro_f1_positive_support": (
            round(sum(supported_f1) / len(supported_f1), 4) if supported_f1 else 1.0
        ),
        "false_required_activation_count": counts["false_positive"],
    }


def _validate_pack_list(value: Any, field: str) -> Tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(field + " must be an array of pack ids.")
    if len(value) != len(set(value)) or not set(value) <= set(profile_repo.PACK_ORDER):
        raise ValueError(field + " contains duplicate or unknown pack ids.")
    return tuple(value)


def run_profile_accuracy(
    manifest_path: Path = DEFAULT_PROFILE_MANIFEST,
) -> Dict[str, Any]:
    """Evaluate frozen, maintainer-authored profile labels without code execution."""

    manifest = profile_repo.strict_json_loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest.get("cases") if isinstance(manifest, dict) else None
    if not isinstance(cases, list) or not cases:
        raise ValueError("Profile benchmark manifest must contain cases.")
    ids = [case.get("id") for case in cases if isinstance(case, dict)]
    if len(ids) != len(cases) or len(ids) != len(set(ids)):
        raise ValueError("Profile benchmark case ids must be unique strings.")

    overall = _empty_counts()
    per_pack = {pack: _empty_counts() for pack in profile_repo.PACK_ORDER}
    split_counts: Dict[str, Dict[str, int]] = {}
    split_per_pack: Dict[str, Dict[str, Dict[str, int]]] = {}
    split_exact: Dict[str, int] = {}
    split_cases: Dict[str, int] = {}
    exact = 0
    candidate_exact = 0
    safety_expected = 0
    safety_detected = 0
    capability_total = 0
    capability_exact = 0
    results = []

    for case in cases:
        split = case.get("split")
        if split not in {"development", "evaluation"}:
            raise ValueError("Profile cases must use development or evaluation split.")
        expected = set(
            _validate_pack_list(
                case.get("expected_required_packs"), "expected_required_packs"
            )
        )
        expected_candidate = set(
            _validate_pack_list(
                case.get("expected_candidate_packs", []), "expected_candidate_packs"
            )
        )
        if "foundation" not in expected or expected & expected_candidate:
            raise ValueError(
                "Profile labels must require foundation and keep states disjoint."
            )
        safety = set(
            _validate_pack_list(
                case.get("safety_critical_packs", []), "safety_critical_packs"
            )
        )
        if not safety <= expected:
            raise ValueError("safety_critical_packs must be expected required packs.")
        capabilities = case.get("expected_capabilities", {})
        if not isinstance(capabilities, dict) or not all(
            key in profile_repo.KNOWN_CAPABILITIES
            and value in {"present", "not_present"}
            for key, value in capabilities.items()
        ):
            raise ValueError("expected_capabilities contains an invalid annotation.")

        with materialized_case(case["id"], case.get("files")) as root:
            profile = profile_repo.profile_repository(root)
        actual = set(profile["required_packs"])
        actual_candidate = set(profile["candidate_packs"])
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        missing_candidate = sorted(expected_candidate - actual_candidate)
        unexpected_candidate = sorted(actual_candidate - expected_candidate)
        mismatches = []
        if missing or unexpected:
            mismatches.append(
                {
                    "dimension": "required_packs",
                    "missing": missing,
                    "unexpected": unexpected,
                }
            )
        if missing_candidate or unexpected_candidate:
            mismatches.append(
                {
                    "dimension": "candidate_packs",
                    "missing": missing_candidate,
                    "unexpected": unexpected_candidate,
                }
            )
        capability_states = {
            item["key"]: item["state"] for item in profile["capabilities"]
        }
        for capability, expected_state in sorted(capabilities.items()):
            capability_total += 1
            actual_state = capability_states[capability]
            matches = (
                actual_state == "present"
                if expected_state == "present"
                else actual_state != "present"
            )
            capability_exact += matches
            if not matches:
                mismatches.append(
                    {
                        "dimension": "capability",
                        "id": capability,
                        "expected": expected_state,
                        "actual": actual_state,
                    }
                )

        split_counts.setdefault(split, _empty_counts())
        split_per_pack.setdefault(
            split, {pack: _empty_counts() for pack in profile_repo.PACK_ORDER}
        )
        split_exact.setdefault(split, 0)
        split_cases[split] = split_cases.get(split, 0) + 1
        exact_match = not missing and not unexpected
        exact += exact_match
        split_exact[split] += exact_match
        candidate_exact += not missing_candidate and not unexpected_candidate
        safety_expected += len(safety)
        safety_detected += len(safety & actual)
        for pack in profile_repo.PACK_ORDER:
            _add_binary_counts(pack in expected, pack in actual, overall)
            _add_binary_counts(pack in expected, pack in actual, per_pack[pack])
            _add_binary_counts(pack in expected, pack in actual, split_counts[split])
            _add_binary_counts(
                pack in expected, pack in actual, split_per_pack[split][pack]
            )
        results.append(
            {
                "id": case["id"],
                "split": split,
                "label_source": case.get("label_source", "maintainer-authored"),
                "status": "pass" if not mismatches else "fail",
                "mismatches": mismatches,
            }
        )

    metrics = _metric_block(overall, per_pack, exact, len(cases))
    metrics.update(
        {
            "exact_candidate_set_accuracy": ratio(candidate_exact, len(cases)),
            "safety_critical_trigger_recall": ratio(safety_detected, safety_expected),
            "capability_annotation_accuracy": ratio(capability_exact, capability_total),
            "capability_annotation_count": capability_total,
        }
    )
    thresholds = manifest.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise ValueError("Profile benchmark thresholds must be an object.")
    threshold_results = {
        "macro_f1_positive_support": metrics["macro_f1_positive_support"]
        >= float(thresholds.get("macro_f1_positive_support", 0.0)),
        "safety_critical_trigger_recall": metrics["safety_critical_trigger_recall"]
        >= float(thresholds.get("safety_critical_trigger_recall", 0.0)),
        "false_required_activation_count": metrics["false_required_activation_count"]
        <= int(thresholds.get("max_false_required_activations", len(cases))),
        "capability_annotation_accuracy": metrics["capability_annotation_accuracy"]
        >= float(thresholds.get("capability_annotation_accuracy", 0.0)),
    }
    splits = {
        split: _metric_block(
            split_counts[split],
            split_per_pack[split],
            split_exact[split],
            split_cases[split],
        )
        for split in sorted(split_cases)
    }
    return {
        "schema_version": BENCHMARK_VERSION,
        "suite": "profile_accuracy",
        "status": "pass" if all(threshold_results.values()) else "fail",
        "manifest_version": manifest.get("version"),
        "case_count": len(cases),
        "metrics": metrics,
        "splits": splits,
        "thresholds": thresholds,
        "threshold_results": threshold_results,
        "per_pack": per_pack,
        "results": results,
        "method": manifest.get("method"),
    }


def run_mutations(manifest_path: Path = DEFAULT_MUTATION_MANIFEST) -> Dict[str, Any]:
    """Prove that published checker shapes change when one control is removed."""

    manifest = profile_repo.strict_json_loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest.get("mutations") if isinstance(manifest, dict) else None
    if not isinstance(cases, list) or not cases:
        raise ValueError("Mutation manifest must contain mutations.")
    ids = [case.get("id") for case in cases if isinstance(case, dict)]
    if len(ids) != len(cases) or len(ids) != len(set(ids)):
        raise ValueError("Mutation ids must be unique strings.")
    killed = 0
    results = []
    checker_counts: Dict[str, Dict[str, int]] = {}
    for case in cases:
        checker_id = case.get("checker_id")
        expected_status = case.get("expected_mutant_status")
        expected_controls = case.get("expected_control_ids")
        if not isinstance(checker_id, str) or expected_status not in {
            "failed",
            "unknown",
        }:
            raise ValueError("Mutation checker_id or expected status is invalid.")
        if (
            not isinstance(expected_controls, list)
            or not expected_controls
            or not all(isinstance(item, str) for item in expected_controls)
        ):
            raise ValueError(
                "Mutation expected_control_ids must be a non-empty string array."
            )
        with materialized_case(
            case["id"] + "-baseline", case.get("baseline_files")
        ) as root:
            profile = profile_repo.profile_repository(root)
            baseline = check_controls.check_repository(root, profile=profile)
        with materialized_case(
            case["id"] + "-mutant", case.get("mutant_files")
        ) as root:
            profile = profile_repo.profile_repository(root)
            mutant = check_controls.check_repository(root, profile=profile)
        baseline_matches = [
            item for item in baseline["findings"] if item["checker"]["id"] == checker_id
        ]
        mutant_matches = [
            item for item in mutant["findings"] if item["checker"]["id"] == checker_id
        ]
        mutant_match = mutant_matches[0] if len(mutant_matches) == 1 else None
        survived_reasons = []
        if baseline_matches:
            survived_reasons.append("target finding already existed in baseline")
        if mutant_match is None:
            survived_reasons.append("mutant did not emit exactly one target finding")
        elif mutant_match["status"] != expected_status:
            survived_reasons.append("mutant finding status differed")
        elif not set(expected_controls) <= set(mutant_match["control_ids"]):
            survived_reasons.append("mutant finding did not bind expected controls")
        is_killed = not survived_reasons
        killed += is_killed
        checker_counts.setdefault(checker_id, {"eligible": 0, "killed": 0})
        checker_counts[checker_id]["eligible"] += 1
        checker_counts[checker_id]["killed"] += is_killed
        results.append(
            {
                "id": case["id"],
                "checker_id": checker_id,
                "status": "killed" if is_killed else "survived",
                "survived_reasons": survived_reasons,
            }
        )
    score = ratio(killed, len(cases))
    minimum = float(manifest.get("thresholds", {}).get("minimum_kill_rate", 0.0))
    return {
        "schema_version": BENCHMARK_VERSION,
        "suite": "mutation_verification",
        "status": "pass" if score >= minimum else "fail",
        "manifest_version": manifest.get("version"),
        "eligible_mutations": len(cases),
        "killed_mutations": killed,
        "surviving_mutations": len(cases) - killed,
        "mutation_kill_rate": score,
        "threshold": minimum,
        "by_checker": checker_counts,
        "results": results,
        "method": manifest.get("method"),
    }


def _git_commit(root: Path) -> str:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD^{commit}"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=environment,
    )
    if completed.returncode != 0:
        raise ValueError("Unable to verify pinned Git commit for " + root.name)
    commit = completed.stdout.strip().lower()
    if re.fullmatch(r"[a-f0-9]{40}", commit) is None:
        raise ValueError("Git returned an invalid commit identity for " + root.name)
    return commit


def run_real_repositories(
    workspace: Path, manifest_path: Path = DEFAULT_REAL_REPO_MANIFEST
) -> Dict[str, Any]:
    """Evaluate manually labeled public repositories at exact local commits."""

    workspace = workspace.resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError("Real-repo workspace is not a directory.")
    manifest = profile_repo.strict_json_loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest.get("repositories") if isinstance(manifest, dict) else None
    if not isinstance(cases, list) or not cases:
        raise ValueError("Real-repo manifest must contain repositories.")
    results = []
    counts = _empty_counts()
    per_pack = {pack: _empty_counts() for pack in profile_repo.PACK_ORDER}
    exact = 0
    for case in cases:
        directory = case.get("directory")
        if (
            not isinstance(directory, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", directory) is None
        ):
            raise ValueError("Real-repo directory is invalid.")
        root = (workspace / directory).resolve(strict=True)
        if root.parent != workspace:
            raise ValueError("Real-repo checkout escaped the workspace.")
        expected_commit = case.get("commit")
        actual_commit = _git_commit(root)
        if actual_commit != expected_commit:
            raise ValueError(
                "Pinned commit mismatch for " + case["id"] + ": " + actual_commit
            )
        expected = set(
            _validate_pack_list(
                case.get("expected_required_packs"), "expected_required_packs"
            )
        )
        expected_candidate = set(
            _validate_pack_list(
                case.get("expected_candidate_packs", []), "expected_candidate_packs"
            )
        )
        profile = profile_repo.profile_repository(root)
        actual = set(profile["required_packs"])
        actual_candidate = set(profile["candidate_packs"])
        mismatches = []
        if actual != expected:
            mismatches.append(
                {
                    "dimension": "required_packs",
                    "missing": sorted(expected - actual),
                    "unexpected": sorted(actual - expected),
                }
            )
        if actual_candidate != expected_candidate:
            mismatches.append(
                {
                    "dimension": "candidate_packs",
                    "missing": sorted(expected_candidate - actual_candidate),
                    "unexpected": sorted(actual_candidate - expected_candidate),
                }
            )
        expected_coverage = case.get("expected_coverage")
        if profile["coverage"]["status"] != expected_coverage:
            mismatches.append(
                {
                    "dimension": "coverage",
                    "expected": expected_coverage,
                    "actual": profile["coverage"]["status"],
                }
            )
        exact += actual == expected
        for pack in profile_repo.PACK_ORDER:
            _add_binary_counts(pack in expected, pack in actual, counts)
            _add_binary_counts(pack in expected, pack in actual, per_pack[pack])
        results.append(
            {
                "id": case["id"],
                "repository": case["repository"],
                "commit": actual_commit,
                "license": case["license"],
                "coverage": profile["coverage"]["status"],
                "subject_revision": profile["subject"]["subject_revision"],
                "status": "pass" if not mismatches else "fail",
                "mismatches": mismatches,
            }
        )
    metrics = _metric_block(counts, per_pack, exact, len(cases))
    return {
        "schema_version": BENCHMARK_VERSION,
        "suite": "pinned_real_repositories",
        "status": "pass"
        if all(item["status"] == "pass" for item in results)
        else "fail",
        "manifest_version": manifest.get("version"),
        "repository_count": len(cases),
        "metrics": metrics,
        "results": results,
        "method": manifest.get("method"),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run ContextSec decision benchmarks.")
    parser.add_argument(
        "--suite",
        choices=("regression", "profile", "mutation", "real-repo", "adversarial", "all"),
        default="regression",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--profile-manifest", type=Path, default=DEFAULT_PROFILE_MANIFEST
    )
    parser.add_argument(
        "--mutation-manifest", type=Path, default=DEFAULT_MUTATION_MANIFEST
    )
    parser.add_argument(
        "--real-repo-manifest", type=Path, default=DEFAULT_REAL_REPO_MANIFEST
    )
    parser.add_argument(
        "--adversarial-manifest", type=Path, default=DEFAULT_ADVERSARIAL_MANIFEST
    )
    parser.add_argument("--workspace", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.suite == "regression":
            result = run_benchmark(args.manifest)
        elif args.suite == "profile":
            result = run_profile_accuracy(args.profile_manifest)
        elif args.suite == "mutation":
            result = run_mutations(args.mutation_manifest)
        elif args.suite == "real-repo":
            if args.workspace is None:
                raise ValueError("--workspace is required for the real-repo suite.")
            result = run_real_repositories(args.workspace, args.real_repo_manifest)
        elif args.suite == "adversarial":
            result = run_adversarial_performance(args.adversarial_manifest)
        else:
            suites = {
                "regression": run_benchmark(args.manifest),
                "profile": run_profile_accuracy(args.profile_manifest),
                "mutation": run_mutations(args.mutation_manifest),
            }
            result = {
                "schema_version": BENCHMARK_VERSION,
                "suite": "offline_all",
                "status": "pass"
                if all(item["status"] == "pass" for item in suites.values())
                else "fail",
                "suites": suites,
                "note": "Pinned real repositories are opt-in and require --suite real-repo --workspace.",
            }
    except (OSError, ValueError, RecursionError, subprocess.SubprocessError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
