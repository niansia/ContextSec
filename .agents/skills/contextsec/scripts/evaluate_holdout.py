#!/usr/bin/env python3
"""Compare frozen independent consensus labels with pinned ContextSec profiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import check_controls  # noqa: E402
import attestation_verifier  # noqa: E402
import external_review  # noqa: E402
import profile_repo  # noqa: E402
import safe_io  # noqa: E402
import validate_profile  # noqa: E402
import versioning  # noqa: E402

SCHEMA_URL = "https://raw.githubusercontent.com/niansia/ContextSec/v0.4.0/benchmarks/holdout-predictions.schema.json"


def _load(path: Path, label: str, limit: int) -> Dict[str, Any]:
    return safe_io.read_json_object_bounded(path, limit, label)


def _digest(value: Mapping[str, Any]) -> str:
    material = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return round(numerator / denominator, 4) if denominator else None


def _binary(rows: Sequence[Mapping[str, Any]], state: str) -> Dict[str, Any]:
    truth = [
        (case_id, pack, labels[pack] == state, predictions[pack] == state)
        for case_id, labels, predictions in (
            (str(row["id"]), row["truth"], row["prediction"]) for row in rows
        )
        for pack in labels
    ]
    tp = sum(expected and actual for _, _, expected, actual in truth)
    fp = sum(not expected and actual for _, _, expected, actual in truth)
    fn = sum(expected and not actual for _, _, expected, actual in truth)
    tn = sum(not expected and not actual for _, _, expected, actual in truth)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (
        round(2 * precision * recall / (precision + recall), 4)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _critical_packs() -> set[str]:
    return {
        pack["id"]
        for pack in profile_repo.PACK_CATALOG["packs"]
        if any(
            control.get("blocking") is True and control.get("severity") == "critical"
            for control in pack["controls"]
        )
    }


def _aggregate(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    exact = sum(row["truth"] == row["prediction"] for row in rows)
    required_sets = sum(
        {pack for pack, state in row["truth"].items() if state == "required"}
        == {pack for pack, state in row["prediction"].items() if state == "required"}
        for row in rows
    )
    candidate_sets = sum(
        {pack for pack, state in row["truth"].items() if state == "candidate"}
        == {pack for pack, state in row["prediction"].items() if state == "candidate"}
        for row in rows
    )
    critical = _critical_packs()
    critical_truth = sum(
        row["truth"][pack] == "required" for row in rows for pack in critical
    )
    critical_hits = sum(
        row["truth"][pack] == "required" and row["prediction"][pack] == "required"
        for row in rows
        for pack in critical
    )
    return {
        "case_count": len(rows),
        "required": _binary(rows, "required"),
        "candidate": _binary(rows, "candidate"),
        "false_required_count": sum(
            prediction == "required" and row["truth"][pack] != "required"
            for row in rows
            for pack, prediction in row["prediction"].items()
        ),
        "exact_label_set_accuracy": _ratio(exact, len(rows)),
        "exact_required_set_accuracy": _ratio(required_sets, len(rows)),
        "exact_candidate_set_accuracy": _ratio(candidate_sets, len(rows)),
        "safety_critical_required_recall": _ratio(critical_hits, critical_truth),
        "safety_critical_truth_count": critical_truth,
    }


def _pack_aggregate(rows: Sequence[Mapping[str, Any]], pack: str) -> Dict[str, Any]:
    narrowed = [
        {
            **row,
            "truth": {pack: row["truth"][pack]},
            "prediction": {pack: row["prediction"][pack]},
        }
        for row in rows
    ]
    return {
        "case_count": len(rows),
        "label_accuracy": _ratio(
            sum(row["truth"][pack] == row["prediction"][pack] for row in rows),
            len(rows),
        ),
        "required": _binary(narrowed, "required"),
        "candidate": _binary(narrowed, "candidate"),
    }


def _profile_labels(profile: Mapping[str, Any]) -> Dict[str, str]:
    routing = profile.get("routing")
    if not isinstance(routing, list):
        raise ValueError("Prediction profile routing must be an array.")
    labels = {
        str(item.get("pack")): str(item.get("state"))
        for item in routing
        if isinstance(item, dict)
    }
    if set(labels) != set(profile_repo.PACK_ORDER) or not set(labels.values()) <= set(
        external_review.LABEL_STATES
    ):
        raise ValueError("Prediction profile must route every pack exactly once.")
    return labels


def _derived_support_class(profile: Mapping[str, Any]) -> str:
    """Derive metric eligibility from validated profiler coverage, never labels."""

    coverage = profile.get("coverage")
    if not isinstance(coverage, dict):
        raise ValueError("Prediction profile coverage must be an object.")
    traversal = coverage.get("status")
    language = coverage.get("language_support")
    if language == "unsupported":
        return "unsupported"
    if traversal == "complete" and language == "supported":
        return "supported"
    return "partial"


def _trusted_evidence(evidence_trust: Optional[Mapping[str, Any]]) -> bool:
    if not (
        isinstance(evidence_trust, Mapping)
        and isinstance(evidence_trust.get("labels"), Mapping)
        and isinstance(evidence_trust.get("predictions"), Mapping)
        and evidence_trust["labels"].get("status") == "verified"
        and evidence_trust["predictions"].get("status") == "verified"
    ):
        return False
    try:
        label_time = datetime.fromisoformat(
            str(evidence_trust["labels"].get("verified_at", "")).replace("Z", "+00:00")
        )
        prediction_time = datetime.fromisoformat(
            str(evidence_trust["predictions"].get("verified_at", "")).replace("Z", "+00:00")
        )
    except (ValueError, TypeError):
        return False
    return (
        label_time.tzinfo is not None
        and prediction_time.tzinfo is not None
        and label_time < prediction_time
    )


def evaluate(
    labels_payload: Mapping[str, Any],
    predictions: Mapping[str, Any],
    headline_trust: bool = False,
) -> Dict[str, Any]:
    external_review.evaluate(labels_payload)
    if set(predictions) != {"$schema", "version", "status", "tool", "cases"}:
        raise ValueError("Holdout predictions have unexpected or missing fields.")
    if predictions.get("$schema") != SCHEMA_URL:
        raise ValueError("Holdout prediction schema identity is incompatible.")
    if not isinstance(predictions.get("version"), str) or not predictions["version"]:
        raise ValueError("Holdout prediction version is invalid.")
    if predictions.get("status") != "complete":
        raise ValueError("Holdout predictions must be marked complete.")
    tool = predictions.get("tool")
    expected_tool = {
        "tool_version": versioning.TOOL_VERSION,
        "schema_version": versioning.SCHEMA_VERSION,
        "detector_version": profile_repo.DETECTOR_VERSION,
        "checker_version": check_controls.CHECKER_VERSION,
        "detector_model_digest": profile_repo.DETECTOR_MODEL_DIGEST,
        "routing_model_digest": profile_repo.ROUTING_MODEL_DIGEST,
        "checker_model_digest": check_controls.CHECKER_MODEL_DIGEST,
        "catalog_digest": profile_repo.CATALOG_DIGEST,
        "composition_digest": profile_repo.COMPOSITION_DIGEST,
        "support_matrix_digest": profile_repo.SUPPORT_MATRIX_DIGEST,
    }
    if not isinstance(tool, dict) or set(tool) != {"git_commit", *expected_tool}:
        raise ValueError("Holdout tool provenance has an invalid shape.")
    if re.fullmatch(r"[a-f0-9]{40}", str(tool.get("git_commit", ""))) is None:
        raise ValueError("Holdout tool provenance must pin a full git commit.")
    for field, expected in expected_tool.items():
        if tool.get(field) != expected:
            raise ValueError("Holdout tool provenance does not match the active " + field + ".")

    label_cases = labels_payload.get("cases")
    prediction_cases = predictions.get("cases")
    if not isinstance(label_cases, list) or not isinstance(prediction_cases, list):
        raise ValueError("Holdout labels and predictions must contain case arrays.")
    labels_by_id = {str(case["id"]): case for case in label_cases}
    if len(labels_by_id) != len(label_cases):
        raise ValueError("Holdout label case ids must be unique.")
    predicted_by_id: Dict[str, Mapping[str, Any]] = {}
    for case in prediction_cases:
        if not isinstance(case, dict) or set(case) != {"id", "repository", "commit", "profile"}:
            raise ValueError("Holdout prediction case has an invalid shape.")
        case_id = case.get("id")
        if (
            not isinstance(case_id, str)
            or external_review.CASE_ID.fullmatch(case_id) is None
            or case_id in predicted_by_id
        ):
            raise ValueError("Holdout prediction case ids must be unique and non-empty.")
        predicted_by_id[case_id] = case
    if set(predicted_by_id) != set(labels_by_id):
        raise ValueError("Holdout predictions must match the frozen case ids exactly.")

    rows = []
    cases = []
    for case_id in labels_by_id:
        label_case = labels_by_id[case_id]
        predicted_case = predicted_by_id[case_id]
        if (
            predicted_case.get("repository") != label_case.get("repository")
            or predicted_case.get("commit") != label_case.get("commit")
        ):
            raise ValueError("Holdout prediction repository/commit binding mismatch: " + case_id)
        profile = predicted_case.get("profile")
        if not isinstance(profile, dict):
            raise ValueError("Holdout prediction profile must be an object: " + case_id)
        profile_errors = validate_profile.validate(profile)
        if profile_errors:
            raise ValueError("Holdout prediction profile is invalid: " + profile_errors[0])
        provenance = profile["subject"].get("source_provenance")
        if (
            not isinstance(provenance, dict)
            or provenance.get("status") != "verified"
            or provenance.get("worktree") != "clean"
            or provenance.get("repository") != label_case.get("repository")
            or provenance.get("commit") != label_case.get("commit")
        ):
            raise ValueError(
                "Holdout Profile is not bound to the frozen clean Git commit: "
                + case_id
            )
        for field in (
            "detector_model_digest",
            "routing_model_digest",
            "catalog_digest",
            "composition_digest",
            "support_matrix_digest",
        ):
            if profile["subject"].get(field) != tool[field]:
                raise ValueError("Holdout prediction profile/tool binding mismatch: " + field)
        truth = external_review._labels(
            label_case["consensus"]["labels"], "consensus.labels"
        )
        prediction = _profile_labels(profile)
        support_class = _derived_support_class(profile)
        row = {
            "id": case_id,
            "framework_group": label_case["framework_group"],
            "support_class": support_class,
            "truth": truth,
            "prediction": prediction,
        }
        rows.append(row)
        cases.append(
            {
                "id": case_id,
                "repository": label_case["repository"],
                "commit": label_case["commit"],
                "framework_group": label_case["framework_group"],
                "support_class": support_class,
                "subject_revision": profile["subject"]["subject_revision"],
                "profile_artifact_digest": _digest(profile),
                "false_required_packs": sorted(
                    pack
                    for pack in profile_repo.PACK_ORDER
                    if prediction[pack] == "required" and truth[pack] != "required"
                ),
                "missed_required_packs": sorted(
                    pack
                    for pack in profile_repo.PACK_ORDER
                    if truth[pack] == "required" and prediction[pack] != "required"
                ),
                "exact_labels": truth == prediction,
            }
        )

    frameworks = sorted({str(row["framework_group"]) for row in rows})
    support_classes = ("supported", "partial", "unsupported")
    headline_verified = headline_trust is True
    return {
        "schema_version": "0.4.0",
        "suite": "independent_holdout_accuracy",
        "status": "pass" if headline_verified else "development-only",
        "headline_eligible": headline_verified,
        "evidence_trust": {
            "labels": {"status": "verified" if headline_verified else "unsigned"},
            "predictions": {
                "status": "verified" if headline_verified else "unsigned"
            },
            "attestation_chronology": (
                "verified" if headline_verified else "unverified"
            ),
        },
        "label_manifest_version": labels_payload.get("version"),
        "prediction_manifest_version": predictions.get("version"),
        "tool": dict(tool),
        "supported_aggregate": _aggregate(
            [row for row in rows if row["support_class"] == "supported"]
        ),
        "per_support_class": {
            support: _aggregate(
                [row for row in rows if row["support_class"] == support]
            )
            for support in support_classes
        },
        "per_framework": {
            framework: {
                support: _aggregate(
                    [
                        row
                        for row in rows
                        if row["framework_group"] == framework
                        and row["support_class"] == support
                    ]
                )
                for support in support_classes
            }
            for framework in frameworks
        },
        "per_pack": {
            pack: {
                support: _pack_aggregate(
                    [row for row in rows if row["support_class"] == support], pack
                )
                for support in support_classes
            }
            for pack in profile_repo.PACK_ORDER
        },
        "cases": cases,
        "claim_boundary": "Support class is derived from each validated Profile, and supported-stack metrics are isolated from partial and unsupported cases. Headline eligibility additionally requires signer-constrained cryptographic attestations whose trusted timestamps prove the frozen label artifact predates the prediction artifact. This report is not compliance evidence or proof of ecosystem representativeness.",
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare frozen external consensus with pinned ContextSec profiles."
    )
    parser.add_argument("labels", type=Path)
    parser.add_argument("predictions", type=Path)
    parser.add_argument("--labels-attestation-repo")
    parser.add_argument("--predictions-attestation-repo")
    parser.add_argument("--labels-signer-workflow")
    parser.add_argument("--predictions-signer-workflow")
    parser.add_argument("--allow-unsigned-development", action="store_true")
    args = parser.parse_args(argv)
    try:
        headline_trust = False
        if args.labels_attestation_repo or args.predictions_attestation_repo:
            if not args.labels_attestation_repo or not args.predictions_attestation_repo:
                raise ValueError("Both label and prediction attestations are required.")
            if not args.labels_signer_workflow or not args.predictions_signer_workflow:
                raise ValueError("Both label and prediction signer workflows are required.")
            trust = {
                "labels": attestation_verifier.verify(
                    args.labels,
                    args.labels_attestation_repo,
                    signer_workflow=args.labels_signer_workflow,
                ),
                "predictions": attestation_verifier.verify(
                    args.predictions,
                    args.predictions_attestation_repo,
                    signer_workflow=args.predictions_signer_workflow,
                ),
            }
            if not _trusted_evidence(trust):
                raise ValueError(
                    "Trusted label attestation must predate the prediction attestation."
                )
            headline_trust = True
        elif not args.allow_unsigned_development:
            raise ValueError(
                "Signed label and prediction attestations are required for a headline report; use --allow-unsigned-development only for non-headline local work."
            )
        result = evaluate(
            _load(args.labels, "External holdout labels", 8 * 1024 * 1024),
            _load(args.predictions, "External holdout predictions", 64 * 1024 * 1024),
            headline_trust,
        )
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    # The strict evaluator emits only metrics, fixed model identities, canonical
    # public repository/commit identifiers, and restricted case/group IDs. Raw
    # profiles, reviewer metadata, labels, process output, and credentials are
    # absent from this allowlisted report shape. This is the command's structured
    # result channel, not diagnostic logging.

    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
