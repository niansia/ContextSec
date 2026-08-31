#!/usr/bin/env python3
"""Validate independent labels and report agreement without erasing disagreement."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import profile_repo  # noqa: E402
import safe_io  # noqa: E402

LABEL_STATES = ("required", "candidate", "inactive", "unknown")
SCHEMA_URL = "https://raw.githubusercontent.com/niansia/ContextSec/v0.4.0/benchmarks/external-review.schema.json"


def _load(path: Path) -> Dict[str, Any]:
    return safe_io.read_json_object_bounded(
        path, 2 * 1024 * 1024, "External review manifest"
    )


def _labels(value: Any, label: str) -> Dict[str, str]:
    packs = set(profile_repo.PACK_ORDER)
    if (
        not isinstance(value, dict)
        or set(value) != packs
        or not all(state in LABEL_STATES for state in value.values())
    ):
        raise ValueError(label + " must label every ContextSec pack exactly once.")
    return dict(value)


def _agreement(pairs: Sequence[tuple[str, str]]) -> Dict[str, Any]:
    if not pairs:
        return {
            "rating_count": 0,
            "raw_agreement": None,
            "cohen_kappa": None,
            "confusion_counts": {
                left: {right: 0 for right in LABEL_STATES}
                for left in LABEL_STATES
            },
            "label_prevalence": {
                "annotator_a": {state: 0.0 for state in LABEL_STATES},
                "annotator_b": {state: 0.0 for state in LABEL_STATES},
            },
        }
    observed = sum(left == right for left, right in pairs) / len(pairs)
    expected = 0.0
    for state in LABEL_STATES:
        left = sum(item[0] == state for item in pairs) / len(pairs)
        right = sum(item[1] == state for item in pairs) / len(pairs)
        expected += left * right
    kappa = (observed - expected) / (1.0 - expected) if expected < 1.0 else None
    confusion = {
        left: {
            right: sum(pair == (left, right) for pair in pairs)
            for right in LABEL_STATES
        }
        for left in LABEL_STATES
    }
    return {
        "rating_count": len(pairs),
        "raw_agreement": round(observed, 4),
        "cohen_kappa": round(kappa, 4) if kappa is not None else None,
        "confusion_counts": confusion,
        "label_prevalence": {
            "annotator_a": {
                state: round(sum(pair[0] == state for pair in pairs) / len(pairs), 4)
                for state in LABEL_STATES
            },
            "annotator_b": {
                state: round(sum(pair[1] == state for pair in pairs) / len(pairs), 4)
                for state in LABEL_STATES
            },
        },
    }


def evaluate(payload: Mapping[str, Any]) -> Dict[str, Any]:
    if set(payload) != {
        "$schema",
        "version",
        "status",
        "sampling_frame",
        "review_policy",
        "cases",
    }:
        raise ValueError("External review manifest has unexpected or missing fields.")
    if payload.get("$schema") != SCHEMA_URL:
        raise ValueError("External review manifest schema identity is incompatible.")
    if not isinstance(payload.get("version"), str) or not payload["version"]:
        raise ValueError("External review manifest version is invalid.")
    if payload.get("status") != "complete":
        raise ValueError("External review evidence must be marked complete.")
    sampling = payload.get("sampling_frame")
    if not isinstance(sampling, dict) or set(sampling) != {
        "population",
        "selection_method",
        "inclusion_criteria",
        "exclusion_criteria",
        "freeze_date",
    }:
        raise ValueError("Sampling frame must be frozen and fully declared.")
    try:
        date.fromisoformat(str(sampling.get("freeze_date", "")))
    except ValueError:
        raise ValueError("Sampling freeze_date must be YYYY-MM-DD.")
    for field in ("population", "selection_method"):
        if not isinstance(sampling.get(field), str) or not sampling[field]:
            raise ValueError("Sampling frame " + field + " must be non-empty.")
    for field in ("inclusion_criteria", "exclusion_criteria"):
        value = sampling.get(field)
        if not isinstance(value, list) or not value or not all(
            isinstance(item, str) and item for item in value
        ):
            raise ValueError("Sampling frame " + field + " must be non-empty strings.")
    policy = payload.get("review_policy")
    expected_policy = {
        "detector_implementers_excluded": True,
        "contextsec_contributors_excluded": True,
        "reviewers_label_before_tool_output": True,
        "reviewers_from_distinct_organizations": True,
        "adjudicator_independent_of_reviewers": True,
        "conflicts_disclosed": True,
        "disagreements_retained": True,
        "minimum_reviewers_per_case": 2,
    }
    if policy != expected_policy:
        raise ValueError("External review policy does not preserve independence.")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("External review evidence must contain at least one case.")
    ids: list[str] = []
    overall_pairs: list[tuple[str, str]] = []
    per_pack: Dict[str, list[tuple[str, str]]] = {
        pack: [] for pack in profile_repo.PACK_ORDER
    }
    framework_pairs: Dict[str, list[tuple[str, str]]] = {}
    disagreements = 0
    normalized_cases = []
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
            "id",
            "repository",
            "commit",
            "framework_group",
            "license_spdx",
            "license_evidence_url",
            "selection_rank",
            "sampling_reason",
            "frozen_at",
            "annotator_a",
            "annotator_b",
            "consensus",
        }:
            raise ValueError("External review case has an invalid shape.")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError("External review case id is invalid.")
        ids.append(case_id)
        if re.fullmatch(r"[a-f0-9]{40}", str(case.get("commit", ""))) is None:
            raise ValueError("External review cases must pin full commit IDs.")
        if re.fullmatch(
            r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
            str(case.get("repository", "")),
        ) is None:
            raise ValueError("External review repository must be a canonical GitHub URL.")
        if not isinstance(case.get("license_spdx"), str) or not case["license_spdx"]:
            raise ValueError("External review license_spdx is required.")
        if re.fullmatch(r"https://[^\s]+", str(case.get("license_evidence_url", ""))) is None:
            raise ValueError("External review license evidence must be an HTTPS URL.")
        if type(case.get("selection_rank")) is not int or case["selection_rank"] < 1:
            raise ValueError("External review selection_rank must be a positive integer.")
        if not isinstance(case.get("sampling_reason"), str) or not case["sampling_reason"]:
            raise ValueError("External review sampling_reason is required.")
        try:
            date.fromisoformat(str(case.get("frozen_at", "")))
        except ValueError:
            raise ValueError("External review frozen_at must be YYYY-MM-DD.")
        reviewers = []
        for role in ("annotator_a", "annotator_b"):
            reviewer = case.get(role)
            if not isinstance(reviewer, dict) or set(reviewer) != {
                "reviewer_id",
                "implemented_detectors",
                "contextsec_contributor",
                "organization",
                "conflicts_of_interest",
                "expertise_class",
                "labels_frozen_at",
                "labels",
            }:
                raise ValueError(role + " has an invalid shape.")
            if reviewer.get("implemented_detectors") is not False:
                raise ValueError("Detector implementers cannot label the external holdout.")
            if reviewer.get("contextsec_contributor") is not False:
                raise ValueError("ContextSec contributors cannot label the external holdout.")
            if not isinstance(reviewer.get("reviewer_id"), str) or not reviewer["reviewer_id"]:
                raise ValueError(role + " requires a reviewer_id.")
            if not isinstance(reviewer.get("expertise_class"), str) or not reviewer["expertise_class"]:
                raise ValueError(role + " requires an expertise_class.")
            if not isinstance(reviewer.get("organization"), str) or not reviewer["organization"]:
                raise ValueError(role + " requires an organization.")
            if reviewer.get("conflicts_of_interest") != []:
                raise ValueError(role + " must disclose and resolve conflicts of interest.")
            try:
                date.fromisoformat(str(reviewer.get("labels_frozen_at", "")))
            except ValueError:
                raise ValueError(role + ".labels_frozen_at must be YYYY-MM-DD.")
            reviewers.append(_labels(reviewer.get("labels"), role + ".labels"))
        if case["annotator_a"]["reviewer_id"] == case["annotator_b"]["reviewer_id"]:
            raise ValueError("External cases require two distinct reviewers.")
        if case["annotator_a"]["organization"] == case["annotator_b"]["organization"]:
            raise ValueError("External reviewers must come from distinct organizations.")
        consensus = case.get("consensus")
        if not isinstance(consensus, dict) or set(consensus) != {
            "labels",
            "adjudication_reason",
            "adjudicator_id",
            "adjudicator_implemented_detectors",
            "adjudicator_contextsec_contributor",
            "adjudicator_organization",
            "adjudicator_conflicts_of_interest",
        }:
            raise ValueError("Consensus must stay separate from raw annotations.")
        consensus_labels = _labels(consensus.get("labels"), "consensus.labels")
        if not isinstance(consensus.get("adjudication_reason"), str) or not consensus["adjudication_reason"]:
            raise ValueError("Consensus requires a non-empty adjudication reason.")
        if not isinstance(consensus.get("adjudicator_id"), str) or not consensus["adjudicator_id"]:
            raise ValueError("Consensus requires an adjudicator_id.")
        if consensus.get("adjudicator_implemented_detectors") is not False:
            raise ValueError("A detector implementer cannot adjudicate the external holdout.")
        if consensus.get("adjudicator_contextsec_contributor") is not False:
            raise ValueError("A ContextSec contributor cannot adjudicate the external holdout.")
        if consensus.get("adjudicator_conflicts_of_interest") != []:
            raise ValueError("The adjudicator must disclose and resolve conflicts of interest.")
        if (
            not isinstance(consensus.get("adjudicator_organization"), str)
            or not consensus["adjudicator_organization"]
        ):
            raise ValueError("Consensus requires an adjudicator organization.")
        reviewer_ids = {
            case["annotator_a"]["reviewer_id"],
            case["annotator_b"]["reviewer_id"],
        }
        reviewer_organizations = {
            case["annotator_a"]["organization"],
            case["annotator_b"]["organization"],
        }
        if consensus["adjudicator_id"] in reviewer_ids:
            raise ValueError("The adjudicator must be distinct from both reviewers.")
        if consensus["adjudicator_organization"] in reviewer_organizations:
            raise ValueError("The adjudicator must be organizationally independent.")
        framework = case.get("framework_group")
        if not isinstance(framework, str) or not framework:
            raise ValueError("External cases require a framework_group.")
        case_disagreements = []
        for pack in profile_repo.PACK_ORDER:
            pair = (reviewers[0][pack], reviewers[1][pack])
            overall_pairs.append(pair)
            per_pack[pack].append(pair)
            framework_pairs.setdefault(framework, []).append(pair)
            if pair[0] != pair[1]:
                disagreements += 1
                case_disagreements.append(pack)
        normalized_cases.append(
            {
                "id": case_id,
                "repository": case["repository"],
                "commit": case["commit"],
                "framework_group": framework,
                "license_spdx": case["license_spdx"],
                "license_evidence_url": case["license_evidence_url"],
                "selection_rank": case["selection_rank"],
                "sampling_reason": case["sampling_reason"],
                "frozen_at": case["frozen_at"],
                "annotator_expertise_classes": [
                    case["annotator_a"]["expertise_class"],
                    case["annotator_b"]["expertise_class"],
                ],
                "annotator_organizations": [
                    case["annotator_a"]["organization"],
                    case["annotator_b"]["organization"],
                ],
                "adjudicator_id": consensus["adjudicator_id"],
                "adjudicator_organization": consensus["adjudicator_organization"],
                "disagreement_packs": case_disagreements,
                "consensus_labels": consensus_labels,
            }
        )
    if len(ids) != len(set(ids)):
        raise ValueError("External review case ids must be unique.")
    ranks = [case["selection_rank"] for case in cases]
    if len(ranks) != len(set(ranks)):
        raise ValueError("External review selection_rank values must be unique.")
    return {
        "schema_version": "0.4.0",
        "suite": "independent_external_labels",
        "status": "pass",
        "manifest_version": payload.get("version"),
        "case_count": len(cases),
        "raw_disagreement_count": disagreements,
        "agreement": _agreement(overall_pairs),
        "per_pack_agreement": {
            pack: _agreement(per_pack[pack]) for pack in profile_repo.PACK_ORDER
        },
        "per_framework_agreement": {
            framework: _agreement(pairs)
            for framework, pairs in sorted(framework_pairs.items())
        },
        "cases": normalized_cases,
        "sampling_frame": dict(sampling),
        "claim_boundary": "Agreement measures independent applicability labels only; it is not detector accuracy, ecosystem representativeness, or compliance evidence.",
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate independent ContextSec labels.")
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args(argv)
    try:
        result = evaluate(_load(args.manifest))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
