#!/usr/bin/env python3
"""Validate independent labels and report agreement without erasing disagreement."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import profile_repo  # noqa: E402
import safe_io  # noqa: E402

LABEL_STATES = ("required", "candidate", "inactive", "unknown")


def _load(path: Path) -> Dict[str, Any]:
    payload = profile_repo.strict_json_loads(
        safe_io.read_regular_file(path, 2 * 1024 * 1024).decode("utf-8-sig")
    )
    if not isinstance(payload, dict):
        raise ValueError("External review manifest root must be an object.")
    return payload


def _labels(value: Any, label: str) -> Dict[str, str]:
    packs = set(profile_repo.PACK_ORDER)
    if (
        not isinstance(value, dict)
        or set(value) != packs
        or not all(state in LABEL_STATES for state in value.values())
    ):
        raise ValueError(label + " must label every ContextSec pack exactly once.")
    return dict(value)


def _agreement(pairs: Sequence[tuple[str, str]]) -> Dict[str, float]:
    if not pairs:
        return {"raw_agreement": 1.0, "cohen_kappa": 1.0}
    observed = sum(left == right for left, right in pairs) / len(pairs)
    expected = 0.0
    for state in LABEL_STATES:
        left = sum(item[0] == state for item in pairs) / len(pairs)
        right = sum(item[1] == state for item in pairs) / len(pairs)
        expected += left * right
    kappa = (
        (observed - expected) / (1.0 - expected)
        if expected < 1.0
        else (1.0 if observed == 1.0 else 0.0)
    )
    return {
        "raw_agreement": round(observed, 4),
        "cohen_kappa": round(kappa, 4),
    }


def evaluate(payload: Mapping[str, Any]) -> Dict[str, Any]:
    if set(payload) != {
        "version",
        "status",
        "sampling_frame",
        "review_policy",
        "cases",
    }:
        raise ValueError("External review manifest has unexpected or missing fields.")
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
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(sampling.get("freeze_date", ""))):
        raise ValueError("Sampling freeze_date must be YYYY-MM-DD.")
    policy = payload.get("review_policy")
    expected_policy = {
        "detector_implementers_excluded": True,
        "reviewers_label_before_tool_output": True,
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
            "support_class",
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
        if case.get("support_class") not in {"supported", "partial", "unsupported"}:
            raise ValueError("External review support_class is invalid.")
        reviewers = []
        for role in ("annotator_a", "annotator_b"):
            reviewer = case.get(role)
            if not isinstance(reviewer, dict) or set(reviewer) != {
                "reviewer_id",
                "implemented_detectors",
                "labels",
            }:
                raise ValueError(role + " has an invalid shape.")
            if reviewer.get("implemented_detectors") is not False:
                raise ValueError("Detector implementers cannot label the external holdout.")
            if not isinstance(reviewer.get("reviewer_id"), str) or not reviewer["reviewer_id"]:
                raise ValueError(role + " requires a reviewer_id.")
            reviewers.append(_labels(reviewer.get("labels"), role + ".labels"))
        if case["annotator_a"]["reviewer_id"] == case["annotator_b"]["reviewer_id"]:
            raise ValueError("External cases require two distinct reviewers.")
        consensus = case.get("consensus")
        if not isinstance(consensus, dict) or set(consensus) != {
            "labels",
            "adjudication_reason",
        }:
            raise ValueError("Consensus must stay separate from raw annotations.")
        consensus_labels = _labels(consensus.get("labels"), "consensus.labels")
        if not isinstance(consensus.get("adjudication_reason"), str) or not consensus["adjudication_reason"]:
            raise ValueError("Consensus requires a non-empty adjudication reason.")
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
                "support_class": case["support_class"],
                "disagreement_packs": case_disagreements,
                "consensus_labels": consensus_labels,
            }
        )
    if len(ids) != len(set(ids)):
        raise ValueError("External review case ids must be unique.")
    return {
        "schema_version": "0.1.0",
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
