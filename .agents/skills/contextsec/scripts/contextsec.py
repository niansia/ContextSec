#!/usr/bin/env python3
"""Small stdlib-only command dispatcher for the ContextSec decision layer."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import benchmark  # noqa: E402
import check_controls  # noqa: E402
import control_ledger  # noqa: E402
import external_review  # noqa: E402
import evaluate_holdout  # noqa: E402
import profile_repo  # noqa: E402
import validate_catalog  # noqa: E402
import validate_checks  # noqa: E402
import validate_ledger  # noqa: E402
import validate_profile  # noqa: E402
import support_matrix  # noqa: E402
import versioning  # noqa: E402


def doctor() -> int:
    matrix = support_matrix.SUPPORT_MATRIX
    payload = {
        "tool_version": versioning.TOOL_VERSION,
        "schema_version": versioning.SCHEMA_VERSION,
        "detector_version": profile_repo.DETECTOR_VERSION,
        "checker_version": check_controls.CHECKER_VERSION,
        "python": platform.python_version(),
        "python_supported": sys.version_info >= (3, 11),
        "platform": platform.system().lower(),
        "decision_model_digest": profile_repo.DECISION_MODEL_DIGEST,
        "routing_model_digest": profile_repo.ROUTING_MODEL_DIGEST,
        "detector_model_digest": profile_repo.DETECTOR_MODEL_DIGEST,
        "checker_model_digest": check_controls.CHECKER_MODEL_DIGEST,
        "catalog_digest": profile_repo.CATALOG_DIGEST,
        "composition_digest": profile_repo.COMPOSITION_DIGEST,
        "support_matrix_digest": profile_repo.SUPPORT_MATRIX_DIGEST,
        "support_matrix": matrix,
    }
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if payload["python_supported"] else 1


def explain(identifier: str, root: Optional[Path] = None) -> int:
    pack = next(
        (item for item in profile_repo.PACK_CATALOG["packs"] if item["id"] == identifier),
        None,
    )
    compositions = control_ledger.composition_rules()
    if pack is None:
        rule = next((item for item in compositions if item["id"] == identifier), None)
        if rule is None:
            print("error: unknown pack or composition: " + identifier, file=sys.stderr)
            return 2
        payload: Dict[str, Any] = dict(rule)
        if root is not None:
            profile = profile_repo.profile_repository(root)
            checks = check_controls.check_repository(root, profile=profile)
            ledger = control_ledger.build_ledger(profile, checks)
            payload["repository_evaluation"] = next(
                (
                    item
                    for item in ledger["ledger"]
                    if item["control_id"] == identifier
                ),
                None,
            )
            payload["gate"] = ledger["gate"]
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    related = [rule for rule in compositions if identifier in rule["requires"]]
    related_ids = {rule["id"] for rule in related}
    payload = {**pack, "related_compositions": related}
    if root is not None:
        profile = profile_repo.profile_repository(root)
        checks = check_controls.check_repository(root, profile=profile)
        ledger = control_ledger.build_ledger(profile, checks)
        payload["repository_evaluation"] = {
            "route": next(item for item in profile["routing"] if item["pack"] == identifier),
            "observations": [
                item for item in profile["observations"] if item["pack"] == identifier
            ],
            "controls": [
                item
                for item in ledger["ledger"]
                if item["source"] == {"type": "pack", "id": identifier}
            ],
            "compositions": [
                item
                for item in ledger["ledger"]
                if item["source"]["type"] == "composition"
                and item["control_id"] in related_ids
            ],
            "gate": ledger["gate"],
        }
    print(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
    )
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="contextsec",
        description="Profile product risk, explain routing, check controls, and evaluate releases.",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s " + versioning.TOOL_VERSION
    )
    parser.add_argument(
        "command",
        choices=(
            "profile",
            "check",
            "explain",
            "gate",
            "benchmark",
            "validate-catalog",
            "validate-profile",
            "validate-checks",
            "validate-ledger",
            "external-review",
            "evaluate-holdout",
            "doctor",
        ),
    )
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return doctor()
    if args.command == "profile":
        return profile_repo.main(args.arguments)
    if args.command == "check":
        return check_controls.main(args.arguments)
    if args.command == "gate":
        return control_ledger.main(args.arguments)
    if args.command == "benchmark":
        return benchmark.main(args.arguments)
    if args.command == "validate-catalog":
        return validate_catalog.main(args.arguments)
    if args.command == "validate-profile":
        return validate_profile.main(args.arguments)
    if args.command == "validate-checks":
        return validate_checks.main(args.arguments)
    if args.command == "validate-ledger":
        return validate_ledger.main(args.arguments)
    if args.command == "external-review":
        return external_review.main(args.arguments)
    if args.command == "evaluate-holdout":
        return evaluate_holdout.main(args.arguments)
    explain_parser = argparse.ArgumentParser(prog="contextsec explain")
    explain_parser.add_argument("identifier")
    explain_parser.add_argument("--repo", type=Path)
    explain_args = explain_parser.parse_args(args.arguments)
    return explain(explain_args.identifier, explain_args.repo)


if __name__ == "__main__":
    raise SystemExit(main())
