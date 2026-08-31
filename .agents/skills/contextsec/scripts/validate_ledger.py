#!/usr/bin/env python3
"""Validate ContextSec ledger semantics with only the Python standard library."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

REFERENCE_DIR = Path(__file__).resolve().parents[1] / "references"
CATALOG = json.loads((REFERENCE_DIR / "catalog.json").read_text(encoding="utf-8"))
COMPOSITIONS = json.loads(
    (REFERENCE_DIR / "compositions" / "catalog.json").read_text(encoding="utf-8")
)
VERSION = "0.3.0"
APPLICABILITY = {"required", "candidate", "not_applicable", "unknown"}
VERIFICATION = {"verified", "failed", "unknown", "waived"}
SEVERITY = {"critical", "high", "medium", "low", "info"}


def validate(payload: Mapping[str, Any], as_of: Optional[date] = None) -> List[str]:
    errors: List[str] = []

    def exact(value: Mapping[str, Any], keys: set, label: str) -> None:
        if set(value) != keys:
            errors.append(label + " has unexpected or missing fields")

    exact(
        payload,
        {"schema_version", "evaluation_date", "subject", "active_compositions", "ledger", "summary", "gate", "limitations"},
        "ledger root",
    )
    if payload.get("schema_version") != VERSION:
        errors.append("unsupported schema_version")
    evaluation_value = payload.get("evaluation_date")
    evaluation_date: Optional[date] = None
    if evaluation_value is not None:
        try:
            evaluation_date = date.fromisoformat(str(evaluation_value))
        except ValueError:
            errors.append("evaluation_date is invalid")
    if as_of is not None and evaluation_date != as_of:
        errors.append("evaluation_date does not match the expected release date")
    controls: Dict[str, Dict[str, Any]] = {
        control["id"]: {**control, "source_type": "pack", "source_id": pack["id"]}
        for pack in CATALOG["packs"]
        for control in pack["controls"]
    }
    controls.update(
        {
            rule["id"]: {**rule, "source_type": "composition", "source_id": rule["id"]}
            for rule in COMPOSITIONS["rules"]
        }
    )
    subject = payload.get("subject")
    if not isinstance(subject, dict):
        errors.append("subject must be an object")
    else:
        exact(
            subject,
            {"repository", "subject_revision", "source_inventory_digest", "decision_model_digest", "profile_coverage", "profile_language_support", "checker_coverage"},
            "subject",
        )
        for field in ("subject_revision", "source_inventory_digest", "decision_model_digest"):
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", str(subject.get(field, ""))):
                errors.append("subject." + field + " is invalid")
        if subject.get("profile_coverage") not in {"complete", "partial"}:
            errors.append("subject.profile_coverage is invalid")
        if subject.get("profile_language_support") not in {
            "supported",
            "partial",
            "unsupported",
        }:
            errors.append("subject.profile_language_support is invalid")
        checker_coverage = subject.get("checker_coverage")
        if not isinstance(checker_coverage, dict):
            errors.append("subject.checker_coverage must be an object")
        else:
            exact(
                checker_coverage,
                {"traversal", "language_support", "checker_support", "match_enumeration"},
                "subject.checker_coverage",
            )
            if checker_coverage.get("traversal") not in {"complete", "partial"}:
                errors.append("subject.checker_coverage.traversal is invalid")
            if checker_coverage.get("language_support") not in {
                "supported",
                "partial",
                "unsupported",
            }:
                errors.append("subject.checker_coverage.language_support is invalid")
            if checker_coverage.get("checker_support") not in {"complete", "partial"}:
                errors.append("subject.checker_coverage.checker_support is invalid")
            if checker_coverage.get("match_enumeration") not in {
                "complete",
                "mixed_first_only",
                "first_only",
            }:
                errors.append("subject.checker_coverage.match_enumeration is invalid")

    rows = payload.get("ledger")
    if not isinstance(rows, list):
        errors.append("ledger must be an array")
        rows = []
    identifiers: List[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"ledger[{index}] must be an object")
            continue
        exact(
            row,
            {"control_id", "source", "applicability", "verification", "severity", "blocking", "evidence_refs", "required_verification", "reason", "evaluation_sources", "waiver"},
            f"ledger[{index}]",
        )
        control_id = row.get("control_id")
        if not isinstance(control_id, str):
            errors.append(f"ledger[{index}].control_id is invalid")
            continue
        identifiers.append(control_id)
        control = controls.get(control_id)
        if control is None:
            errors.append(f"ledger[{index}] has an unknown control")
            continue
        source = row.get("source")
        if not isinstance(source, dict):
            errors.append(f"ledger[{index}].source must be an object")
        else:
            exact(source, {"type", "id"}, f"ledger[{index}].source")
            if source != {"type": control["source_type"], "id": control["source_id"]}:
                errors.append(f"ledger[{index}].source does not match the catalog")
        if row.get("applicability") not in APPLICABILITY:
            errors.append(f"ledger[{index}] has invalid applicability")
        if row.get("verification") not in VERIFICATION:
            errors.append(f"ledger[{index}] has invalid verification")
        if row.get("severity") != control["severity"] or row.get("severity") not in SEVERITY:
            errors.append(f"ledger[{index}] severity does not match the catalog")
        if row.get("required_verification") != control["required_verification"]:
            errors.append(
                f"ledger[{index}] required_verification does not match the catalog"
            )
        expected_blocking = bool(
            control["blocking"] and row.get("applicability") == "required"
        )
        if type(row.get("blocking")) is not bool or row.get("blocking") != expected_blocking:
            errors.append(f"ledger[{index}] blocking does not match policy")
        for field in ("evidence_refs", "evaluation_sources"):
            value = row.get(field)
            if (
                not isinstance(value, list)
                or not all(isinstance(item, str) and item for item in value)
                or len(value) != len(set(value))
                or field == "evaluation_sources" and not value
            ):
                errors.append(f"ledger[{index}].{field} is invalid")
        evidence_refs = row.get("evidence_refs")
        evaluation_sources = row.get("evaluation_sources")
        source_set = set(evaluation_sources) if isinstance(evaluation_sources, list) and all(
            isinstance(item, str) for item in evaluation_sources
        ) else set()
        if not source_set <= {
            "applicability",
            "supplied-evidence",
            "deterministic-check",
            "waiver",
        } or "applicability" not in source_set:
            errors.append(f"ledger[{index}].evaluation_sources is inconsistent")
        if row.get("verification") in {"verified", "failed"} and (
            not isinstance(evidence_refs, list) or not evidence_refs
        ):
            errors.append(f"ledger[{index}] verified/failed state lacks evidence")
        if row.get("verification") in {"verified", "failed"} and not (
            {"supplied-evidence", "deterministic-check"} & source_set
        ):
            errors.append(f"ledger[{index}] verification source is inconsistent")
        if not isinstance(row.get("reason"), str) or not row["reason"]:
            errors.append(f"ledger[{index}].reason is invalid")
        waiver = row.get("waiver")
        if waiver is not None:
            if not isinstance(waiver, dict):
                errors.append(f"ledger[{index}].waiver is invalid")
            else:
                exact(
                    waiver,
                    {"control_id", "owner", "reason", "compensating_control", "expires", "valid"},
                    f"ledger[{index}].waiver",
                )
                string_fields = {
                    "control_id",
                    "owner",
                    "reason",
                    "compensating_control",
                    "expires",
                }
                if not all(
                    isinstance(waiver.get(field), str) and waiver.get(field)
                    for field in string_fields
                ):
                    errors.append(f"ledger[{index}].waiver has invalid fields")
                try:
                    expiry = date.fromisoformat(str(waiver.get("expires", "")))
                except ValueError:
                    errors.append(f"ledger[{index}].waiver expiry is invalid")
                    expiry = None
                trusted_date = as_of if as_of is not None else evaluation_date
                expected_valid = bool(
                    trusted_date is not None
                    and expiry is not None
                    and trusted_date <= expiry
                )
                if waiver.get("valid") != expected_valid:
                    errors.append(f"ledger[{index}].waiver validity is stale")
                if waiver.get("control_id") != control_id or type(waiver.get("valid")) is not bool:
                    errors.append(f"ledger[{index}].waiver does not match control")
        if row.get("verification") == "waived" and (
            not row.get("blocking")
            or not isinstance(waiver, dict)
            or waiver.get("valid") is not True
        ):
            errors.append(f"ledger[{index}] has invalid waived verification")
        if row.get("verification") == "waived" and "waiver" not in source_set:
            errors.append(f"ledger[{index}] waived state lacks waiver source")
    if len(identifiers) != len(set(identifiers)):
        errors.append("ledger control ids must be unique")
    has_waiver = any(
        isinstance(row, dict) and row.get("waiver") is not None for row in rows
    )
    if has_waiver and as_of is None:
        errors.append("waiver-bearing ledger requires an expected as-of date")

    active = payload.get("active_compositions")
    emitted_compositions = sorted(
        row["control_id"]
        for row in rows
        if isinstance(row, dict)
        and isinstance(row.get("source"), dict)
        and row["source"].get("type") == "composition"
    )
    if (
        not isinstance(active, list)
        or not all(isinstance(item, str) for item in active)
        or len(active) != len(set(active))
        or sorted(active) != emitted_compositions
    ):
        errors.append("active_compositions does not match ledger rows")

    summary = payload.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary must be an object")
    else:
        exact(
            summary,
            {"applicability", "verification", "total", "blocking_unresolved", "blocking_waived"},
            "summary",
        )
        expected_app = {
            state: sum(isinstance(row, dict) and row.get("applicability") == state for row in rows)
            for state in sorted(APPLICABILITY)
        }
        expected_ver = {
            state: sum(isinstance(row, dict) and row.get("verification") == state for row in rows)
            for state in sorted(VERIFICATION)
        }
        blockers = [
            row for row in rows if isinstance(row, dict) and row.get("blocking") and row.get("verification") in {"failed", "unknown"}
        ]
        waived = [
            row for row in rows if isinstance(row, dict) and row.get("blocking") and row.get("verification") == "waived"
        ]
        if summary.get("applicability") != expected_app or summary.get("verification") != expected_ver:
            errors.append("summary state counts do not match ledger")
        for group, states in (
            (summary.get("applicability"), APPLICABILITY),
            (summary.get("verification"), VERIFICATION),
        ):
            if not isinstance(group, dict) or set(group) != states or not all(
                type(group.get(state)) is int and group[state] >= 0 for state in states
            ):
                errors.append("summary state counts are invalid")
        for field in ("total", "blocking_unresolved", "blocking_waived"):
            if type(summary.get(field)) is not int or summary[field] < 0:
                errors.append("summary." + field + " is invalid")
        if summary.get("total") != len(rows):
            errors.append("summary total does not match ledger")
        if summary.get("blocking_unresolved") != len(blockers) or summary.get("blocking_waived") != len(waived):
            errors.append("summary blocker counts do not match ledger")

    gate = payload.get("gate")
    if not isinstance(gate, dict):
        errors.append("gate must be an object")
    else:
        exact(gate, {"status", "reason", "blocking_controls", "waived_controls"}, "gate")
        blockers = sorted(
            row["control_id"]
            for row in rows
            if isinstance(row, dict) and row.get("blocking") and row.get("verification") in {"failed", "unknown"}
        )
        waived = sorted(
            row["control_id"]
            for row in rows
            if isinstance(row, dict) and row.get("blocking") and row.get("verification") == "waived"
        )
        gate_blockers = gate.get("blocking_controls")
        gate_waived = gate.get("waived_controls")
        arrays_valid = all(
            isinstance(items, list)
            and all(isinstance(item, str) for item in items)
            and len(items) == len(set(items))
            for items in (gate_blockers, gate_waived)
        )
        if not arrays_valid:
            errors.append("gate control arrays are invalid")
        elif sorted(gate_blockers) != blockers or sorted(gate_waived) != waived:
            errors.append("gate controls do not match ledger")
        if not isinstance(gate.get("reason"), str) or not gate["reason"]:
            errors.append("gate reason is invalid")
        coverage_block = isinstance(subject, dict) and (
            subject.get("profile_coverage") == "partial"
            or subject.get("profile_language_support") != "supported"
            or isinstance(subject.get("checker_coverage"), dict)
            and subject["checker_coverage"].get("traversal") == "partial"
        )
        unresolved = any(
            isinstance(row, dict)
            and row.get("applicability") in {"required", "candidate", "unknown"}
            and row.get("verification") in {"failed", "unknown"}
            for row in rows
        )
        expected_status = (
            "BLOCK"
            if coverage_block or blockers
            else "WAIVED"
            if waived
            else "WARN"
            if unresolved
            else "PASS"
        )
        if gate.get("status") != expected_status:
            errors.append("gate status does not match ledger semantics")
    limitations = payload.get("limitations")
    if not isinstance(limitations, list) or not limitations or not all(
        isinstance(item, str) and item for item in limitations
    ):
        errors.append("limitations must be a non-empty string array")
    return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a ContextSec control ledger.")
    parser.add_argument("ledger", type=Path)
    parser.add_argument(
        "--as-of", help="Expected release date for waiver validation (YYYY-MM-DD)."
    )
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.ledger.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        print("error: unable to read ledger: " + str(exc), file=sys.stderr)
        return 2
    if not isinstance(payload, dict):
        print("error: ledger root must be an object", file=sys.stderr)
        return 2
    try:
        as_of = date.fromisoformat(args.as_of) if args.as_of else None
    except ValueError:
        print("error: --as-of must be YYYY-MM-DD", file=sys.stderr)
        return 2
    errors = validate(payload, as_of)
    if errors:
        for error in errors:
            print("error: " + error, file=sys.stderr)
        return 1
    print("Control ledger is semantically valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
