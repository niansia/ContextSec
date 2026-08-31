#!/usr/bin/env python3
"""Validate semantic consistency of ContextSec deterministic check output."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, List, Mapping, Optional, Sequence, Set

REFERENCE_DIR = Path(__file__).resolve().parents[1] / "references"
CATALOG = json.loads((REFERENCE_DIR / "catalog.json").read_text(encoding="utf-8"))
PACKS = {item["id"] for item in CATALOG["packs"]}
CHECKER_VERSION = "0.3.0"


def digest(material: str) -> str:
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def exact_keys(value: Mapping[str, Any], expected: Set[str], label: str, errors: List[str]) -> None:
    if set(value) != expected:
        errors.append(label + " has unexpected or missing fields")


def known_controls() -> Set[str]:
    controls = {
        control["id"]
        for pack in CATALOG["packs"]
        for control in pack["controls"]
    }
    compositions = json.loads(
        (REFERENCE_DIR / "compositions" / "catalog.json").read_text(encoding="utf-8")
    )
    controls.update(rule["id"] for rule in compositions["rules"])
    return controls


def validate(payload: Mapping[str, Any]) -> List[str]:
    errors: List[str] = []
    exact_keys(
        payload,
        {"schema_version", "subject", "active_packs", "findings", "finding_summary", "limitations"},
        "checks",
        errors,
    )
    if payload.get("schema_version") != "0.3.0":
        errors.append("unsupported schema_version")
    active = payload.get("active_packs")
    if (
        not isinstance(active, list)
        or not all(isinstance(item, str) for item in active)
        or not set(active) <= PACKS
        or len(active) != len(set(active))
    ):
        errors.append("active_packs must be a unique array of known packs")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be an array")
        findings = []
    ids: List[str] = []
    controls = known_controls()
    counts = {"failed": 0, "unknown": 0, "verified": 0}
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            errors.append(f"findings[{index}] must be an object")
            continue
        exact_keys(
            item,
            {"id", "checker", "control_ids", "status", "severity", "title", "impact", "attack_path", "evidence", "method"},
            f"findings[{index}]",
            errors,
        )
        finding_id = item.get("id")
        if not isinstance(finding_id, str) or not re.fullmatch(
            r"finding-[a-z0-9-]+", finding_id
        ):
            errors.append(f"findings[{index}] has an invalid id")
        else:
            ids.append(finding_id)
        status = item.get("status")
        if status not in {"verified", "failed", "unknown", "not_applicable"}:
            errors.append(f"findings[{index}] has an invalid status")
        elif status in counts:
            counts[status] += 1
        if item.get("severity") not in {
            "critical",
            "high",
            "medium",
            "low",
            "info",
        }:
            errors.append(f"findings[{index}] has an invalid severity")
        for field in ("title", "impact", "attack_path", "method"):
            if not isinstance(item.get(field), str) or not item.get(field):
                errors.append(f"findings[{index}].{field} must be non-empty")
        checker = item.get("checker")
        if (
            not isinstance(checker, dict)
            or not re.fullmatch(r"[A-Z0-9-]+", str(checker.get("id", "")))
            or not isinstance(checker.get("version"), str)
            or checker.get("version") != CHECKER_VERSION
        ):
            errors.append(f"findings[{index}] has invalid checker metadata")
        elif isinstance(checker, dict):
            exact_keys(checker, {"id", "version"}, f"findings[{index}].checker", errors)
        control_ids = item.get("control_ids")
        if (
            not isinstance(control_ids, list)
            or not control_ids
            or not all(isinstance(control_id, str) for control_id in control_ids)
            or not set(control_ids) <= controls
        ):
            errors.append(f"findings[{index}] references an unknown control")
        elif len(control_ids) != len(set(control_ids)):
            errors.append(f"findings[{index}] has duplicate controls")
        evidence = item.get("evidence")
        evidence_fields = {
            "path",
            "locator",
            "evidence_id",
            "location_id",
            "content_digest",
            "fingerprint",
            "subject_revision",
        }
        if not isinstance(evidence, dict) or not evidence_fields <= set(evidence):
            errors.append(f"findings[{index}] has incomplete evidence")
        elif (
            not isinstance(evidence.get("path"), str)
            or not evidence.get("path")
            or not re.fullmatch(r"line:[1-9][0-9]*", str(evidence.get("locator", "")))
            or any(
                not re.fullmatch(r"sha256:[a-f0-9]{64}", str(evidence.get(field, "")))
                for field in (
                    "evidence_id",
                    "location_id",
                    "content_digest",
                    "fingerprint",
                    "subject_revision",
                )
            )
            or (
                isinstance(payload.get("subject"), dict)
                and evidence.get("subject_revision")
                != payload["subject"].get("subject_revision")
            )
        ):
            errors.append(f"findings[{index}] has invalid evidence values")
        if isinstance(evidence, dict):
            exact_keys(evidence, evidence_fields, f"findings[{index}].evidence", errors)
            if isinstance(checker, dict):
                path = str(evidence.get("path", ""))
                locator = str(evidence.get("locator", ""))
                checker_id = str(checker.get("id", ""))
                evidence_id = digest(
                    "\x1f".join(
                        ("evidence", path, locator, checker_id, CHECKER_VERSION)
                    )
                )
                location_id = digest("\x1f".join(("location", path, locator)))
                fingerprint = digest(
                    "\x1f".join(
                        (
                            "fingerprint",
                            evidence_id,
                            str(evidence.get("content_digest", "")),
                        )
                    )
                )
                if evidence.get("evidence_id") != evidence_id:
                    errors.append(f"findings[{index}] evidence_id is inconsistent")
                if evidence.get("location_id") != location_id:
                    errors.append(f"findings[{index}] location_id is inconsistent")
                if evidence.get("fingerprint") != fingerprint:
                    errors.append(f"findings[{index}] fingerprint is inconsistent")
                suffix = hashlib.sha256(
                    (path + "\x1f" + locator).encode("utf-8")
                ).hexdigest()[:8]
                if item.get("id") != "finding-" + checker_id.lower() + "-" + suffix:
                    errors.append(f"findings[{index}] id is inconsistent")
    if len(ids) != len(set(ids)):
        errors.append("finding ids must be unique")

    summary = payload.get("finding_summary")
    expected = {
        "failed_findings": counts["failed"],
        "unknown_findings": counts["unknown"],
        "verified_findings": counts["verified"],
        "total_findings": len(findings),
    }
    if summary != expected:
        errors.append("finding_summary does not match findings")
    subject = payload.get("subject")
    if not isinstance(subject, dict):
        errors.append("subject must be an object")
    else:
        exact_keys(
            subject,
            {"repository", "subject_revision", "source_inventory_digest", "decision_model_digest", "checker_version", "profile_coverage", "profile_language_support", "checker_coverage", "checker_input_hash"},
            "subject",
            errors,
        )
        if subject.get("profile_coverage") not in {"complete", "partial"}:
            errors.append("subject.profile_coverage must be complete or partial")
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
            exact_keys(
                checker_coverage,
                {"traversal", "language_support", "checker_support", "match_enumeration"},
                "subject.checker_coverage",
                errors,
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
        if not re.fullmatch(
            r"sha256:[a-f0-9]{64}", str(subject.get("checker_input_hash", ""))
        ):
            errors.append("subject.checker_input_hash must be a SHA-256 identifier")
        if not re.fullmatch(
            r"sha256:[a-f0-9]{64}", str(subject.get("subject_revision", ""))
        ):
            errors.append("subject.subject_revision must be a SHA-256 identifier")
        if not re.fullmatch(
            r"sha256:[a-f0-9]{64}",
            str(subject.get("decision_model_digest", "")),
        ):
            errors.append("subject.decision_model_digest must be a SHA-256 identifier")
        if not re.fullmatch(
            r"sha256:[a-f0-9]{64}",
            str(subject.get("source_inventory_digest", "")),
        ):
            errors.append("subject.source_inventory_digest must be a SHA-256 identifier")
        if not isinstance(subject.get("repository"), str) or not subject.get(
            "repository"
        ):
            errors.append("subject.repository must be non-empty")
    limitations = payload.get("limitations")
    if (
        not isinstance(limitations, list)
        or not limitations
        or not all(isinstance(item, str) and item for item in limitations)
    ):
        errors.append("limitations must be a non-empty string array")
    return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate ContextSec control-check output."
    )
    parser.add_argument("checks", type=Path)
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.checks.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        print("error: unable to read checks: " + str(exc), file=sys.stderr)
        return 2
    if not isinstance(payload, dict):
        print("error: checks root must be an object", file=sys.stderr)
        return 2
    errors = validate(payload)
    if errors:
        for error in errors:
            print("error: " + error, file=sys.stderr)
        return 1
    print("Control checks are semantically valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
