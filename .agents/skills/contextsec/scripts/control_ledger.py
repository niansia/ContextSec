#!/usr/bin/env python3
"""Compose applicable controls into an evidence-backed release ledger and gate."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import check_controls  # noqa: E402
import profile_repo  # noqa: E402
import safe_io  # noqa: E402
import validate_checks  # noqa: E402
import versioning  # noqa: E402

REFERENCE_DIR = Path(__file__).resolve().parents[1] / "references"
COMPOSITION_PATH = REFERENCE_DIR / "compositions" / "catalog.json"
SCHEMA_VERSION = versioning.SCHEMA_VERSION
APPLICABILITY_STATES = {"required", "candidate", "not_applicable", "unknown"}
VERIFICATION_STATES = {"verified", "failed", "unknown", "waived"}


def load_json_object(path: Path) -> Dict[str, Any]:
    try:
        payload = safe_io.read_json_object_bounded(
            path, 64 * 1024 * 1024, "Control evidence"
        )
    except (OSError, ValueError, RecursionError) as exc:
        raise ValueError("Unable to read JSON evidence: " + str(exc)) from exc
    return payload


def catalog_controls() -> Dict[str, Dict[str, Any]]:
    controls: Dict[str, Dict[str, Any]] = {}
    for pack in profile_repo.PACK_CATALOG["packs"]:
        for control in pack["controls"]:
            if control["id"] in controls:
                raise ValueError("Duplicate control id in catalog: " + control["id"])
            controls[control["id"]] = {**control, "pack": pack["id"]}
    return controls


def composition_rules() -> List[Dict[str, Any]]:
    payload = profile_repo.COMPOSITION_CATALOG
    rules = payload.get("rules")
    if payload.get("schema_version") != SCHEMA_VERSION or not isinstance(rules, list):
        raise ValueError("Composition catalog must be a compatible rules array.")
    return [dict(rule) for rule in rules if isinstance(rule, dict)]


def evidence_index(payload: Optional[Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if payload is None:
        return {}
    entries = payload.get("controls", [])
    if not isinstance(entries, list):
        raise ValueError("Evidence controls must be an array.")
    result: Dict[str, Dict[str, Any]] = {}
    expected = {
        "control_id",
        "applicability",
        "verification",
        "reason",
        "evidence_refs",
    }
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != expected:
            raise ValueError("Evidence controls have unexpected or missing fields.")
        if not isinstance(entry.get("control_id"), str):
            raise ValueError("Every evidence control must have a control_id.")
        control_id = entry["control_id"]
        if control_id in result:
            raise ValueError("Duplicate control evidence: " + control_id)
        applicability = entry.get("applicability")
        verification = entry.get("verification")
        if applicability not in APPLICABILITY_STATES:
            raise ValueError("Invalid evidence applicability for " + control_id)
        if verification not in VERIFICATION_STATES - {"waived"}:
            raise ValueError("Invalid evidence verification for " + control_id)
        if applicability == "not_applicable" and verification != "unknown":
            raise ValueError(
                "not_applicable evidence cannot claim control verification: "
                + control_id
            )
        if not isinstance(entry.get("reason"), str) or not entry["reason"]:
            raise ValueError("Control evidence requires a reason: " + control_id)
        references = entry.get("evidence_refs", [])
        if not isinstance(references, list) or not references or not all(
            isinstance(item, str) and item for item in references
        ):
            raise ValueError("evidence_refs must contain non-empty strings: " + control_id)
        result[control_id] = dict(entry)
    return result


def waiver_index(
    payload: Optional[Mapping[str, Any]], as_of: Optional[date]
) -> Dict[str, Dict[str, Any]]:
    if payload is None:
        return {}
    entries = payload.get("waivers", [])
    if not isinstance(entries, list):
        raise ValueError("Evidence waivers must be an array.")
    result: Dict[str, Dict[str, Any]] = {}
    required = {"control_id", "owner", "reason", "compensating_control", "expires"}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError(
                "Every waiver requires control, owner, reason, compensation, and expiry."
            )
        if not all(isinstance(entry[field], str) and entry[field] for field in required):
            raise ValueError("Waiver fields must be non-empty strings.")
        try:
            expiry = date.fromisoformat(entry["expires"])
        except ValueError as exc:
            raise ValueError("Waiver expiry must be YYYY-MM-DD.") from exc
        if entry["control_id"] in result:
            raise ValueError("Duplicate control waiver: " + entry["control_id"])
        result[entry["control_id"]] = {
            **entry,
            "valid": as_of is not None and as_of <= expiry,
        }
    return result


def validate_subject_binding(
    profile: Mapping[str, Any], checks: Mapping[str, Any]
) -> None:
    check_errors = validate_checks.validate(checks)
    if check_errors:
        raise ValueError("Checks semantic validation failed: " + check_errors[0])
    if profile_repo.decision_model_digest() != profile_repo.DECISION_MODEL_DIGEST:
        raise ValueError("Decision model changed after profiler initialization.")
    if profile.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Profile schema_version must be " + SCHEMA_VERSION + ".")
    if checks.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Checks schema_version must be " + SCHEMA_VERSION + ".")
    profile_subject = profile.get("subject", {})
    check_subject = checks.get("subject", {})
    live_profile_models = {
        "detector_version": profile_repo.DETECTOR_VERSION,
        "decision_model_digest": profile_repo.DECISION_MODEL_DIGEST,
        "routing_model_digest": profile_repo.ROUTING_MODEL_DIGEST,
        "detector_model_digest": profile_repo.DETECTOR_MODEL_DIGEST,
        "catalog_digest": profile_repo.CATALOG_DIGEST,
        "composition_digest": profile_repo.COMPOSITION_DIGEST,
        "support_matrix_digest": profile_repo.SUPPORT_MATRIX_DIGEST,
    }
    for field, expected in live_profile_models.items():
        if profile_subject.get(field) != expected:
            raise ValueError("Profile " + field + " does not match the live model.")
        if check_subject.get(field) != expected:
            raise ValueError("Checks " + field + " does not match the live model.")
    if profile.get("artifact_options") != checks.get("artifact_options"):
        raise ValueError("Checks/profile artifact_options mismatch.")
    comparisons: Tuple[Tuple[str, Any, Any], ...] = (
        ("repository", profile_subject.get("repository"), check_subject.get("repository")),
        (
            "subject_revision",
            profile_subject.get("subject_revision"),
            check_subject.get("subject_revision"),
        ),
        (
            "decision_model_digest",
            profile_subject.get("decision_model_digest"),
            check_subject.get("decision_model_digest"),
        ),
        *tuple(
            (field, profile_subject.get(field), check_subject.get(field))
            for field in (
                "detector_version",
                "routing_model_digest",
                "detector_model_digest",
                "catalog_digest",
                "composition_digest",
                "support_matrix_digest",
            )
        ),
        (
            "source_inventory_digest",
            profile_subject.get("source_inventory_digest"),
            check_subject.get("source_inventory_digest"),
        ),
        (
            "profile_coverage",
            profile.get("coverage", {}).get("status"),
            check_subject.get("profile_coverage"),
        ),
        (
            "profile_language_support",
            profile.get("coverage", {}).get("language_support"),
            check_subject.get("profile_language_support"),
        ),
    )
    for field, expected, actual in comparisons:
        if not expected or expected != actual:
            raise ValueError("Checks/profile " + field + " mismatch.")
    expected_active = list(
        dict.fromkeys(profile.get("required_packs", []) + profile.get("candidate_packs", []))
    )
    if checks.get("active_packs") != expected_active:
        raise ValueError("Checks/profile active_packs mismatch.")


def condition_applicability(
    condition: Optional[Mapping[str, Any]],
    pack_state: str,
    capabilities: Mapping[str, str],
) -> Tuple[str, str]:
    if condition is None:
        return pack_state, "The pack-level route applies to this control."
    operator = "all" if "all" in condition else "any" if "any" in condition else ""
    keys = condition.get(operator) if operator else None
    if operator not in {"all", "any"} or not isinstance(keys, list) or not keys:
        raise ValueError("Invalid applies_when condition in catalog.")
    states = [capabilities.get(str(key), "unknown") for key in keys]
    if operator == "all" and all(state == "present" for state in states):
        return pack_state, "All required sub-capabilities are present."
    if operator == "any" and any(state == "present" for state in states):
        return pack_state, "At least one required sub-capability is present."
    if operator == "all" and any(state == "not_observed" for state in states):
        return "not_applicable", "A required sub-capability was not observed."
    if operator == "any" and all(state == "not_observed" for state in states):
        return "not_applicable", "No alternative sub-capability was observed."
    return "unknown", "Sub-capability evidence is incomplete."


def evaluate_item(
    control_id: str,
    source: Mapping[str, str],
    severity: str,
    catalog_blocking: bool,
    required_verification: str,
    computed_applicability: str,
    applicability_reason: str,
    findings: Sequence[Mapping[str, Any]],
    supplied: Optional[Mapping[str, Any]],
    waiver: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    applicability = computed_applicability
    verification = "unknown"
    references: List[str] = []
    reasons = [applicability_reason]
    sources = ["applicability"]
    if supplied is not None:
        supplied_applicability = str(supplied["applicability"])
        if (
            computed_applicability == "required"
            and supplied_applicability != "required"
        ):
            raise ValueError(
                "Supplied evidence cannot downgrade required applicability: "
                + control_id
            )
        applicability = supplied_applicability
        verification = str(supplied["verification"])
        references.extend(supplied.get("evidence_refs", []))
        reasons.append(str(supplied["reason"]))
        sources.append("supplied-evidence")
    for finding in findings:
        applicability = "required"
        if finding["status"] == "failed":
            verification = "failed"
        elif finding["status"] == "verified" and verification != "failed":
            verification = "verified"
        references.append(str(finding["id"]))
        reasons.append(str(finding["title"]))
        sources.append("deterministic-check")
    blocking = bool(catalog_blocking and applicability == "required")
    if (
        blocking
        and verification in {"failed", "unknown"}
        and waiver is not None
        and waiver.get("valid")
    ):
        verification = "waived"
        reasons.append("An active, owner-attributed waiver covers this release gate.")
        sources.append("waiver")
    return {
        "control_id": control_id,
        "source": dict(source),
        "applicability": applicability,
        "verification": verification,
        "severity": severity,
        "blocking": blocking,
        "evidence_refs": sorted(set(references)),
        "required_verification": required_verification,
        "reason": " ".join(dict.fromkeys(reasons)),
        "evaluation_sources": sorted(set(sources)),
        "waiver": waiver,
    }


def build_ledger(
    profile: Mapping[str, Any],
    checks: Mapping[str, Any],
    supplied_evidence: Optional[Mapping[str, Any]] = None,
    as_of: Optional[date] = None,
) -> Dict[str, Any]:
    validate_subject_binding(profile, checks)
    if supplied_evidence is not None and set(supplied_evidence) != {
        "schema_version",
        "subject_revision",
        "controls",
        "waivers",
    }:
        raise ValueError("Supplied evidence has unexpected or missing fields.")
    if supplied_evidence is not None and supplied_evidence.get(
        "schema_version"
    ) != SCHEMA_VERSION:
        raise ValueError("Supplied evidence schema_version must be " + SCHEMA_VERSION + ".")
    if supplied_evidence is not None and supplied_evidence.get(
        "subject_revision"
    ) != profile["subject"]["subject_revision"]:
        raise ValueError(
            "Supplied evidence subject_revision does not match the current profile."
        )

    route = {item["pack"]: item for item in profile["routing"]}
    capabilities = {
        item["key"]: item["state"] for item in profile.get("capabilities", [])
    }
    catalog = catalog_controls()
    compositions = composition_rules()
    known = set(catalog) | {rule["id"] for rule in compositions}
    external = evidence_index(supplied_evidence)
    waivers = waiver_index(supplied_evidence, as_of)
    unknown_external = (set(external) | set(waivers)) - known
    if unknown_external:
        raise ValueError(
            "Unknown control ids in evidence: " + ", ".join(sorted(unknown_external))
        )

    findings_by_control: Dict[str, List[Mapping[str, Any]]] = {}
    for finding in checks.get("findings", []):
        for control_id in finding.get("control_ids", []):
            if control_id not in known:
                raise ValueError("Finding references unknown control id: " + control_id)
            findings_by_control.setdefault(control_id, []).append(finding)

    ledger: List[Dict[str, Any]] = []
    for pack in profile_repo.PACK_CATALOG["packs"]:
        pack_id = pack["id"]
        pack_state = route[pack_id]["state"]
        if pack_state not in {"required", "candidate"}:
            continue
        for control in pack["controls"]:
            applicability, reason = condition_applicability(
                control.get("applies_when"), pack_state, capabilities
            )
            control_id = control["id"]
            ledger.append(
                evaluate_item(
                    control_id,
                    {"type": "pack", "id": pack_id},
                    control["severity"],
                    control["blocking"],
                    control["required_verification"],
                    applicability,
                    " ".join(route[pack_id]["reasons"] + [reason]),
                    findings_by_control.get(control_id, []),
                    external.get(control_id),
                    waivers.get(control_id),
                )
            )

    active_compositions: List[str] = []
    for rule in compositions:
        states = [route[pack]["state"] for pack in rule["requires"]]
        if not all(state in {"required", "candidate"} for state in states):
            continue
        control_id = rule["id"]
        intersection = capabilities.get(rule["intersection_capability"], "unknown")
        actual_flow = intersection == "present" or bool(
            findings_by_control.get(control_id)
        )
        applicability = (
            "required"
            if actual_flow and all(state == "required" for state in states)
            else "candidate"
        )
        reason = (
            "Required because the context intersection has direct flow evidence."
            if applicability == "required"
            else "Candidate because the packs co-occur but their intersection is not established."
        )
        ledger.append(
            evaluate_item(
                control_id,
                {"type": "composition", "id": control_id},
                rule["severity"],
                rule["blocking"],
                rule["required_verification"],
                applicability,
                reason + " Packs: " + " + ".join(rule["requires"]) + ".",
                findings_by_control.get(control_id, []),
                external.get(control_id),
                waivers.get(control_id),
            )
        )
        active_compositions.append(control_id)

    ledger.sort(key=lambda item: item["control_id"])
    unwaived_blockers = [
        item
        for item in ledger
        if item["blocking"] and item["verification"] in {"failed", "unknown"}
    ]
    waived_blockers = [
        item
        for item in ledger
        if item["blocking"] and item["verification"] == "waived"
    ]
    coverage_block = (
        profile["coverage"]["status"] == "partial"
        or profile["coverage"]["language_support"] != "supported"
        or checks["subject"]["checker_coverage"]["traversal"] == "partial"
    )
    unresolved = [
        item
        for item in ledger
        if item["applicability"] in {"required", "candidate", "unknown"}
        and item["verification"] in {"failed", "unknown"}
    ]
    if coverage_block or unwaived_blockers:
        gate_status = "BLOCK"
    elif waived_blockers:
        gate_status = "WAIVED"
    elif unresolved:
        gate_status = "WARN"
    else:
        gate_status = "PASS"

    return {
        "schema_version": SCHEMA_VERSION,
        "evaluation_date": as_of.isoformat() if as_of is not None else None,
        "artifact_options": dict(profile["artifact_options"]),
        "subject": {
            "repository": profile["subject"]["repository"],
            "subject_revision": profile["subject"]["subject_revision"],
            "decision_model_digest": profile["subject"]["decision_model_digest"],
            "routing_model_digest": profile["subject"]["routing_model_digest"],
            "detector_version": profile["subject"]["detector_version"],
            "detector_model_digest": profile["subject"]["detector_model_digest"],
            "catalog_digest": profile["subject"]["catalog_digest"],
            "composition_digest": profile["subject"]["composition_digest"],
            "support_matrix_digest": profile["subject"]["support_matrix_digest"],
            "checker_model_digest": checks["subject"]["checker_model_digest"],
            "checker_version": checks["subject"]["checker_version"],
            "source_inventory_digest": profile["subject"]["source_inventory_digest"],
            "profile_coverage": profile["coverage"]["status"],
            "profile_language_support": profile["coverage"]["language_support"],
            "checker_coverage": checks["subject"]["checker_coverage"],
        },
        "active_compositions": sorted(active_compositions),
        "ledger": ledger,
        "summary": {
            "applicability": {
                state: sum(item["applicability"] == state for item in ledger)
                for state in sorted(APPLICABILITY_STATES)
            },
            "verification": {
                state: sum(item["verification"] == state for item in ledger)
                for state in sorted(VERIFICATION_STATES)
            },
            "total": len(ledger),
            "blocking_unresolved": len(unwaived_blockers),
            "blocking_waived": len(waived_blockers),
        },
        "gate": {
            "status": gate_status,
            "reason": (
                "Supported input traversal or stack coverage is incomplete."
                if coverage_block
                else (
                    "Blocking required controls failed or lack verification."
                    if unwaived_blockers
                    else (
                        "Every blocking gap has an active, owner-attributed waiver."
                        if waived_blockers
                        else (
                            "Only non-blocking, candidate, or unknown applicability gaps remain."
                            if unresolved
                            else "Every required control is verified or concretely not applicable."
                        )
                    )
                )
            ),
            "blocking_controls": [item["control_id"] for item in unwaived_blockers],
            "waived_controls": [item["control_id"] for item in waived_blockers],
        },
        "limitations": [
            "Applicability and verification are independent; unknown is never converted into verified.",
            "Pack co-occurrence creates a candidate composition until flow evidence establishes the intersection.",
            "Supplied evidence is accepted only when bound to this exact subject revision.",
            "A waiver is active only when an as-of date is supplied and it is not expired.",
            "Consumers must revalidate waiver-bearing ledgers against the intended release date.",
        ],
    }


def evaluate_repository(
    root: Path,
    supplied_evidence: Optional[Mapping[str, Any]] = None,
    as_of: Optional[date] = None,
    path_privacy: str = "heuristic",
) -> Dict[str, Any]:
    profile = profile_repo.profile_repository(root, path_privacy=path_privacy)
    checks = check_controls.check_repository(
        root, profile=profile, path_privacy=path_privacy
    )
    return build_ledger(profile, checks, supplied_evidence, as_of)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate the ContextSec control ledger and release gate."
    )
    parser.add_argument("--repo", default=".")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument(
        "--as-of", help="Deterministic waiver evaluation date (YYYY-MM-DD)."
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--path-privacy",
        choices=profile_repo.PATH_PRIVACY_MODES,
        default="heuristic",
    )
    args = parser.parse_args(argv)
    try:
        supplied = load_json_object(args.evidence) if args.evidence else None
        as_of = date.fromisoformat(args.as_of) if args.as_of else None
        result = evaluate_repository(
            Path(args.repo), supplied, as_of, args.path_privacy
        )
        rendered = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.output:
            profile_repo.write_output_atomic(args.output, rendered)
        else:
            sys.stdout.write(rendered)
        return 1 if result["gate"]["status"] == "BLOCK" else 0
    except (OSError, ValueError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
