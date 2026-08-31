#!/usr/bin/env python3
"""Publish exact automated/manual verification coverage without inflating it."""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, Optional, Sequence

import check_controls
import profile_repo
import versioning

DETERMINISTIC_CHECKER_CONTROLS = {
    "AIR-DATA-001",
    "API-OBJ-001",
    "CICD-ACTION-001",
    "CICD-TOKEN-001",
    "EXT-EGRESS-001",
    "FND-LOG-001",
    "FND-SECRET-001",
    "PAY-IDEMP-001",
    "PII-ACCESS-001",
    "PII-LOG-001",
    "PII-PROC-001",
    "TEN-DB-001",
    "UPL-STORE-001",
}
DETERMINISTIC_CHECKER_COMPOSITIONS = {
    "COMP-AI-PII-001",
    "COMP-AI-TEN-001",
    "COMP-API-TEN-001",
    "COMP-UPL-TEN-001",
}
POLICY_AUDIT_CONTROLS = {
    "CICD-ACTION-001",
    "CICD-INJECT-001",
    "CICD-PR-001",
    "CICD-PROV-001",
    "CICD-TOKEN-001",
    "FND-DEP-001",
}


def build() -> Dict[str, Any]:
    rows = []
    known_controls = {
        control["id"]
        for pack in profile_repo.PACK_CATALOG["packs"]
        for control in pack["controls"]
    }
    known_compositions = {
        rule["id"] for rule in profile_repo.COMPOSITION_CATALOG["rules"]
    }
    if not DETERMINISTIC_CHECKER_CONTROLS <= known_controls:
        raise ValueError("Checker coverage references unknown controls.")
    if not POLICY_AUDIT_CONTROLS <= known_controls:
        raise ValueError("Policy coverage references unknown controls.")
    if not DETERMINISTIC_CHECKER_COMPOSITIONS <= known_compositions:
        raise ValueError("Checker coverage references unknown compositions.")
    for pack in profile_repo.PACK_CATALOG["packs"]:
        for control in pack["controls"]:
            identifier = control["id"]
            methods = []
            if identifier in DETERMINISTIC_CHECKER_CONTROLS:
                methods.append("deterministic-checker")
            if identifier in POLICY_AUDIT_CONTROLS:
                methods.append("repository-policy-audit")
            rows.append(
                {
                    "id": identifier,
                    "kind": "control",
                    "source": pack["id"],
                    "verification_class": "automated" if methods else "evidence-required",
                    "automated_methods": methods,
                    "required_verification": control["required_verification"],
                }
            )
    for rule in profile_repo.COMPOSITION_CATALOG["rules"]:
        identifier = rule["id"]
        methods = (
            ["deterministic-checker"]
            if identifier in DETERMINISTIC_CHECKER_COMPOSITIONS
            else []
        )
        rows.append(
            {
                "id": identifier,
                "kind": "composition",
                "source": identifier,
                "verification_class": "automated" if methods else "evidence-required",
                "automated_methods": methods,
                "required_verification": rule["required_verification"],
            }
        )
    rows.sort(key=lambda item: (item["kind"], item["id"]))
    automated = sum(item["verification_class"] == "automated" for item in rows)
    return {
        "schema_version": versioning.SCHEMA_VERSION,
        "artifact_type": "verification-coverage",
        "status": "pass",
        "model": {
            "catalog_digest": profile_repo.CATALOG_DIGEST,
            "composition_digest": profile_repo.COMPOSITION_DIGEST,
            "checker_model_digest": check_controls.CHECKER_MODEL_DIGEST,
        },
        "summary": {
            "total": len(rows),
            "automated": automated,
            "evidence_required": len(rows) - automated,
            "automated_ratio": round(automated / len(rows), 4),
        },
        "items": rows,
        "claim_boundary": "Automated means a supported deterministic checker or repository-policy audit exists; it does not mean the control passed for a repository. Evidence-required rows remain unknown until relevant verification evidence is supplied.",
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Report exact ContextSec verification coverage.")
    parser.parse_args(argv)
    print(json.dumps(build(), indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
