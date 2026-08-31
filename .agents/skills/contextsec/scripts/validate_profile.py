#!/usr/bin/env python3
"""Validate ContextSec profile semantics using only the Python standard library."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import profile_repo  # noqa: E402

PACKS = profile_repo.PACK_ORDER
CLAIMS = profile_repo.PACK_CLAIMS


def require(condition: bool, message: str, errors: List[str]) -> None:
    if not condition:
        errors.append(message)


def exact_keys(value: Mapping[str, Any], expected: set, label: str, errors: List[str]) -> None:
    require(set(value) == expected, label + " has unexpected or missing fields", errors)


def validate(profile: Mapping[str, Any]) -> List[str]:
    errors: List[str] = []
    exact_keys(
        profile,
        {
            "schema_version",
            "subject",
            "coverage",
            "observations",
            "claims",
            "capabilities",
            "routing",
            "required_packs",
            "candidate_packs",
            "contradictions",
            "limitations",
        },
        "profile",
        errors,
    )
    require(
        profile.get("schema_version") == profile_repo.SCHEMA_VERSION,
        "unsupported schema_version",
        errors,
    )

    subject = profile.get("subject")
    require(isinstance(subject, dict), "subject must be an object", errors)
    if isinstance(subject, dict):
        exact_keys(
            subject,
            {
                "repository",
                "subject_revision",
                "source_inventory_digest",
                "decision_model_digest",
                "files_scanned",
                "files_skipped",
                "bytes_scanned",
            },
            "subject",
            errors,
        )
        require(
            bool(
                re.fullmatch(
                    r"sha256:[a-f0-9]{64}",
                    str(subject.get("subject_revision", "")),
                )
            ),
            "subject.subject_revision must be a SHA-256 identifier",
            errors,
        )
        require(
            subject.get("decision_model_digest")
            == profile_repo.DECISION_MODEL_DIGEST,
            "subject.decision_model_digest does not match the active catalogs",
            errors,
        )
        require(
            bool(
                re.fullmatch(
                    r"sha256:[a-f0-9]{64}",
                    str(subject.get("source_inventory_digest", "")),
                )
            ),
            "subject.source_inventory_digest must be a SHA-256 identifier",
            errors,
        )
    coverage = profile.get("coverage")
    require(isinstance(coverage, dict), "coverage must be an object", errors)
    if isinstance(coverage, dict):
        exact_keys(
            coverage,
            {"status", "language_support", "entries_seen", "production_files_considered", "skip_counts", "limits"},
            "coverage",
            errors,
        )
        require(
            coverage.get("status") in {"complete", "partial"},
            "coverage.status must be complete or partial",
            errors,
        )
        skip_counts = coverage.get("skip_counts")
        require(isinstance(skip_counts, dict), "coverage.skip_counts must be an object", errors)
        if isinstance(skip_counts, dict):
            exact_keys(
                skip_counts,
                {
                    "non_production_scope",
                    "file_size_limit",
                    "total_byte_limit",
                    "stat_error",
                    "read_error",
                    "unsafe_file",
                    "binary",
                    "invalid_encoding",
                    "invalid_manifest",
                },
                "coverage.skip_counts",
                errors,
            )
            require(
                all(type(value) is int and value >= 0 for value in skip_counts.values()),
                "coverage.skip_counts values must be non-negative integers",
                errors,
            )
        require(
            coverage.get("language_support")
            in {"supported", "partial", "unsupported"},
            "coverage.language_support is invalid",
            errors,
        )

    observations = profile.get("observations")
    require(isinstance(observations, list), "observations must be an array", errors)
    observation_ids = []
    if isinstance(observations, list):
        for index, item in enumerate(observations):
            if not isinstance(item, dict):
                errors.append(f"observations[{index}] must be an object")
                continue
            exact_keys(
                item,
                {"id", "kind", "pack", "claim", "scope", "confidence", "detector", "evidence"},
                f"observations[{index}]",
                errors,
            )
            observation_ids.append(item.get("id"))
            require(
                bool(re.fullmatch(r"obs-[a-f0-9]{12}", str(item.get("id", "")))),
                f"observations[{index}] has an invalid id",
                errors,
            )
            require(
                item.get("pack") in PACKS,
                f"observations[{index}] has unknown pack",
                errors,
            )
            require(
                item.get("confidence") in {"high", "medium", "low"},
                f"observations[{index}] has invalid confidence",
                errors,
            )
            evidence = item.get("evidence")
            digest_fields = (
                "evidence_id",
                "location_id",
                "content_digest",
                "fingerprint",
                "subject_revision",
            )
            require(
                isinstance(evidence, dict)
                and isinstance(subject, dict)
                and all(
                    re.fullmatch(
                        r"sha256:[a-f0-9]{64}", str(evidence.get(field, ""))
                    )
                    for field in digest_fields
                )
                and evidence.get("subject_revision")
                == subject.get("subject_revision"),
                f"observations[{index}] has invalid or stale evidence",
                errors,
            )
            if isinstance(evidence, dict):
                exact_keys(
                    evidence,
                    {"path", "locator", *digest_fields},
                    f"observations[{index}].evidence",
                    errors,
                )
        require(
            len(observation_ids) == len(set(observation_ids)),
            "observation ids must be unique",
            errors,
        )
    observation_id_set = set(observation_ids)

    claims = profile.get("claims")
    require(isinstance(claims, list), "claims must be an array", errors)
    claim_packs: List[Any] = []
    if isinstance(claims, list):
        for index, item in enumerate(claims):
            if not isinstance(item, dict):
                errors.append(f"claims[{index}] must be an object")
                continue
            exact_keys(
                item,
                {"key", "pack", "state", "source", "inference_confidence", "evidence_refs"},
                f"claims[{index}]",
                errors,
            )
            pack = item.get("pack")
            claim_packs.append(pack)
            require(pack in CLAIMS, f"claims[{index}] has unknown pack", errors)
            if pack in CLAIMS:
                require(
                    item.get("key") == CLAIMS[pack],
                    f"claims[{index}] key does not match pack",
                    errors,
                )
            state = item.get("state")
            source = item.get("source")
            confidence = item.get("inference_confidence")
            require(
                state in {"present", "absent", "unknown", "contradicted"},
                f"claims[{index}] has invalid state",
                errors,
            )
            require(
                source in {"inferred", "declared", "combined"},
                f"claims[{index}] has invalid source",
                errors,
            )
            require(
                confidence in {"high", "medium", "low", "none"},
                f"claims[{index}] has invalid confidence",
                errors,
            )
            refs = item.get("evidence_refs")
            require(
                isinstance(refs, list),
                f"claims[{index}].evidence_refs must be an array",
                errors,
            )
            if isinstance(refs, list):
                require(
                    len(refs) == len(set(refs)),
                    f"claims[{index}] has duplicate evidence refs",
                    errors,
                )
                require(
                    set(refs) <= observation_id_set,
                    f"claims[{index}] has dangling evidence refs",
                    errors,
                )
                if state in {"present", "contradicted"} and source in {
                    "inferred",
                    "combined",
                }:
                    require(
                        bool(refs) and confidence != "none",
                        f"claims[{index}] observed state lacks evidence",
                        errors,
                    )
                for ref in refs:
                    observation = next(
                        (
                            observed
                            for observed in (
                                observations if isinstance(observations, list) else []
                            )
                            if isinstance(observed, dict) and observed.get("id") == ref
                        ),
                        None,
                    )
                    require(
                        observation is not None
                        and observation.get("pack") == pack
                        and observation.get("claim") == item.get("key"),
                        f"claims[{index}] evidence does not support its pack and key",
                        errors,
                    )
                supporting = [
                    observed
                    for observed in (
                        observations if isinstance(observations, list) else []
                    )
                    if isinstance(observed, dict) and observed.get("id") in refs
                ]
                if supporting:
                    require(
                        state in {"present", "contradicted"},
                        f"claims[{index}] suppresses observed evidence",
                        errors,
                    )
                    require(
                        confidence == profile_repo.confidence_for(supporting),
                        f"claims[{index}] confidence does not match evidence",
                        errors,
                    )
        require(
            set(claim_packs) == set(CLAIMS),
            "claims must contain every product pack exactly once",
            errors,
        )
        require(
            len(claim_packs) == len(set(claim_packs)),
            "claim packs must be unique",
            errors,
        )

    capabilities = profile.get("capabilities")
    require(isinstance(capabilities, list), "capabilities must be an array", errors)
    if isinstance(capabilities, list):
        capability_keys = []
        for index, item in enumerate(capabilities):
            if not isinstance(item, dict):
                errors.append(f"capabilities[{index}] must be an object")
                continue
            exact_keys(
                item,
                {"key", "state", "evidence_refs", "reason"},
                f"capabilities[{index}]",
                errors,
            )
            capability_keys.append(item.get("key"))
            require(
                item.get("key") in profile_repo.KNOWN_CAPABILITIES,
                f"capabilities[{index}] has an unknown key",
                errors,
            )
            require(
                item.get("state") in {"present", "not_observed", "unknown"},
                f"capabilities[{index}] has an invalid state",
                errors,
            )
            refs = item.get("evidence_refs")
            require(
                isinstance(refs, list)
                and len(refs) == len(set(refs))
                and set(refs) <= observation_id_set,
                f"capabilities[{index}] has invalid evidence refs",
                errors,
            )
            if item.get("state") == "present":
                require(bool(refs), f"capabilities[{index}] lacks evidence", errors)
            if isinstance(refs, list):
                supporting = [
                    observed
                    for observed in (
                        observations if isinstance(observations, list) else []
                    )
                    if isinstance(observed, dict) and observed.get("id") in refs
                ]
                require(
                    all(observed.get("claim") == item.get("key") for observed in supporting),
                    f"capabilities[{index}] evidence does not support its key",
                    errors,
                )
                if item.get("state") != "present":
                    require(
                        not refs,
                        f"capabilities[{index}] has evidence without a present state",
                        errors,
                    )
        require(
            set(capability_keys) == set(profile_repo.KNOWN_CAPABILITIES)
            and len(capability_keys) == len(set(capability_keys)),
            "capabilities must contain every known sub-capability exactly once",
            errors,
        )

    routing = profile.get("routing")
    require(isinstance(routing, list), "routing must be an array", errors)
    route_states: Dict[Any, Any] = {}
    if isinstance(routing, list):
        for index, item in enumerate(routing):
            if not isinstance(item, dict):
                errors.append(f"routing[{index}] must be an object")
                continue
            exact_keys(
                item,
                {"pack", "state", "reasons", "dependencies"},
                f"routing[{index}]",
                errors,
            )
            pack = item.get("pack")
            require(pack in PACKS, f"routing[{index}] has unknown pack", errors)
            require(
                pack not in route_states,
                f"routing contains duplicate pack {pack}",
                errors,
            )
            route_state = item.get("state")
            require(
                route_state in {"required", "candidate", "inactive", "unknown"},
                f"routing[{index}] has invalid state",
                errors,
            )
            dependencies = item.get("dependencies")
            require(
                isinstance(dependencies, list)
                and set(dependencies) <= set(PACKS)
                and len(dependencies) == len(set(dependencies)),
                f"routing[{index}] has invalid dependencies",
                errors,
            )
            reasons = item.get("reasons")
            require(
                isinstance(reasons, list)
                and bool(reasons)
                and all(isinstance(reason, str) and reason for reason in reasons),
                f"routing[{index}] has invalid reasons",
                errors,
            )
            route_states[pack] = route_state
        require(
            set(route_states) == set(PACKS),
            "routing must contain every pack exactly once",
            errors,
        )
        if (
            isinstance(claims, list)
            and len(claims) == len(CLAIMS)
            and all(
                isinstance(item, dict) and item.get("pack") in CLAIMS for item in claims
            )
        ):
            expected_routes = {
                item["pack"]: item["state"]
                for item in profile_repo.build_routing(claims)
            }
            require(
                route_states == expected_routes,
                "routing states do not match claim-derived routing",
                errors,
            )

    required = profile.get("required_packs")
    candidate = profile.get("candidate_packs")
    require(isinstance(required, list), "required_packs must be an array", errors)
    require(isinstance(candidate, list), "candidate_packs must be an array", errors)
    if isinstance(required, list) and isinstance(candidate, list):
        require(
            len(required) == len(set(required)),
            "required_packs contains duplicates",
            errors,
        )
        require(
            len(candidate) == len(set(candidate)),
            "candidate_packs contains duplicates",
            errors,
        )
        require(
            set(required) <= set(PACKS),
            "required_packs contains an unknown pack",
            errors,
        )
        require(
            set(candidate) <= set(PACKS),
            "candidate_packs contains an unknown pack",
            errors,
        )
        require(
            not (set(required) & set(candidate)),
            "required and candidate packs overlap",
            errors,
        )
        require(
            set(required)
            == {pack for pack, state in route_states.items() if state == "required"},
            "required_packs does not match routing",
            errors,
        )
        require(
            set(candidate)
            == {pack for pack, state in route_states.items() if state == "candidate"},
            "candidate_packs does not match routing",
            errors,
        )
    contradictions = profile.get("contradictions")
    require(isinstance(contradictions, list), "contradictions must be an array", errors)
    if isinstance(contradictions, list):
        for index, item in enumerate(contradictions):
            require(isinstance(item, dict), f"contradictions[{index}] must be an object", errors)
            if isinstance(item, dict):
                exact_keys(
                    item,
                    {"claim", "declared", "observed", "message"},
                    f"contradictions[{index}]",
                    errors,
                )
    limitations = profile.get("limitations")
    require(
        isinstance(limitations, list)
        and all(isinstance(item, str) and item for item in limitations),
        "limitations must be a string array",
        errors,
    )
    return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a ContextSec security profile."
    )
    parser.add_argument("profile", type=Path)
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.profile.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        print("error: unable to read profile: " + str(exc), file=sys.stderr)
        return 2
    if not isinstance(payload, dict):
        print("error: profile root must be an object", file=sys.stderr)
        return 2
    errors = validate(payload)
    if errors:
        for error in errors:
            print("error: " + error, file=sys.stderr)
        return 1
    print("Profile is semantically valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
