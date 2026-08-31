#!/usr/bin/env python3
"""Create deterministic, signed-release-ready evidence for one exact source commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

import check_controls
import profile_repo
import verification_coverage
import versioning


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def build(
    archive: Path,
    *,
    tag: str,
    source_commit: str,
    main_commit: str,
    workflow_run: str,
    proof_result: str,
    immutable_releases_enabled: bool,
) -> Dict[str, Any]:
    archive = archive.resolve(strict=True)
    if tag != "v" + versioning.TOOL_VERSION:
        raise ValueError("Release evidence tag does not match the tool version.")
    if re.fullmatch(r"[a-f0-9]{40}", source_commit) is None or source_commit != main_commit:
        raise ValueError("Release evidence requires the exact reviewed main commit.")
    if not workflow_run.startswith("https://github.com/"):
        raise ValueError("Release workflow run must be a canonical GitHub URL.")
    if proof_result != "success":
        raise ValueError("Full security proof did not succeed.")
    if immutable_releases_enabled is not True:
        raise ValueError("Immutable Releases must be verified before evidence creation.")
    coverage = verification_coverage.build()
    return {
        "$schema": "https://raw.githubusercontent.com/niansia/ContextSec/v0.4.0/.agents/skills/contextsec/references/release-evidence.schema.json",
        "schema_version": versioning.SCHEMA_VERSION,
        "artifact_type": "release-evidence",
        "release": {
            "tag": tag,
            "source_commit": source_commit,
            "main_commit": main_commit,
            "workflow_run": workflow_run,
            "immutable_releases_precondition": "verified",
            "full_security_proof": proof_result,
        },
        "tool": {
            "tool_version": versioning.TOOL_VERSION,
            "detector_version": versioning.DETECTOR_VERSION,
            "checker_version": versioning.CHECKER_VERSION,
            "schema_version": versioning.SCHEMA_VERSION,
            "detector_model_digest": profile_repo.DETECTOR_MODEL_DIGEST,
            "routing_model_digest": profile_repo.ROUTING_MODEL_DIGEST,
            "checker_model_digest": check_controls.CHECKER_MODEL_DIGEST,
            "catalog_digest": profile_repo.CATALOG_DIGEST,
            "composition_digest": profile_repo.COMPOSITION_DIGEST,
            "support_matrix_digest": profile_repo.SUPPORT_MATRIX_DIGEST,
        },
        "artifact": {
            "name": archive.name,
            "size": archive.stat().st_size,
            "sha256": file_digest(archive),
        },
        "verification_coverage": {
            "digest": profile_repo.canonical_digest(coverage),
            "summary": coverage["summary"],
        },
        "claim_boundary": "This evidence is trustworthy only when its file digest is covered by a verified GitHub artifact attestation and the final immutable Release attestation binds the same assets.",
    }


def validate(payload: Mapping[str, Any]) -> list[str]:
    errors = []
    if set(payload) != {
        "$schema",
        "schema_version",
        "artifact_type",
        "release",
        "tool",
        "artifact",
        "verification_coverage",
        "claim_boundary",
    }:
        errors.append("release evidence has unexpected or missing fields")
        return errors
    if payload.get("schema_version") != versioning.SCHEMA_VERSION:
        errors.append("release evidence schema version is incompatible")
    if payload.get("$schema") != "https://raw.githubusercontent.com/niansia/ContextSec/v0.4.0/.agents/skills/contextsec/references/release-evidence.schema.json":
        errors.append("release evidence schema identity is incompatible")
    if payload.get("artifact_type") != "release-evidence":
        errors.append("release evidence artifact_type is invalid")
    release = payload.get("release")
    if (
        not isinstance(release, dict)
        or set(release) != {
            "tag",
            "source_commit",
            "main_commit",
            "workflow_run",
            "immutable_releases_precondition",
            "full_security_proof",
        }
        or release.get("tag") != "v" + versioning.TOOL_VERSION
        or re.fullmatch(r"[a-f0-9]{40}", str(release.get("source_commit", ""))) is None
        or release.get("source_commit") != release.get("main_commit")
        or not str(release.get("workflow_run", "")).startswith("https://github.com/")
        or release.get("immutable_releases_precondition") != "verified"
        or release.get("full_security_proof") != "success"
    ):
        errors.append("release evidence is not bound to exact main")
    tool = payload.get("tool")
    expected_tool = {
        "tool_version": versioning.TOOL_VERSION,
        "detector_version": versioning.DETECTOR_VERSION,
        "checker_version": versioning.CHECKER_VERSION,
        "schema_version": versioning.SCHEMA_VERSION,
        "detector_model_digest": profile_repo.DETECTOR_MODEL_DIGEST,
        "routing_model_digest": profile_repo.ROUTING_MODEL_DIGEST,
        "checker_model_digest": check_controls.CHECKER_MODEL_DIGEST,
        "catalog_digest": profile_repo.CATALOG_DIGEST,
        "composition_digest": profile_repo.COMPOSITION_DIGEST,
        "support_matrix_digest": profile_repo.SUPPORT_MATRIX_DIGEST,
    }
    if tool != expected_tool:
        errors.append("release evidence tool/model identity is inconsistent")
    artifact = payload.get("artifact")
    if (
        not isinstance(artifact, dict)
        or set(artifact) != {"name", "size", "sha256"}
        or artifact.get("name") != "contextsec-v" + versioning.TOOL_VERSION + ".zip"
        or type(artifact.get("size")) is not int
        or artifact.get("size", 0) < 1
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", str(artifact.get("sha256", "")))
    ):
        errors.append("release evidence artifact identity is invalid")
    coverage = verification_coverage.build()
    expected_coverage = {
        "digest": profile_repo.canonical_digest(coverage),
        "summary": coverage["summary"],
    }
    if payload.get("verification_coverage") != expected_coverage:
        errors.append("release evidence verification coverage is inconsistent")
    return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Create release evidence for signing.")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--main-commit", required=True)
    parser.add_argument("--workflow-run", required=True)
    parser.add_argument("--proof-result", required=True)
    parser.add_argument("--immutable-releases-enabled", choices=("true",), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = build(
            args.archive,
            tag=args.tag,
            source_commit=args.source_commit,
            main_commit=args.main_commit,
            workflow_run=args.workflow_run,
            proof_result=args.proof_result,
            immutable_releases_enabled=args.immutable_releases_enabled == "true",
        )
        errors = validate(payload)
        if errors:
            raise ValueError(errors[0])
        profile_repo.write_output_atomic(
            args.output,
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        )
        return 0
    except (OSError, ValueError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
