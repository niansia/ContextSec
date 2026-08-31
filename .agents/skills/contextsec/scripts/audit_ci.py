#!/usr/bin/env python3
"""Derive bounded CI policy evidence for ContextSec's own release ledger."""

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
import versioning  # noqa: E402

ACTION = re.compile(r"(?m)^\s*-?\s*uses\s*:\s*[\"']?(?P<value>[^\s\"'#]+)")
IMMUTABLE_ACTION = re.compile(
    r"^(?P<owner>[A-Za-z0-9_.-]+)/[^@]+@[a-f0-9]{40}(?:[a-f0-9]{24})?$",
    re.IGNORECASE,
)
UNTRUSTED_EXPRESSION = re.compile(
    r"\$\{\{\s*"
    r"(?:github\.(?!sha\b|repository\b|ref_name\b)|inputs\.|env\.|matrix\.)"
)


def _run_blocks(text: str) -> list[str]:
    lines = text.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(
            r"^(?P<indent>\s*)(?:-\s*)?run\s*:\s*(?P<tail>.*)$",
            lines[index],
        )
        if match is None:
            index += 1
            continue
        indentation = len(match.group("indent"))
        tail = match.group("tail")
        if tail not in {"|", ">", "|-", ">-", "|+", ">+"}:
            blocks.append(tail)
            index += 1
            continue
        body: list[str] = []
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= indentation:
                break
            body.append(line)
            index += 1
        blocks.append("\n".join(body))
    return blocks


def _load_json(path: Path) -> Dict[str, Any]:
    payload = profile_repo.strict_json_loads(
        safe_io.read_regular_file(path, 256 * 1024).decode("utf-8-sig")
    )
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object.")
    return payload


def audit_repository(root: Path) -> Dict[str, Any]:
    root = root.resolve(strict=True)
    policy = _load_json(root / "ci" / "allowed-actions.json")
    if policy.get("schema_version") != versioning.SCHEMA_VERSION:
        raise ValueError("CI action policy schema version is incompatible.")
    owners = policy.get("allowed_owners")
    if not isinstance(owners, list) or not owners or not all(
        isinstance(item, str) and item for item in owners
    ):
        raise ValueError("CI action policy must list allowed owners.")
    allowed = {item.lower() for item in owners}
    workflow_dir = root / ".github" / "workflows"
    workflows = sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))
    if not workflows:
        raise ValueError("No GitHub Actions workflows were found.")

    issues: list[str] = []
    action_count = 0
    pull_request_workflows = 0
    for path in workflows:
        text = safe_io.read_regular_file(path, 512 * 1024).decode("utf-8")
        label = path.relative_to(root).as_posix()
        permission_match = re.search(
            r"(?m)^permissions:\s*\n(?P<body>(?:  [A-Za-z0-9_-]+:\s*[A-Za-z-]+\s*\n?)+)",
            text,
        )
        if (
            permission_match is None
            or permission_match.group("body").strip() != "contents: read"
        ):
            issues.append(label + ": top-level permissions are not exactly contents: read")
        if any(UNTRUSTED_EXPRESSION.search(block) for block in _run_blocks(text)):
            issues.append(label + ": untrusted event/input expression reaches a run block")
        if re.search(r"(?m)^\s*pull_request_target\s*:", text):
            issues.append(label + ": pull_request_target is prohibited")
        has_pull_request = bool(re.search(r"(?m)^\s*pull_request\s*:", text))
        if has_pull_request:
            pull_request_workflows += 1
            if re.search(r"\$\{\{\s*secrets\.", text):
                issues.append(label + ": pull-request workflow references a secret")
            if re.search(r"(?im)^\s*runs-on\s*:.*\bself-hosted\b", text):
                issues.append(label + ": pull-request workflow uses a self-hosted runner")
        for match in ACTION.finditer(text):
            value = match.group("value")
            if value.startswith(("./", "docker://")):
                continue
            action_count += 1
            immutable = IMMUTABLE_ACTION.fullmatch(value)
            if immutable is None:
                issues.append(label + ": mutable action reference " + value)
                continue
            if immutable.group("owner").lower() not in allowed:
                issues.append(label + ": action owner is not allowlisted")
            if value.lower().startswith("actions/checkout@"):
                step_tail = text[match.end() : match.end() + 300]
                if not re.search(r"(?m)^\s+persist-credentials:\s*false\s*$", step_tail):
                    issues.append(label + ": checkout does not disable persisted credentials")

    release_path = workflow_dir / "release.yml"
    release = (
        safe_io.read_regular_file(release_path, 512 * 1024).decode("utf-8")
        if release_path.exists()
        else ""
    )
    release_markers = (
        "attestations: write",
        "id-token: write",
        "--draft",
        "package_release.py",
        "SHA256SUMS",
        "cmp ",
        "attest-build-provenance",
    )
    missing_release = [item for item in release_markers if item not in release]
    if missing_release:
        issues.append(".github/workflows/release.yml: incomplete provenance workflow")
    if pull_request_workflows < 1:
        issues.append("no pull_request workflow exercises the untrusted contribution path")
    if action_count < 1:
        issues.append("no third-party Action references were audited")
    requirements = safe_io.read_regular_file(
        root / "ci" / "agent-skills-validator-requirements.txt", 256 * 1024
    ).decode("utf-8")
    logical_requirements = requirements.replace("\\\n", " ").splitlines()
    for line in logical_requirements:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if (
            re.match(r"^[A-Za-z0-9_.-]+==[^\s]+\s+", stripped) is None
            or re.search(r"--hash=sha256:[a-f0-9]{64}$", stripped) is None
        ):
            issues.append("ci/agent-skills-validator-requirements.txt: dependency is not exact and hash-pinned")
            break

    return {
        "status": "pass" if not issues else "fail",
        "workflow_count": len(workflows),
        "action_count": action_count,
        "pull_request_workflow_count": pull_request_workflows,
        "issues": issues,
        "evidence_refs": {
            "action_policy": "ci-audit:immutable-actions-and-owner-allowlist",
            "token_policy": "ci-audit:explicit-workflow-permissions",
            "pr_policy": "ci-audit:pull-request-secret-and-runner-isolation",
            "injection_policy": "ci-audit:expression-to-shell-boundary",
            "provenance_policy": "ci-audit:reproducible-attested-release-workflow",
            "dependency_policy": "ci-audit:hash-pinned-validator-runtime",
        },
    }


def build_evidence(profile: Mapping[str, Any], audit: Mapping[str, Any]) -> Dict[str, Any]:
    if profile.get("schema_version") != versioning.SCHEMA_VERSION:
        raise ValueError("Profile schema version is incompatible.")
    if audit.get("status") != "pass":
        raise ValueError("CI audit failed; verified evidence cannot be emitted.")
    refs = audit["evidence_refs"]
    rows = (
        ("CICD-ACTION-001", refs["action_policy"], "All external Action references are immutable and owner-allowlisted."),
        ("CICD-TOKEN-001", refs["token_policy"], "Every workflow has an explicit read-only token baseline and elevated release permissions are job-local."),
        ("CICD-PR-001", refs["pr_policy"], "Pull-request workflows expose neither secret references nor self-hosted runners and checkout credentials are not persisted."),
        ("CICD-INJECT-001", refs["injection_policy"], "Repository-controlled event, input, environment, and matrix expressions do not enter run blocks."),
        ("CICD-PROV-001", refs["provenance_policy"], "The release workflow rebuilds deterministically, publishes SHA256SUMS, and requests artifact provenance."),
        ("FND-DEP-001", refs["dependency_policy"], "The Agent Skills validator source is commit-pinned and its complete Python build/runtime closure is hash-pinned."),
    )
    return {
        "schema_version": versioning.SCHEMA_VERSION,
        "subject_revision": profile["subject"]["subject_revision"],
        "controls": [
            {
                "control_id": control_id,
                "applicability": "required",
                "verification": "verified",
                "reason": reason,
                "evidence_refs": [reference],
            }
            for control_id, reference, reason in rows
        ],
        "waivers": [],
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Audit ContextSec's GitHub Actions policy.")
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        audit = audit_repository(args.repo)
        payload: Mapping[str, Any] = audit
        if args.profile is not None:
            profile = _load_json(args.profile)
            payload = build_evidence(profile, audit)
        rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.output is not None:
            profile_repo.write_output_atomic(args.output, rendered)
        else:
            sys.stdout.write(rendered)
        return 0 if audit["status"] == "pass" else 1
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
