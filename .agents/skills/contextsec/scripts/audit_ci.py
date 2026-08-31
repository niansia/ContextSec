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
    r"^(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@[a-f0-9]{40}(?:[a-f0-9]{24})?$",
    re.IGNORECASE,
)
IMMUTABLE_DOCKER = re.compile(
    r"^docker://(?P<image>[A-Za-z0-9._:/-]+)@sha256:[a-f0-9]{64}$",
    re.IGNORECASE,
)
IMMUTABLE_CONTAINER = re.compile(
    r"^(?P<image>[A-Za-z0-9._:/-]+)@sha256:[a-f0-9]{64}$",
    re.IGNORECASE,
)
CONTAINER_IMAGE = re.compile(
    r"(?m)^\s+image\s*:\s*[\"']?(?P<value>[^\s\"'#]+)"
)
UNTRUSTED_EXPRESSION = re.compile(
    r"\$\{\{\s*"
    r"(?:github\.(?!sha\b|repository\b)|inputs\.|env\.|matrix\.)"
)
DYNAMIC_SHELL_CODE = re.compile(
    r"(?im)(?:^|[;&|]\s*)"
    r"(?:eval\b|iex\b|invoke-expression\b|(?:ba|z|k)?sh\s+-c\b|"
    r"(?:pwsh|powershell)(?:\.exe)?\s+-(?:command|encodedcommand)\b)"
)
ENV_ASSIGNMENT = re.compile(
    r"(?m)^[ \t]*(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]*:[ \t]*(?P<value>[^\n]+?)[ \t]*$"
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
    return safe_io.read_json_object_bounded(path, 256 * 1024, "CI policy")


def _tainted_environment(text: str) -> set[str]:
    return {
        match.group("name")
        for match in ENV_ASSIGNMENT.finditer(text)
        if UNTRUSTED_EXPRESSION.search(match.group("value"))
    }


def _uses_environment(block: str, name: str) -> bool:
    escaped = re.escape(name)
    return bool(
        re.search(r"\$" + escaped + r"\b|\$\{" + escaped + r"\}", block)
        or re.search(r"\$env:" + escaped + r"\b", block, re.IGNORECASE)
        or re.search(r"%" + escaped + r"%", block, re.IGNORECASE)
    )


def _permission_mapping(lines: Sequence[str], index: int, indent: int) -> Dict[str, str]:
    if lines[index].strip() != "permissions:":
        raise ValueError("Permissions must use an explicit YAML mapping.")
    result: Dict[str, str] = {}
    cursor = index + 1
    while cursor < len(lines):
        line = lines[cursor]
        stripped = line.strip()
        current_indent = len(line) - len(line.lstrip())
        if stripped and current_indent <= indent:
            break
        if not stripped or stripped.startswith("#"):
            cursor += 1
            continue
        match = re.fullmatch(
            r"\s{" + str(indent + 2) + r"}(?P<scope>[A-Za-z0-9_-]+):\s*(?P<level>read|write|none)\s*",
            line,
        )
        if match is None or match.group("scope") in result:
            raise ValueError("Permissions contain an unsupported or duplicate entry.")
        result[match.group("scope")] = match.group("level")
        cursor += 1
    if not result:
        raise ValueError("Permissions mappings must not be empty.")
    return result


def _effective_job_permissions(text: str) -> tuple[Dict[str, str], Dict[str, Dict[str, str]]]:
    """Parse the constrained permissions/jobs subset used by repository workflows."""

    lines = text.splitlines()
    top_indices = [
        index
        for index, line in enumerate(lines)
        if line == "permissions:"
    ]
    if len(top_indices) != 1:
        raise ValueError("Workflow must declare exactly one top-level permissions mapping.")
    top = _permission_mapping(lines, top_indices[0], 0)
    jobs_indices = [index for index, line in enumerate(lines) if line == "jobs:"]
    if len(jobs_indices) != 1:
        raise ValueError("Workflow must declare exactly one jobs mapping.")
    jobs: Dict[str, Dict[str, str]] = {}
    index = jobs_indices[0] + 1
    while index < len(lines):
        line = lines[index]
        if line.strip() and len(line) - len(line.lstrip()) == 0:
            break
        match = re.fullmatch(r"  (?P<job>[A-Za-z0-9_-]+):\s*", line)
        if match is None:
            index += 1
            continue
        job = match.group("job")
        if job in jobs:
            raise ValueError("Workflow job ids must be unique.")
        end = index + 1
        permission_indices = []
        while end < len(lines):
            candidate = lines[end]
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= 2:
                break
            if candidate == "    permissions:":
                permission_indices.append(end)
            end += 1
        if len(permission_indices) > 1:
            raise ValueError("Job must not declare multiple permissions mappings.")
        jobs[job] = (
            _permission_mapping(lines, permission_indices[0], 4)
            if permission_indices
            else dict(top)
        )
        index = end
    if not jobs:
        raise ValueError("Workflow must contain at least one statically named job.")
    return top, jobs


def audit_repository(root: Path) -> Dict[str, Any]:
    root = root.resolve(strict=True)
    policy = _load_json(root / "ci" / "allowed-actions.json")
    if policy.get("schema_version") != versioning.SCHEMA_VERSION:
        raise ValueError("CI action policy schema version is incompatible.")
    if set(policy) != {"schema_version", "allowed_actions", "allowed_docker_images", "policy"}:
        raise ValueError("CI action policy has unexpected or missing fields.")
    actions = policy.get("allowed_actions")
    if not isinstance(actions, list) or not actions or not all(
        isinstance(item, str)
        and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", item)
        for item in actions
    ):
        raise ValueError("CI action policy must list exact action repositories.")
    if len(actions) != len({item.lower() for item in actions}):
        raise ValueError("CI action policy has duplicate actions.")
    allowed = {item.lower() for item in actions}
    images = policy.get("allowed_docker_images")
    if (
        not isinstance(images, list)
        or len(images) != len({str(item).lower() for item in images})
        or not all(
            isinstance(item, str)
            and re.fullmatch(r"[A-Za-z0-9._:/-]+", item)
            for item in images
        )
    ):
        raise ValueError("CI action policy has invalid allowed_docker_images.")
    allowed_images = {item.lower() for item in images}
    permission_policy = _load_json(root / "ci" / "workflow-permissions.json")
    if (
        permission_policy.get("schema_version") != versioning.SCHEMA_VERSION
        or set(permission_policy) != {"schema_version", "policy", "workflows"}
        or not isinstance(permission_policy.get("workflows"), dict)
    ):
        raise ValueError("CI workflow permission policy is invalid.")
    workflow_dir = root / ".github" / "workflows"
    workflows = sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))
    if not workflows:
        raise ValueError("No GitHub Actions workflows were found.")

    issues: list[str] = []
    workflow_labels = {path.relative_to(root).as_posix() for path in workflows}
    permission_labels = set(permission_policy["workflows"])
    if permission_labels != workflow_labels:
        issues.append("ci/workflow-permissions.json: workflow inventory is not exact")
    action_count = 0
    image_count = 0
    pull_request_workflows = 0
    for path in workflows:
        text = safe_io.read_regular_file_at(
            root, path.relative_to(root), 512 * 1024
        ).decode("utf-8")
        label = path.relative_to(root).as_posix()
        try:
            top_permissions, effective_permissions = _effective_job_permissions(text)
        except ValueError as exc:
            issues.append(label + ": " + str(exc))
            top_permissions, effective_permissions = {}, {}
        if top_permissions != {"contents": "read"}:
            issues.append(label + ": top-level permissions are not exactly contents: read")
        expected_permissions = permission_policy["workflows"].get(label)
        if not isinstance(expected_permissions, dict):
            issues.append(label + ": workflow is missing from the exact permission policy")
        elif effective_permissions != expected_permissions:
            issues.append(label + ": effective job permissions differ from the reviewed policy")
        run_blocks = _run_blocks(text)
        tainted_environment = _tainted_environment(text)
        if any(UNTRUSTED_EXPRESSION.search(block) for block in run_blocks):
            issues.append(label + ": untrusted event/input expression reaches a run block")
        if any(DYNAMIC_SHELL_CODE.search(block) for block in run_blocks):
            issues.append(label + ": dynamic shell-code execution is prohibited")
        tainted_uses = sorted(
            name
            for name in tainted_environment
            if any(_uses_environment(block, name) for block in run_blocks)
        )
        if tainted_uses:
            issues.append(
                label
                + ": expression-tainted environment reaches a run block: "
                + ", ".join(tainted_uses)
            )
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
            if value.startswith("./"):
                continue
            if value.startswith("docker://"):
                image_count += 1
                immutable_image = IMMUTABLE_DOCKER.fullmatch(value)
                if immutable_image is None:
                    issues.append(label + ": mutable docker action reference " + value)
                elif immutable_image.group("image").lower() not in allowed_images:
                    issues.append(label + ": docker action image is not exactly allowlisted")
                continue
            action_count += 1
            immutable = IMMUTABLE_ACTION.fullmatch(value)
            if immutable is None:
                issues.append(label + ": mutable action reference " + value)
                continue
            if immutable.group("action").lower() not in allowed:
                issues.append(label + ": action is not exactly allowlisted")
            if value.lower().startswith("actions/checkout@"):
                step_tail = text[match.end() : match.end() + 300]
                if not re.search(r"(?m)^\s+persist-credentials:\s*false\s*$", step_tail):
                    issues.append(label + ": checkout does not disable persisted credentials")
        docker_action_values = {
            match.group("value")
            for match in ACTION.finditer(text)
            if match.group("value").startswith("docker://")
        }
        for match in CONTAINER_IMAGE.finditer(text):
            value = match.group("value")
            if value in docker_action_values:
                continue
            image_count += 1
            immutable_image = IMMUTABLE_CONTAINER.fullmatch(value)
            if immutable_image is None:
                issues.append(label + ": mutable container or service image " + value)
            elif immutable_image.group("image").lower() not in allowed_images:
                issues.append(label + ": container or service image is not exactly allowlisted")

    release_path = workflow_dir / "release.yml"
    release = (
        safe_io.read_regular_file_at(
            root, release_path.relative_to(root), 512 * 1024
        ).decode("utf-8")
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
        "gh_2.98.0_linux_amd64.tar.gz",
        "3b8ac6b30336802fc1a858d7c084e11cdf24ac1a761ca90b68022d7d729208de",
        "gh release verify",
        "repos/$GITHUB_REPOSITORY/immutable-releases",
        'test "$tag_commit" = "$(git rev-parse refs/remotes/origin/main)"',
        "release-evidence.json",
        "environment: release",
        "timeout-minutes: 30",
        "--signer-workflow",
        "--source-digest",
        "--deny-self-hosted-runners",
    )
    missing_release = [item for item in release_markers if item not in release]
    if missing_release:
        issues.append(".github/workflows/release.yml: incomplete provenance workflow")
    proof = safe_io.read_regular_file_at(
        root, Path(".github/workflows/security-proof.yml"), 512 * 1024
    ).decode("utf-8")
    proof_markers = (
        "workflow_call:",
        "test:",
        "evidence:",
        "agent-skill-spec:",
        "real-repositories:",
        "needs: [test, evidence, agent-skill-spec, real-repositories]",
    )
    if any(item not in proof for item in proof_markers):
        issues.append(".github/workflows/security-proof.yml: full proof contract is incomplete")
    topology_markers = (
        "uses: ./.github/workflows/security-proof.yml",
        "needs: proof",
        'test "$tag_commit" = "$(git rev-parse refs/remotes/origin/main)"',
        "gh attestation verify",
    )
    if any(item not in release for item in topology_markers):
        issues.append(".github/workflows/release.yml: release is not gated by the reusable full proof")
    if pull_request_workflows < 1:
        issues.append("no pull_request workflow exercises the untrusted contribution path")
    if action_count < 1:
        issues.append("no third-party Action references were audited")
    requirements = safe_io.read_regular_file_at(
        root, Path("ci") / "agent-skills-validator-requirements.txt", 256 * 1024
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
        "image_count": image_count,
        "pull_request_workflow_count": pull_request_workflows,
        "issues": issues,
        "evidence_refs": {
            "action_policy": "ci-audit:immutable-actions-images-and-exact-allowlist",
            "token_policy": "ci-audit:exact-effective-job-permissions",
            "pr_policy": "ci-audit:pull-request-secret-and-runner-isolation",
            "injection_policy": "ci-audit:expression-env-and-shell-code-boundary",
            "provenance_policy": "ci-audit:configured-release-verification-boundary",
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
        ("CICD-ACTION-001", "verified", refs["action_policy"], "All external Actions and Docker action/container/service images are immutable and exactly allowlisted."),
        ("CICD-TOKEN-001", "verified", refs["token_policy"], "Every job's effective token permissions exactly match the reviewed least-privilege policy."),
        ("CICD-PR-001", "verified", refs["pr_policy"], "Pull-request workflows expose neither secret references nor self-hosted runners and checkout credentials are not persisted."),
        ("CICD-INJECT-001", "verified", refs["injection_policy"], "Supported workflow shell flows contain no direct untrusted expressions, expression-tainted environment use, or dynamic shell-code execution sinks."),
        ("CICD-PROV-001", "unknown", refs["provenance_policy"], "The workflow configures reproducible archives, checksums, attestations, and draft-asset re-verification; successful provenance for a particular release is established only by that release run."),
        ("FND-DEP-001", "verified", refs["dependency_policy"], "The Agent Skills validator source is commit-pinned and its complete Python build/runtime closure is hash-pinned."),
    )
    return {
        "schema_version": versioning.SCHEMA_VERSION,
        "subject_revision": profile["subject"]["subject_revision"],
        "controls": [
            {
                "control_id": control_id,
                "applicability": "required",
                "verification": verification,
                "reason": reason,
                "evidence_refs": [reference],
            }
            for control_id, verification, reference, reason in rows
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
