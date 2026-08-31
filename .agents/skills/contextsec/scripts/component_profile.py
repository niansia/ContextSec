#!/usr/bin/env python3
"""Build and validate component-scoped profiles for explicit monorepo models."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Mapping, Optional, Sequence

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import profile_repo  # noqa: E402
import safe_io  # noqa: E402
import source_provenance  # noqa: E402
import validate_profile  # noqa: E402
import versioning  # noqa: E402

MODEL_SCHEMA_URL = "https://raw.githubusercontent.com/niansia/ContextSec/v0.4.0/.agents/skills/contextsec/references/component-model.schema.json"
PROFILE_SCHEMA_URL = "https://raw.githubusercontent.com/niansia/ContextSec/v0.4.0/.agents/skills/contextsec/references/component-profile.schema.json"
IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{0,63}")
CAPABILITY = re.compile(r"[a-z][a-z0-9_.-]{0,127}")


def _exact(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise ValueError(label + " has unexpected or missing fields.")


def _normalized_root(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("Component roots must be non-empty POSIX relative paths.")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("Component roots must be normalized repository-relative paths.")
    return pure.as_posix()


def _normalize_model(payload: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Component model root must be an object.")
    _exact(payload, {"$schema", "schema_version", "components", "flows"}, "component model")
    if payload.get("$schema") != MODEL_SCHEMA_URL:
        raise ValueError("Component model schema identity is incompatible.")
    if payload.get("schema_version") != versioning.SCHEMA_VERSION:
        raise ValueError("Component model schema version is incompatible.")
    components = payload.get("components")
    flows = payload.get("flows")
    if not isinstance(components, list) or not components:
        raise ValueError("Component model requires at least one component.")
    if not isinstance(flows, list):
        raise ValueError("Component model flows must be an array.")
    normalized_components = []
    identifiers: set[str] = set()
    roots: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("Component entries must be objects.")
        _exact(component, {"id", "root", "kind", "depends_on"}, "component")
        identifier = component.get("id")
        if not isinstance(identifier, str) or IDENTIFIER.fullmatch(identifier) is None:
            raise ValueError("Component id is invalid.")
        root = _normalized_root(component.get("root"))
        kind = component.get("kind")
        dependencies = component.get("depends_on")
        if identifier in identifiers or root in roots:
            raise ValueError("Component ids and roots must be unique.")
        if not isinstance(kind, str) or IDENTIFIER.fullmatch(kind) is None:
            raise ValueError("Component kind is invalid.")
        if (
            not isinstance(dependencies, list)
            or len(dependencies) != len(set(dependencies))
            or not all(isinstance(item, str) and IDENTIFIER.fullmatch(item) for item in dependencies)
        ):
            raise ValueError("Component dependencies are invalid.")
        identifiers.add(identifier)
        roots.add(root)
        normalized_components.append(
            {"id": identifier, "root": root, "kind": kind, "depends_on": list(dependencies)}
        )
    for left in roots:
        for right in roots:
            if left != right and PurePosixPath(left) in PurePosixPath(right).parents:
                raise ValueError("Component roots must not overlap.")
    for component in normalized_components:
        if component["id"] in component["depends_on"] or not set(component["depends_on"]) <= identifiers:
            raise ValueError("Component dependencies must reference other declared components.")
    visiting: set[str] = set()
    visited: set[str] = set()
    by_id = {item["id"]: item for item in normalized_components}

    def visit(identifier: str) -> None:
        if identifier in visiting:
            raise ValueError("Component dependency graph must be acyclic.")
        if identifier in visited:
            return
        visiting.add(identifier)
        for dependency in by_id[identifier]["depends_on"]:
            visit(dependency)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in sorted(identifiers):
        visit(identifier)
    normalized_flows = []
    flow_ids: set[str] = set()
    for flow in flows:
        if not isinstance(flow, dict):
            raise ValueError("Component flows must be objects.")
        _exact(flow, {"id", "from", "to", "capabilities", "evidence_refs"}, "component flow")
        flow_id = flow.get("id")
        source = flow.get("from")
        destination = flow.get("to")
        capabilities = flow.get("capabilities")
        evidence_refs = flow.get("evidence_refs")
        if not isinstance(flow_id, str) or IDENTIFIER.fullmatch(flow_id) is None or flow_id in flow_ids:
            raise ValueError("Component flow id is invalid or duplicated.")
        if source not in identifiers or destination not in identifiers or source == destination:
            raise ValueError("Component flow endpoints are invalid.")
        if (
            not isinstance(capabilities, list)
            or not capabilities
            or len(capabilities) != len(set(capabilities))
            or not all(isinstance(item, str) and CAPABILITY.fullmatch(item) for item in capabilities)
        ):
            raise ValueError("Component flow capabilities are invalid.")
        if (
            not isinstance(evidence_refs, list)
            or not evidence_refs
            or len(evidence_refs) != len(set(evidence_refs))
            or not all(isinstance(item, str) and item for item in evidence_refs)
        ):
            raise ValueError("Component flow evidence_refs must be non-empty and unique.")
        flow_ids.add(flow_id)
        normalized_flows.append(
            {
                "id": flow_id,
                "from": source,
                "to": destination,
                "capabilities": sorted(capabilities),
                "evidence_refs": sorted(evidence_refs),
            }
        )
    return {
        "$schema": MODEL_SCHEMA_URL,
        "schema_version": versioning.SCHEMA_VERSION,
        "components": sorted(normalized_components, key=lambda item: item["id"]),
        "flows": sorted(normalized_flows, key=lambda item: item["id"]),
    }


def load_model(repository: Path, manifest: Path) -> Dict[str, Any]:
    repository = repository.resolve(strict=True)
    manifest_relative = Path(manifest)
    if manifest_relative.is_absolute():
        try:
            manifest_relative = manifest_relative.resolve(strict=True).relative_to(repository)
        except (OSError, ValueError):
            raise ValueError("Component model must stay inside the repository root.")
    raw = safe_io.read_regular_file_at(repository, manifest_relative, 2 * 1024 * 1024)
    payload = profile_repo.strict_json_loads(raw.decode("utf-8"))
    return _normalize_model(payload)


def build(
    repository: Path,
    manifest: Path,
    *,
    path_privacy: str = "heuristic",
) -> Dict[str, Any]:
    repository = repository.resolve(strict=True)
    model = load_model(repository, manifest)
    provenance = source_provenance.read(repository)
    component_results = []
    for component in model["components"]:
        raw_root = component["root"]
        component_root = repository.joinpath(*PurePosixPath(raw_root).parts)
        current = repository
        for part in PurePosixPath(raw_root).parts:
            current = current / part
            if not current.exists() or not current.is_dir() or profile_repo.is_link_like(current):
                raise ValueError("Component root is missing or link-like: " + raw_root)
        profile = profile_repo.profile_repository(
            component_root,
            path_privacy=path_privacy,
            provenance_root=repository,
            component={"id": component["id"], "root": raw_root},
        )
        component_results.append(
            {
                "id": component["id"],
                "root": profile_repo.redact_path(raw_root, path_privacy),
                "root_identity": profile_repo.path_identity(raw_root),
                "kind": component["kind"],
                "depends_on": component["depends_on"],
                "profile_artifact_digest": profile_repo.canonical_digest(profile),
                "profile": profile,
            }
        )
    model_digest = profile_repo.canonical_digest(model)
    subject_revision = profile_repo.canonical_digest(
        {
            "source_provenance": provenance,
            "component_model_digest": model_digest,
            "components": [
                {
                    "id": item["id"],
                    "root_identity": item["root_identity"],
                    "profile_artifact_digest": item["profile_artifact_digest"],
                }
                for item in component_results
            ],
        }
    )
    return {
        "$schema": PROFILE_SCHEMA_URL,
        "schema_version": versioning.SCHEMA_VERSION,
        "artifact_type": "component-profile",
        "artifact_options": {"path_privacy": path_privacy},
        "subject": {
            "repository": profile_repo.redact_path(repository.name, path_privacy),
            "source_provenance": provenance,
            "component_model_digest": model_digest,
            "subject_revision": subject_revision,
        },
        "component_model": model,
        "components": component_results,
        "flows": model["flows"],
        "limitations": [
            "Component boundaries and cross-component flows are explicit reviewed declarations; ContextSec does not infer deployment topology from directory names.",
            "Each component Profile is independently content-, model-, path-, and Git-provenance-bound.",
        ],
    }


def validate(payload: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    expected = {
        "$schema",
        "schema_version",
        "artifact_type",
        "artifact_options",
        "subject",
        "component_model",
        "components",
        "flows",
        "limitations",
    }
    if set(payload) != expected:
        errors.append("component profile has unexpected or missing fields")
        return errors
    if payload.get("$schema") != PROFILE_SCHEMA_URL:
        errors.append("component profile schema identity is incompatible")
    if payload.get("schema_version") != versioning.SCHEMA_VERSION:
        errors.append("component profile schema version is incompatible")
    if payload.get("artifact_type") != "component-profile":
        errors.append("component profile artifact_type is invalid")
    options = payload.get("artifact_options")
    if (
        not isinstance(options, dict)
        or set(options) != {"path_privacy"}
        or options.get("path_privacy") not in profile_repo.PATH_PRIVACY_MODES
    ):
        errors.append("component profile artifact_options are invalid")
        return errors
    model = payload.get("component_model")
    components = payload.get("components")
    subject = payload.get("subject")
    if not isinstance(model, dict) or not isinstance(components, list) or not components:
        errors.append("component profile model/components are invalid")
        return errors
    try:
        normalized_model = _normalize_model(model)
    except ValueError as exc:
        errors.append("component profile model is invalid: " + str(exc))
        return errors
    if model != normalized_model:
        errors.append("component profile model is not canonical")
    if not isinstance(subject, dict) or set(subject) != {
        "repository",
        "source_provenance",
        "component_model_digest",
        "subject_revision",
    }:
        errors.append("component profile subject is invalid")
        return errors
    model_digest = profile_repo.canonical_digest(model)
    if subject.get("component_model_digest") != model_digest:
        errors.append("component_model_digest is inconsistent")
    normalized = []
    model_components = {
        component["id"]: component for component in normalized_model["components"]
    }
    component_ids: set[str] = set()
    for index, component in enumerate(components):
        if not isinstance(component, dict) or set(component) != {
            "id",
            "root",
            "root_identity",
            "kind",
            "depends_on",
            "profile_artifact_digest",
            "profile",
        }:
            errors.append(f"components[{index}] has an invalid shape")
            continue
        identifier = component.get("id")
        if identifier in component_ids or identifier not in model_components:
            errors.append(f"components[{index}].id is duplicate or not declared")
            continue
        component_ids.add(identifier)
        declaration = model_components[identifier]
        expected_root_identity = profile_repo.path_identity(declaration["root"])
        expected_display_root = profile_repo.redact_path(
            declaration["root"], options["path_privacy"]
        )
        if (
            component.get("root_identity") != expected_root_identity
            or component.get("root") != expected_display_root
            or component.get("kind") != declaration["kind"]
            or component.get("depends_on") != declaration["depends_on"]
        ):
            errors.append(f"components[{index}] differs from its model declaration")
        profile = component.get("profile")
        if not isinstance(profile, dict):
            errors.append(f"components[{index}].profile must be an object")
            continue
        profile_errors = validate_profile.validate(profile)
        if profile_errors:
            errors.append(f"components[{index}].profile is invalid: " + profile_errors[0])
        digest = profile_repo.canonical_digest(profile)
        if component.get("profile_artifact_digest") != digest:
            errors.append(f"components[{index}].profile_artifact_digest is inconsistent")
        binding = profile.get("subject", {}).get("component")
        if not isinstance(binding, dict) or binding.get("id") != component.get("id") or binding.get("path_identity") != component.get("root_identity"):
            errors.append(f"components[{index}] is not bound to its Profile")
        if profile.get("subject", {}).get("source_provenance") != subject.get("source_provenance"):
            errors.append(f"components[{index}] source provenance differs from the aggregate")
        normalized.append(
            {
                "id": component.get("id"),
                "root_identity": component.get("root_identity"),
                "profile_artifact_digest": digest,
            }
        )
    if component_ids != set(model_components):
        errors.append("component profile does not contain every declared component exactly once")
    if [component.get("id") for component in components] != sorted(model_components):
        errors.append("component profile components are not in canonical order")
    expected_subject = profile_repo.canonical_digest(
        {
            "source_provenance": subject.get("source_provenance"),
            "component_model_digest": model_digest,
            "components": normalized,
        }
    )
    if subject.get("subject_revision") != expected_subject:
        errors.append("component profile subject_revision is inconsistent")
    if payload.get("flows") != model.get("flows"):
        errors.append("component profile flows do not match the model")
    return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Build a component-scoped monorepo Profile.")
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--components", type=Path, default=Path("contextsec.components.json"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--path-privacy", choices=tuple(sorted(profile_repo.PATH_PRIVACY_MODES)), default="heuristic")
    args = parser.parse_args(argv)
    try:
        payload = build(args.repo, args.components, path_privacy=args.path_privacy)
        errors = validate(payload)
        if errors:
            raise ValueError(errors[0])
        rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.output:
            profile_repo.write_output_atomic(args.output, rendered)
        else:
            print(rendered, end="")
        return 0
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
