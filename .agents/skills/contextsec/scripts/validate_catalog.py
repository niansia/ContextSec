#!/usr/bin/env python3
"""Validate ContextSec pack and composition catalogs with the standard library."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, List, Mapping, Optional, Sequence

SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = SKILL_ROOT / "references" / "catalog.json"
DEFAULT_COMPOSITIONS = SKILL_ROOT / "references" / "compositions" / "catalog.json"
VERSION = "0.3.0"
SEVERITIES = {"critical", "high", "medium", "low", "info"}
PACK_ID = re.compile(r"^[a-z][a-z0-9-]+$")
CONTROL_ID = re.compile(r"^[A-Z]+(?:-[A-Z]+)+-[0-9]{3}$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9_.-]+$")


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate_catalogs(
    catalog: Mapping[str, Any],
    compositions: Mapping[str, Any],
    skill_root: Optional[Path] = None,
) -> List[str]:
    errors: List[str] = []
    if catalog.get("schema_version") != VERSION:
        errors.append("catalog schema_version must be " + VERSION)
    capabilities = catalog.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or len(capabilities) != len(set(capabilities))
        or not all(isinstance(item, str) and CAPABILITY.fullmatch(item) for item in capabilities)
    ):
        errors.append("catalog capabilities must be a unique capability array")
        known_capabilities = set()
    else:
        known_capabilities = set(capabilities)
    packs = catalog.get("packs")
    if not isinstance(packs, list) or not packs:
        return errors + ["catalog packs must be a non-empty array"]
    pack_ids = [item.get("id") for item in packs if isinstance(item, dict)]
    if len(pack_ids) != len(packs) or any(
        not isinstance(item, str) or not PACK_ID.fullmatch(item) for item in pack_ids
    ):
        errors.append("pack ids must be valid strings")
    if len(pack_ids) != len(set(pack_ids)):
        errors.append("pack ids must be unique")
    if not pack_ids or pack_ids[0] != "foundation":
        errors.append("foundation must be the first pack")
    known_packs = set(pack_ids)
    control_ids = set()
    for pack_index, pack in enumerate(packs):
        if not isinstance(pack, dict):
            continue
        prefix = f"packs[{pack_index}]"
        claim = pack.get("claim")
        if pack.get("id") == "foundation":
            if claim is not None:
                errors.append(prefix + ".claim must be null")
        elif not _nonempty(claim) or not CAPABILITY.fullmatch(str(claim)):
            errors.append(prefix + ".claim is invalid")
        dependencies = pack.get("dependencies")
        if (
            not isinstance(dependencies, list)
            or len(dependencies) != len(set(dependencies))
            or not set(dependencies) <= known_packs
            or pack.get("id") in set(dependencies)
        ):
            errors.append(prefix + ".dependencies is invalid")
        reference = pack.get("reference")
        if not _nonempty(reference):
            errors.append(prefix + ".reference is invalid")
        elif skill_root is not None and not (skill_root / "references" / reference).is_file():
            errors.append(prefix + ".reference does not exist")
        if not _nonempty(pack.get("activation")):
            errors.append(prefix + ".activation is invalid")
        controls = pack.get("controls")
        if not isinstance(controls, list) or not controls:
            errors.append(prefix + ".controls must be a non-empty array")
            continue
        for control_index, control in enumerate(controls):
            control_prefix = prefix + f".controls[{control_index}]"
            if not isinstance(control, dict):
                errors.append(control_prefix + " must be an object")
                continue
            control_id = control.get("id")
            if not isinstance(control_id, str) or not CONTROL_ID.fullmatch(control_id):
                errors.append(control_prefix + ".id is invalid")
            elif control_id in control_ids:
                errors.append("duplicate control id: " + control_id)
            else:
                control_ids.add(control_id)
            if control.get("severity") not in SEVERITIES:
                errors.append(control_prefix + ".severity is invalid")
            if type(control.get("blocking")) is not bool:
                errors.append(control_prefix + ".blocking must be a JSON boolean")
            for field in ("invariant", "required_verification"):
                if not _nonempty(control.get(field)):
                    errors.append(control_prefix + "." + field + " is invalid")
            condition = control.get("applies_when")
            if condition is not None:
                if not isinstance(condition, dict) or set(condition) not in ({"all"}, {"any"}):
                    errors.append(control_prefix + ".applies_when must contain exactly one operator")
                else:
                    keys = next(iter(condition.values()))
                    if (
                        not isinstance(keys, list)
                        or not keys
                        or len(keys) != len(set(keys))
                        or not all(isinstance(key, str) and CAPABILITY.fullmatch(key) for key in keys)
                    ):
                        errors.append(control_prefix + ".applies_when has invalid capabilities")
                    elif not set(keys) <= known_capabilities:
                        errors.append(control_prefix + ".applies_when references an unknown capability")

    if compositions.get("schema_version") != VERSION:
        errors.append("composition schema_version must be " + VERSION)
    rules = compositions.get("rules")
    if not isinstance(rules, list):
        return errors + ["composition rules must be an array"]
    composition_ids = set()
    for index, rule in enumerate(rules):
        prefix = f"rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(prefix + " must be an object")
            continue
        control_id = rule.get("id")
        if not isinstance(control_id, str) or not CONTROL_ID.fullmatch(control_id):
            errors.append(prefix + ".id is invalid")
        elif control_id in composition_ids or control_id in control_ids:
            errors.append("duplicate composition/control id: " + control_id)
        else:
            composition_ids.add(control_id)
        requires = rule.get("requires")
        if (
            not isinstance(requires, list)
            or len(requires) < 2
            or len(requires) != len(set(requires))
            or not set(requires) <= known_packs
        ):
            errors.append(prefix + ".requires is invalid")
        if not isinstance(rule.get("intersection_capability"), str) or not CAPABILITY.fullmatch(
            rule.get("intersection_capability", "")
        ):
            errors.append(prefix + ".intersection_capability is invalid")
        elif rule["intersection_capability"] not in known_capabilities:
            errors.append(prefix + ".intersection_capability is unknown")
        if rule.get("severity") not in SEVERITIES:
            errors.append(prefix + ".severity is invalid")
        if type(rule.get("blocking")) is not bool:
            errors.append(prefix + ".blocking must be a JSON boolean")
        for field in ("invariant", "required_verification"):
            if not _nonempty(rule.get(field)):
                errors.append(prefix + "." + field + " is invalid")
    return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate ContextSec decision catalogs.")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--compositions", type=Path, default=DEFAULT_COMPOSITIONS)
    args = parser.parse_args(argv)
    try:
        catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
        compositions = json.loads(args.compositions.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        print("error: unable to read catalogs: " + str(exc), file=sys.stderr)
        return 2
    if not isinstance(catalog, dict) or not isinstance(compositions, dict):
        print("error: catalog roots must be objects", file=sys.stderr)
        return 2
    errors = validate_catalogs(catalog, compositions, SKILL_ROOT)
    if errors:
        for error in errors:
            print("error: " + error, file=sys.stderr)
        return 1
    print("Catalogs are semantically valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
