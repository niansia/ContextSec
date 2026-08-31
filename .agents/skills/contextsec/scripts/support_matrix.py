"""Load and validate the machine-readable ContextSec support contract."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable

import versioning
import safe_io

MATRIX_PATH = Path(__file__).resolve().parents[1] / "references" / "support-matrix.json"


def _string_list(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
        or len(value) != len(set(value))
    ):
        raise RuntimeError("ContextSec support matrix has invalid " + label + ".")
    return list(value)


def load_support_matrix(path: Path = MATRIX_PATH) -> Dict[str, Any]:
    try:
        payload = safe_io.read_json_object_bounded(
            path, 2 * 1024 * 1024, "Support matrix"
        )
    except (OSError, ValueError, RecursionError) as exc:
        raise RuntimeError("Unable to load ContextSec support matrix.") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "$schema",
        "$id",
        "schema_version",
        "profile",
        "checker",
        "coverage_semantics",
    }:
        raise RuntimeError("ContextSec support matrix has an invalid top-level shape.")
    if payload.get("schema_version") != versioning.SCHEMA_VERSION:
        raise RuntimeError("ContextSec support matrix schema is incompatible.")
    profile = payload.get("profile")
    checker = payload.get("checker")
    coverage = payload.get("coverage_semantics")
    if not isinstance(profile, dict) or set(profile) != {
        "supported_manifests",
        "unsupported_manifests",
        "supported_suffixes",
        "unsupported_suffixes",
        "frameworks",
    }:
        raise RuntimeError("ContextSec profiler support matrix is invalid.")
    if not isinstance(checker, dict) or set(checker) != {
        "supported_suffixes",
        "unsupported_suffixes",
        "frameworks",
        "control_shapes",
    }:
        raise RuntimeError("ContextSec checker support matrix is invalid.")
    for key, value in profile.items():
        _string_list(value, "profile." + key)
    for key, value in checker.items():
        _string_list(value, "checker." + key)
    if (
        not isinstance(coverage, dict)
        or set(coverage) != {
            "traversal",
            "language_support",
            "checker_support",
            "match_enumeration",
        }
        or coverage.get("traversal") != ["complete", "partial"]
        or coverage.get("language_support")
        != ["supported", "partial", "unsupported"]
        or coverage.get("checker_support") != "partial"
        or coverage.get("match_enumeration") != "mixed_first_only"
    ):
        raise RuntimeError("ContextSec coverage semantics are invalid.")
    return payload


SUPPORT_MATRIX = load_support_matrix()


def values(section: str, key: str) -> set[str]:
    items: Iterable[str] = SUPPORT_MATRIX[section][key]
    return set(items)
