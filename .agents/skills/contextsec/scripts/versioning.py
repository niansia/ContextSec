"""Load ContextSec release and artifact versions from their canonical files."""

from __future__ import annotations

import re
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
TOOL_VERSION_PATH = SKILL_ROOT / "VERSION"
SCHEMA_VERSION_PATH = SKILL_ROOT / "references" / "SCHEMA_VERSION"
SEMVER = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:[-+][0-9A-Za-z.-]+)?$"
)


def _load_version(path: Path, label: str) -> str:
    try:
        value = path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise RuntimeError("Unable to read ContextSec " + label + " version.") from exc
    if not SEMVER.fullmatch(value):
        raise RuntimeError("ContextSec " + label + " version is not valid SemVer.")
    return value


TOOL_VERSION = _load_version(TOOL_VERSION_PATH, "tool")
SCHEMA_VERSION = _load_version(SCHEMA_VERSION_PATH, "schema")
