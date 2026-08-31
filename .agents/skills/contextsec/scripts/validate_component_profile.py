#!/usr/bin/env python3
"""Validate a ContextSec component-profile artifact."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

import component_profile
import safe_io


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a component-scoped Profile.")
    parser.add_argument("profile", type=Path)
    args = parser.parse_args(argv)
    try:
        payload = safe_io.read_json_object_bounded(
            args.profile, 128 * 1024 * 1024, "Component Profile"
        )
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    errors = component_profile.validate(payload)
    if errors:
        for error in errors:
            print("error: " + error, file=sys.stderr)
        return 1
    print("Component Profile is semantically valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
