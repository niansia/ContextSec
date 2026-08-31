#!/usr/bin/env python3
"""Create a deterministic, allowlisted ContextSec source release archive."""

from __future__ import annotations

import argparse
import os
import sys
import zipfile
from pathlib import Path
from typing import Iterable, Optional, Sequence

import safe_io
import versioning

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
ALLOWLIST = (
    ".agents/skills/contextsec",
    ".github",
    "benchmarks",
    "ci",
    "docs",
    "examples",
    "incidents",
    "tests",
    ".gitignore",
    ".gitattributes",
    "CHANGELOG.md",
    "CITATION.cff",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "RELEASING.md",
    "SECURITY.md",
    "SOURCES.md",
)
EXCLUDED_PARTS = {
    ".git",
    ".contextsec",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "dist",
    "tmp",
}
DEFAULT_OUTPUT = (
    REPOSITORY_ROOT / "dist" / ("contextsec-v" + versioning.TOOL_VERSION + ".zip")
)


def is_link_like(path: Path) -> bool:
    return path.is_symlink() or bool(
        getattr(os.lstat(str(path)), "st_file_attributes", 0)
        & getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def release_files(root: Path = REPOSITORY_ROOT) -> Iterable[Path]:
    found = set()
    for relative in ALLOWLIST:
        target = root / relative
        if not target.exists():
            raise ValueError("Release allowlist target is missing: " + relative)
        candidates = [target] if target.is_file() else sorted(target.rglob("*"))
        for candidate in candidates:
            if not candidate.is_file() or is_link_like(candidate):
                continue
            resolved = candidate.resolve(strict=True)
            try:
                relative_path = resolved.relative_to(root.resolve(strict=True))
            except ValueError as exc:
                raise ValueError("Release file escaped repository root.") from exc
            if set(relative_path.parts) & EXCLUDED_PARTS:
                continue
            found.add(relative_path)
    yield from sorted(found, key=lambda path: path.as_posix())


def build_archive(output: Path, root: Path = REPOSITORY_ROOT) -> int:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    files = list(release_files(root))
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for relative in files:
            data = safe_io.read_regular_file_at(root, relative)
            info = zipfile.ZipInfo(relative.as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.create_version = 20
            info.extract_version = 20
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return len(files)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Build a clean deterministic ContextSec release zip.")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
    )
    parser.add_argument("--list", action="store_true", help="List allowlisted files without writing an archive.")
    args = parser.parse_args(argv)
    try:
        if args.list:
            for path in release_files():
                print(path.as_posix())
            return 0
        count = build_archive(args.output)
        print("Created " + str(args.output) + " with " + str(count) + " files.")
        return 0
    except (OSError, ValueError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
