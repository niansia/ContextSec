"""Read bounded Git provenance without invoking target code or the network."""

from __future__ import annotations

import configparser
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

import safe_io

FULL_COMMIT = re.compile(r"[a-f0-9]{40}")


def _has_safe_git_marker(root: Path) -> bool:
    marker = root / ".git"
    try:
        metadata = os.lstat(marker)
    except OSError:
        return False
    if stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    ):
        return False
    return stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)


def _git_command(root: Path, arguments: list[str], timeout: int = 20) -> Optional[bytes]:
    """Run one fixed Git built-in without a shell, hooks, locks, or network."""

    with tempfile.TemporaryDirectory(prefix="contextsec-git-hooks-") as empty_hooks:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith("GIT_")
        }
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        try:
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.hooksPath=" + empty_hooks,
                    "-C",
                    str(root),
                    *arguments,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
    return result.stdout if result.returncode == 0 else None


def _read_optional(root: Path, relative: Path, limit: int) -> Optional[str]:
    try:
        return safe_io.read_regular_file_at(root, relative, limit).decode("utf-8")
    except (OSError, UnicodeDecodeError, safe_io.UnsafeFileError):
        return None


def _head_commit(root: Path) -> Optional[str]:
    head = _read_optional(root, Path(".git/HEAD"), 4096)
    if head is None:
        if not _has_safe_git_marker(root):
            return None
        output = _git_command(root, ["rev-parse", "--verify", "HEAD"])
        if output is None:
            return None
        value = output.decode("ascii", errors="ignore").strip()
        return value if FULL_COMMIT.fullmatch(value) else None
    value = head.strip()
    if FULL_COMMIT.fullmatch(value):
        return value
    if not value.startswith("ref: "):
        return None
    ref = value.removeprefix("ref: ").strip()
    if not re.fullmatch(r"refs/[A-Za-z0-9._/-]+", ref) or ".." in ref.split("/"):
        return None
    loose = _read_optional(root, Path(".git") / Path(ref), 4096)
    if loose is not None and FULL_COMMIT.fullmatch(loose.strip()):
        return loose.strip()
    packed = _read_optional(root, Path(".git/packed-refs"), 2 * 1024 * 1024)
    if packed is None:
        return None
    for line in packed.splitlines():
        if not line or line.startswith(("#", "^")):
            continue
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1] == ref and FULL_COMMIT.fullmatch(parts[0]):
            return parts[0]
    return None


def normalize_repository_url(value: str) -> Optional[str]:
    value = value.strip()
    patterns = (
        r"https://github\.com/(?P<slug>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$",
        r"git@github\.com:(?P<slug>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$",
        r"ssh://git@github\.com/(?P<slug>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, value, re.IGNORECASE)
        if match:
            return "https://github.com/" + match.group("slug").removesuffix(".git")
    return None


def _origin_repository(root: Path) -> Optional[str]:
    raw = _read_optional(root, Path(".git/config"), 256 * 1024)
    if raw is None:
        if not _has_safe_git_marker(root):
            return None
        output = _git_command(root, ["remote", "get-url", "origin"])
        if output is None:
            return None
        return normalize_repository_url(output.decode("utf-8", errors="replace"))
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(raw)
    except configparser.Error:
        return None
    section = 'remote "origin"'
    if not parser.has_option(section, "url"):
        return None
    return normalize_repository_url(parser.get(section, "url"))


def _worktree_state(root: Path) -> str:
    """Use a fixed, non-shell Git query with hooks and fsmonitor disabled."""
    output = _git_command(
        root,
        ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=no"],
    )
    if output is None:
        return "unavailable"
    return "clean" if not output.strip() else "dirty"


def read(root: Path) -> Dict[str, Any]:
    """Return verified only when both immutable commit and canonical origin exist."""

    commit = _head_commit(root)
    repository = _origin_repository(root)
    worktree = _worktree_state(root) if commit is not None else "unavailable"
    if commit is not None and repository is not None and worktree == "clean":
        return {
            "status": "verified",
            "vcs": "git",
            "repository": repository,
            "commit": commit,
            "worktree": worktree,
        }
    return {
        "status": "dirty" if worktree == "dirty" else "unavailable",
        "vcs": "git" if commit is not None else None,
        "repository": repository,
        "commit": commit,
        "worktree": worktree,
    }
