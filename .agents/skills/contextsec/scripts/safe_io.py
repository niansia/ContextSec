"""Race-resistant, bounded reads for untrusted repository files."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Optional


class UnsafeFileError(OSError):
    """The path was not a stable regular file throughout the read."""


class FileSizeLimitError(OSError):
    """The file exceeded the caller's byte limit."""

    def __init__(self, size: int, limit: int) -> None:
        super().__init__("File exceeds the bounded read limit.")
        self.size = size
        self.limit = limit


def _has_reparse_attribute(stat_result: Any) -> bool:
    attributes = getattr(stat_result, "st_file_attributes", 0) or 0
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _identity(stat_result: os.stat_result) -> tuple[int, int]:
    return (int(stat_result.st_dev), int(stat_result.st_ino))


def _version(stat_result: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(stat_result.st_dev),
        int(stat_result.st_ino),
        int(stat_result.st_size),
        int(getattr(stat_result, "st_mtime_ns", int(stat_result.st_mtime * 1e9))),
        int(getattr(stat_result, "st_ctime_ns", int(stat_result.st_ctime * 1e9))),
    )


def read_regular_file(path: Path, max_bytes: Optional[int] = None) -> bytes:
    """Read one stable regular file without following a link-like replacement.

    POSIX uses ``O_NOFOLLOW`` when available. On every platform, the lstat identity
    is compared with the opened descriptor and descriptor metadata is checked again
    after the read. A concurrent replacement or in-place mutation fails closed.
    """

    pre = os.lstat(str(path))
    if not stat.S_ISREG(pre.st_mode) or _has_reparse_attribute(pre):
        raise UnsafeFileError("Refusing a symlink, reparse point, or non-regular file.")
    if max_bytes is not None and pre.st_size > max_bytes:
        raise FileSizeLimitError(int(pre.st_size), max_bytes)

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(path), flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _has_reparse_attribute(opened)
            or _identity(pre) != _identity(opened)
        ):
            raise UnsafeFileError("File identity changed before it was opened.")
        chunks: list[bytes] = []
        total = 0
        while True:
            request = 64 * 1024
            if max_bytes is not None:
                request = min(request, max_bytes - total + 1)
            chunk = os.read(descriptor, request)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise FileSizeLimitError(total, max_bytes)
        finished = os.fstat(descriptor)
        if _version(opened) != _version(finished):
            raise UnsafeFileError("File changed while it was being read.")
        return b"".join(chunks)
    finally:
        os.close(descriptor)
