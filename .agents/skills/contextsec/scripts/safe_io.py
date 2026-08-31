"""Bounded, race-resistant readers for untrusted files and repository paths."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple


class UnsafeFileError(OSError):
    """The path was not a stable regular file inside the selected root."""


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


def _open_flags(*, directory: bool = False) -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def _read_descriptor(
    descriptor: int,
    opened: os.stat_result,
    max_bytes: Optional[int],
) -> bytes:
    if max_bytes is not None and opened.st_size > max_bytes:
        raise FileSizeLimitError(int(opened.st_size), max_bytes)
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


def read_regular_file(path: Path, max_bytes: Optional[int] = None) -> bytes:
    """Read one stable regular file without following a final link component."""

    pre = os.lstat(str(path))
    if not stat.S_ISREG(pre.st_mode) or _has_reparse_attribute(pre):
        raise UnsafeFileError("Refusing a symlink, reparse point, or non-regular file.")
    if max_bytes is not None and pre.st_size > max_bytes:
        raise FileSizeLimitError(int(pre.st_size), max_bytes)

    descriptor = os.open(str(path), _open_flags())
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _has_reparse_attribute(opened)
            or _identity(pre) != _identity(opened)
        ):
            raise UnsafeFileError("File identity changed before it was opened.")
        return _read_descriptor(descriptor, opened, max_bytes)
    finally:
        os.close(descriptor)


def _relative_parts(relative: Path | str) -> Tuple[str, ...]:
    candidate = Path(relative)
    if candidate.is_absolute() or candidate.drive:
        raise UnsafeFileError("Root-bound reads require a relative path.")
    parts = tuple(candidate.parts)
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise UnsafeFileError("Root-bound path contains an unsafe component.")
    return parts


def _read_regular_file_at_posix(
    root: Path,
    parts: Sequence[str],
    max_bytes: Optional[int],
) -> bytes:
    descriptors: list[int] = []
    try:
        current = os.open(str(root), _open_flags(directory=True))
        descriptors.append(current)
        if not stat.S_ISDIR(os.fstat(current).st_mode):
            raise UnsafeFileError("Selected repository root is not a directory.")
        for component in parts[:-1]:
            pre = os.stat(component, dir_fd=current, follow_symlinks=False)
            if not stat.S_ISDIR(pre.st_mode) or _has_reparse_attribute(pre):
                raise UnsafeFileError("Refusing a link-like parent directory.")
            child = os.open(component, _open_flags(directory=True), dir_fd=current)
            opened = os.fstat(child)
            if not stat.S_ISDIR(opened.st_mode) or _identity(pre) != _identity(opened):
                os.close(child)
                raise UnsafeFileError("Parent directory identity changed during traversal.")
            descriptors.append(child)
            current = child

        pre = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        if not stat.S_ISREG(pre.st_mode) or _has_reparse_attribute(pre):
            raise UnsafeFileError("Refusing a symlink or non-regular repository file.")
        descriptor = os.open(parts[-1], _open_flags(), dir_fd=current)
        descriptors.append(descriptor)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity(pre) != _identity(opened):
            raise UnsafeFileError("Repository file identity changed before open.")
        return _read_descriptor(descriptor, opened, max_bytes)
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _normalize_windows_handle_path(value: str) -> str:
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.normcase(os.path.normpath(value))


def _windows_final_path_from_fd(descriptor: int) -> str:
    import ctypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_name = kernel32.GetFinalPathNameByHandleW
    get_name.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
    get_name.restype = ctypes.c_uint32
    handle = msvcrt.get_osfhandle(descriptor)
    needed = get_name(handle, None, 0, 0)
    if needed == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(needed + 1)
    written = get_name(handle, buffer, len(buffer), 0)
    if written == 0 or written >= len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    return _normalize_windows_handle_path(buffer.value)


def _windows_root_final_path(root: Path) -> str:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    create_file.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    get_name = kernel32.GetFinalPathNameByHandleW
    get_name.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
    get_name.restype = ctypes.c_uint32
    share_all = 0x00000001 | 0x00000002 | 0x00000004
    handle = create_file(str(root), 0, share_all, None, 3, 0x02000000 | 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = get_name(handle, None, 0, 0)
        if needed == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_unicode_buffer(needed + 1)
        written = get_name(handle, buffer, len(buffer), 0)
        if written == 0 or written >= len(buffer):
            raise ctypes.WinError(ctypes.get_last_error())
        return _normalize_windows_handle_path(buffer.value)
    finally:
        close_handle(handle)


def _assert_windows_parent_components(root: Path, parts: Sequence[str]) -> None:
    current = root
    for component in parts[:-1]:
        current = current / component
        metadata = os.lstat(str(current))
        if not stat.S_ISDIR(metadata.st_mode) or _has_reparse_attribute(metadata):
            raise UnsafeFileError("Refusing a link-like parent directory.")


def _read_regular_file_at_windows(
    root: Path,
    parts: Sequence[str],
    max_bytes: Optional[int],
) -> bytes:
    root = root.absolute()
    root_metadata = os.lstat(str(root))
    if not stat.S_ISDIR(root_metadata.st_mode) or _has_reparse_attribute(root_metadata):
        raise UnsafeFileError("Selected repository root is link-like or not a directory.")
    _assert_windows_parent_components(root, parts)
    root_final = _windows_root_final_path(root)
    target = root.joinpath(*parts)
    pre = os.lstat(str(target))
    if not stat.S_ISREG(pre.st_mode) or _has_reparse_attribute(pre):
        raise UnsafeFileError("Refusing a symlink or non-regular repository file.")
    descriptor = os.open(str(target), _open_flags())
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity(pre) != _identity(opened):
            raise UnsafeFileError("Repository file identity changed before open.")
        target_final = _windows_final_path_from_fd(descriptor)
        try:
            contained = os.path.commonpath((root_final, target_final)) == root_final
        except ValueError:
            contained = False
        if not contained:
            raise UnsafeFileError("Resolved repository file escaped the selected root.")
        _assert_windows_parent_components(root, parts)
        return _read_descriptor(descriptor, opened, max_bytes)
    finally:
        os.close(descriptor)


def read_regular_file_at(
    root: Path,
    relative: Path | str,
    max_bytes: Optional[int] = None,
) -> bytes:
    """Read a stable repository file while anchoring pathname resolution to root."""

    parts = _relative_parts(relative)
    if os.name == "nt":
        return _read_regular_file_at_windows(root, parts, max_bytes)
    return _read_regular_file_at_posix(root, parts, max_bytes)


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def strict_json_loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys)


def read_json_object_bounded(path: Path, max_bytes: int, label: str) -> Dict[str, Any]:
    """Read one untrusted UTF-8 JSON object through the shared safe boundary."""

    try:
        raw = read_regular_file(path, max_bytes)
    except FileSizeLimitError as exc:
        raise ValueError(label + " exceeds the " + str(max_bytes) + " byte limit.") from exc
    try:
        payload = strict_json_loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(label + " must be strict UTF-8 JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError(label + " root must be an object.")
    return payload
