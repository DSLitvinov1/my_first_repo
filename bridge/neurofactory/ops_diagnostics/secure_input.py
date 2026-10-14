"""Fail-closed bounded local JSON input for OFFLINE OPS CLIs only.

No network, subprocesses or writes. Unix uses component-by-component
directory descriptor traversal plus O_NOFOLLOW; Windows rejects known reparse
points and verifies file identity before/after read. Trusted operator-owned
parent directories remain required on Windows.
"""
import os
import stat
from pathlib import Path


class SafeInputError(ValueError):
    pass


def _reject(condition, message="Refused unsafe local input"):
    if condition:
        raise SafeInputError(message)


def _read_regular(fd, maximum):
    info = os.fstat(fd)
    _reject(not stat.S_ISREG(info.st_mode), "Input is not a regular file")
    _reject(info.st_size > maximum, "Input exceeds size limit")
    data = os.read(fd, maximum + 1)
    _reject(len(data) > maximum, "Input exceeds size limit")
    after = os.fstat(fd)
    _reject(not stat.S_ISREG(after.st_mode) or
            (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino) or
            after.st_size != info.st_size, "Input changed while being read")
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise SafeInputError("Input is not valid UTF-8") from exc


def _posix_read(path, maximum):
    # Pinned directory handles prevent symlink replacement during open.
    absolute = path.absolute()
    parts = absolute.parts
    _reject(not parts or not absolute.is_absolute())
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current = os.open(parts[0], dir_flags)
    try:
        for piece in parts[1:-1]:
            _reject(piece in (".", "..", ""))
            following = os.open(piece, dir_flags, dir_fd=current)
            os.close(current)
            current = following
        filename = parts[-1]
        _reject(filename in (".", "..", ""))
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(filename, flags, dir_fd=current)
        try:
            return _read_regular(fd, maximum)
        finally:
            os.close(fd)
    finally:
        os.close(current)


def _windows_read(path, maximum):
    # An untrusted actor capable of racing same-UID directory replacement
    # remains OUTSIDE this offline CLI trust boundary on Windows.
    absolute = path.absolute()
    current = Path(absolute.anchor)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for piece in absolute.parts[1:]:
        _reject(piece in (".", "..", ""))
        current = current / piece
        metadata = current.lstat()
        _reject(current.is_symlink() or bool(getattr(metadata, "st_file_attributes", 0) & reparse))
    initial = absolute.lstat()
    _reject(not stat.S_ISREG(initial.st_mode))
    fd = os.open(absolute, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        opened = os.fstat(fd)
        _reject((initial.st_dev, initial.st_ino) != (opened.st_dev, opened.st_ino),
                "Input changed during open")
        return _read_regular(fd, maximum)
    finally:
        os.close(fd)


def read_snapshot(name, maximum=500000):
    if not isinstance(name, (str, Path)) or type(maximum) is not int or maximum < 1:
        raise SafeInputError("Invalid local input parameters")
    path = Path(name)
    _reject(".." in path.parts or not path.name, "Unsafe input path")
    try:
        if os.name == "posix":
            return _posix_read(path, maximum)
        if os.name == "nt":
            return _windows_read(path, maximum)
        raise SafeInputError("Platform lacks reviewed safe file input")
    except SafeInputError:
        raise
    except (OSError, ValueError, OverflowError) as exc:
        raise SafeInputError("Local input missing, inaccessible or unsafe") from exc
