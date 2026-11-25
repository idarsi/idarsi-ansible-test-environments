"""Bounded, existing-only reads for guest target validation."""

import json
import os
from pathlib import Path
import stat

from .state import RunError


def canonical(path: Path) -> Path:
    """Require an absolute spelling without symlink or dot-component aliases."""
    if not path.is_absolute() or str(path.resolve(strict=True)) != str(path):
        raise RunError("Noncanonical existing path")
    return path


def directory(path: Path, *, private=False) -> Path:
    canonical(path)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
        or info.st_mode & 0o022 or (private and stat.S_IMODE(info.st_mode) != 0o700)
    ):
        raise RunError("Unsafe existing directory")
    return path


def read_file(path: Path, limit: int, *, contents=True) -> bytes:
    """Read private authoritative helper state or keys; require exactly 0600."""
    return _read_regular(path, limit, modes=(0o600,), contents=contents)


def read_molecule_state(path: Path, limit: int) -> bytes:
    """Molecule flags are not ownership authority; allow safe ordinary umasks."""
    return _read_regular(path, limit, modes=(0o600, 0o640, 0o644))


def _read_regular(path: Path, limit: int, *, modes: tuple, contents=True) -> bytes:
    canonical(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) not in modes or info.st_nlink != 1
            or info.st_size > limit
        ):
            raise RunError("Unsafe existing regular file")
        if not contents:
            return b""
        value = stream.read(limit + 1)
        if len(value) > limit:
            raise RunError("Existing file exceeds limit")
        return value


def strict_json(value):
    """Decode one UTF-8 JSON document, rejecting duplicate keys and constants."""
    if isinstance(value, bytes):
        value = value.decode("utf-8")

    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise RunError("Duplicate JSON key")
            result[key] = item
        return result

    return json.loads(
        value, object_pairs_hook=pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(RunError("Nonfinite JSON")),
    )
