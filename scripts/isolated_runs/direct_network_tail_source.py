"""Bounded byte-only reader for one reviewed producing-source subset.

The root argument locates bytes, not authority. Nothing is imported or executed
from it, and no snapshot configuration, manifest or cached receipt is consulted.
"""

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

from .state import RunError

PROFILE = "direct-empty-checkpoint-network-tail-v1"
SUBSET_DIGEST = "4f4af9b019ca41ea238b3c581ed8e6b80ab89eba97a27a556189fa9a790642c0"
FILES = {
    "scripts/isolated_runs/__init__.py": (64, "7308d629c6c2fc7d8e6f659016414ac293dc7949a5d1cad275411f4816bc4599"),
    "scripts/isolated_runs/admission.py": (8839, "43b7e40ed91b6df8d09574e6f0d13791ecdd58cad447248686c46cf723fc5d95"),
    "scripts/isolated_runs/backends.py": (28556, "4d5db9b6bdec79547781b8471b0ce38ccc5bb7b721f5ebabe23bcca690cadcf8"),
    "scripts/isolated_runs/cli.py": (20222, "ee73fdc87557bb74b802dc7c597b1cda34723bebcd29d4f6dd899fd9b4d90903"),
    "scripts/isolated_runs/context.py": (18764, "a919c40457343cac5a89425fdb6ed4573971add808a12290975ef43ed58e3fe4"),
    "scripts/isolated_runs/discovery.py": (4302, "3bf99489c00421b24e05d3747d9550b74c81a8cdd991e48f48594d3f05f5f6de"),
    "scripts/isolated_runs/guest_control.py": (16380, "1819e9607868b9a6f346aad3fdcf476a949ecb827bb0052505dfdd872e59176d"),
    "scripts/isolated_runs/network_references.py": (8807, "33b490bfe68e9a55be856c04b9f8414a83baf6724f2e167ec955c6c9c60edf7a"),
    "scripts/isolated_runs/processes.py": (3898, "dba3cf8fb5f93d4661e9a0daa5a8d9fcac090b6e9217b47a4d2ca76194c4311b"),
    "scripts/isolated_runs/state.py": (8142, "5284217cedbdf544a8d313f8e53bd8cb1ff7eea3702c1d51d7a54f074f389ffc"),
    "scripts/isolated_runs/storage.py": (6761, "6bf39ae68c1294cb0f9b8fd387aff87689ef97070e273b456a04203dcfd3cdc0"),
    "scripts/isolated_runs/storage_references.py": (23457, "4122fded6eacffea1bdf2ffa560652b32e09f5d1b4b9f0d983a900e4c0075db6"),
    "scripts/scenario-context": (193, "8d413d08cd32240854304b3a53b17095c5057057815cf918f96afd1fdaf6565b"),
}


def composite(mapping: dict) -> str:
    return hashlib.sha256(json.dumps(
        mapping, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


def approved_definition() -> dict:
    """Derive and check the exact embedded 13-file canonical definition."""
    mapping = {name: {"bytes": length, "sha256": digest} for name, (length, digest) in FILES.items()}
    if composite(mapping) != SUBSET_DIGEST:
        raise RunError("approved_producing_source_definition_changed")
    return mapping


def inode_identity(info) -> tuple:
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def directory_identity(info) -> tuple:
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode


def verify_source(root_argument) -> dict:
    """Verify fixed relative raw bytes through pinned no-follow descriptors.

    The returned location receipt is private binding material, not public CLI
    output and not historical execution attestation or recovery authorization.
    """
    if root_argument is None:
        raise RunError("approved_producing_source_unavailable")
    root = Path(root_argument)
    if not root.is_absolute() or ".." in root.parts:
        raise RunError("unsafe_producing_source_root")
    definition = approved_definition()
    pins = []
    files = []
    try:
        with ExitStack() as stack:
            def directory(name, parent_fd, path, *, descendant):
                fd = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent_fd,
                )
                stack.callback(os.close, fd)
                info = os.fstat(fd)
                sticky = (
                    path == Path("/tmp") and root.is_relative_to(Path("/tmp/opencode"))
                    and info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                )
                owned_temporary_subtree = (
                    root.is_relative_to(Path("/tmp/opencode"))
                    and path.is_relative_to(Path("/tmp/opencode"))
                )
                if (
                    not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                    or ((descendant or owned_temporary_subtree) and info.st_uid != os.getuid())
                    or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
                    or (info.st_mode & 0o022 and not sticky)
                ):
                    raise RunError("unsafe_producing_source_directory")
                pins.append((fd, parent_fd, name, directory_identity(info)))
                return fd

            current = Path("/")
            fd = directory("/", None, current, descendant=False)
            for part in root.parts[1:]:
                current /= part
                fd = directory(part, fd, current, descendant=current == root)
            root_fd = fd
            root_stat = os.fstat(root_fd)
            if root_stat.st_uid != os.getuid():
                raise RunError("unsafe_producing_source_root")
            measured = {}
            for relative, expected in definition.items():
                parts = PurePosixPath(relative).parts
                if not parts or PurePosixPath(relative).is_absolute() or ".." in parts:
                    raise RunError("approved_producing_source_definition_changed")
                parent = root_fd
                current = root
                for part in parts[:-1]:
                    current /= part
                    parent = directory(part, parent, current, descendant=True)
                child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                stack.callback(os.close, child)
                with os.fdopen(os.dup(child), "rb") as stream:
                    before = os.fstat(stream.fileno())
                    if (
                        not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                        or before.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
                        or before.st_nlink != 1 or before.st_size != expected["bytes"]
                    ):
                        raise RunError("unsafe_or_changed_producing_source_file")
                    content = stream.read(expected["bytes"] + 1)
                    after = os.fstat(stream.fileno())
                    entry = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                    if inode_identity(before) != inode_identity(after) or inode_identity(before) != inode_identity(entry):
                        raise RunError("producing_source_changed_during_read")
                files.append((child, parent, parts[-1], inode_identity(before)))
                measured[relative] = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                if measured[relative] != expected:
                    raise RunError("producing_source_bytes_mismatch")
            if composite(measured) != SUBSET_DIGEST:
                raise RunError("producing_source_bytes_mismatch")
            for descriptor, parent, name, expected in pins:
                if (
                    directory_identity(os.fstat(descriptor)) != expected
                    or directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected
                ):
                    raise RunError("producing_source_directory_changed")
            for descriptor, parent, name, expected in files:
                if (
                    inode_identity(os.fstat(descriptor)) != expected
                    or inode_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected
                ):
                    raise RunError("producing_source_changed_during_read")
            return {
                "profile": PROFILE, "subset_digest": SUBSET_DIGEST,
                "root": {"path": str(root), "device": root_stat.st_dev, "inode": root_stat.st_ino,
                         "uid": root_stat.st_uid, "mode": root_stat.st_mode},
                "provenance": "reviewed-byte-subset-not-historical-execution-attestation",
            }
    except (OSError, ValueError, TypeError) as exc:
        raise RunError("approved_producing_source_unavailable") from exc
