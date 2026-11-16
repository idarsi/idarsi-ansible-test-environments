"""Crash-safe Linux unnamed-inode publication for owned qcow2 files."""

import contextlib
import os
from pathlib import Path
import re
import stat
import uuid

from .state import RunError

STORAGE = Path("/var/lib/libvirt/images/idarsi-test-bases")
PRIVATE_POLICY = "supervisor-private-nonexport-v1"
PUBLICATION_PROTOCOL = "linux-o-tmpfile-linkat-v1"


class Storage:
    """Operate relative to a checked, pinned storage directory descriptor."""

    def __init__(self, root: Path = STORAGE):
        self.root = root

    @contextlib.contextmanager
    def directory(self):
        if not self.root.is_absolute():
            raise RunError("Storage path must be absolute")
        # Ancestors can legitimately be root-owned 0711: search permission is
        # sufficient to reach our storage directory. O_PATH pins each component
        # for fstat/relative lookup without requiring directory-list permission.
        path_flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open("/", path_flags)
        try:
            for component in self.root.parts[1:]:
                child = os.open(component, path_flags, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                if info.st_uid not in (0, os.getuid()):
                    raise RunError("Untrusted storage directory owner")
                if info.st_mode & stat.S_IWOTH and not (
                    info.st_uid == 0 and info.st_mode & stat.S_ISVTX
                ):
                    raise RunError("Untrusted world-writable storage ancestor")
                if info.st_mode & stat.S_IWGRP and info.st_gid not in os.getgroups() + [os.getgid()] and not (
                    info.st_uid == 0 and info.st_mode & stat.S_ISVTX
                ):
                    raise RunError("Untrusted storage directory group")
            # Reopen the pinned target itself, not its original pathname. Only
            # this final descriptor needs read permission and must support fsync.
            readable = os.open(
                ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd,
            )
            os.close(fd)
            fd = readable
            yield fd
        finally:
            os.close(fd)

    def basename(self, record: dict) -> str:
        path = Path(record["path"])
        if path.parent != self.root or not re.fullmatch(r"itr-[a-f0-9]{32}\.qcow2", path.name):
            raise RunError("Disk path is outside the owned storage namespace")
        return path.name

    def verify(self, record: dict, directory_fd: int):
        try:
            info = os.stat(self.basename(record), dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode) or (
            info.st_dev, info.st_ino
        ) != (record["device"], record["inode"]):
            raise RunError("Disk inode changed; refusing adoption or deletion")
        if info.st_nlink != 1:
            raise RunError("Unexpected owned-disk hardlinks; refusing mutation")
        return info

    @contextlib.contextmanager
    def publish(self, record: dict, save, *, owner_id: str = None):
        """Persist inode ownership BEFORE linking it into the storage namespace."""
        with self.directory() as directory_fd:
            if owner_id is not None:
                if str(uuid.UUID(owner_id)) != owner_id or "publication" in record:
                    raise RunError("Publication requires a new record and canonical owning run")
                path = str(self.root / self.basename(record))
                if str(Path(path).resolve()) != path:
                    raise RunError("Private publication requires a canonical path")
                record["publication"] = {
                    "policy": PRIVATE_POLICY, "protocol": PUBLICATION_PROTOCOL,
                    "owner": owner_id, "path": path, "state": "intent",
                }
                save()
            fd = os.open(".", os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise RunError("O_TMPFILE did not return a regular file")
                os.fsync(fd)
                record.update(device=info.st_dev, inode=info.st_ino)
                if owner_id is not None:
                    record["publication"].update(
                        device=info.st_dev, inode=info.st_ino, state="inode-journalled",
                    )
                save()
                # linkat with AT_SYMLINK_FOLLOW via /proc, not privileged AT_EMPTY_PATH.
                # No O_EXCL on O_TMPFILE: that would prohibit publication.
                os.link(
                    "/proc/self/fd/" + str(fd), self.basename(record),
                    dst_dir_fd=directory_fd, follow_symlinks=True,
                )
                self.verify(record, directory_fd)
                os.fsync(directory_fd)
                if owner_id is not None:
                    record["publication"]["state"] = "published"
                    save()
                try:
                    yield fd
                finally:
                    # Keep the original inode pinned while tools operate by path.
                    if self.verify(record, directory_fd) is None:
                        raise RunError("Published disk disappeared during provisioning")
                    os.fsync(fd)
            finally:
                os.close(fd)

    def remove(self, record: dict):
        with self.directory() as directory_fd:
            if self.verify(record, directory_fd):
                os.unlink(self.basename(record), dir_fd=directory_fd)
            # Also sync on a retry where unlink succeeded before a crash.
            os.fsync(directory_fd)

    def probe(self, save=lambda record: None):
        """Exercise publication, durability and EEXIST on the exact target FS."""
        record = {"path": str(self.root / ("itr-" + uuid.uuid4().hex + ".qcow2"))}
        try:
            with self.publish(record, lambda: save(record)) as fd:
                with self.directory() as directory_fd:
                    try:
                        os.link(
                            "/proc/self/fd/" + str(fd), self.basename(record),
                            dst_dir_fd=directory_fd, follow_symlinks=True,
                        )
                    except FileExistsError:
                        pass
                    else:
                        raise RunError("Storage filesystem failed collision refusal")
        finally:
            if "inode" in record:
                self.remove(record)
