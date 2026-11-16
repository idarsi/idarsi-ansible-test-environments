"""Durable manifests, leases and advisory locks shared by every checkout."""

import contextlib
import fcntl
import ipaddress
import itertools
import json
import os
from pathlib import Path
import stat
import tempfile
import uuid


class RunError(RuntimeError):
    """An operation could not be proved safe."""


def fsync_directory(path: Path) -> None:
    """Persist directory entries without following a substituted directory."""
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_directory(path: Path) -> Path:
    """Create a private directory, refusing substituted or shared state."""
    if not path.parent.exists():
        private_directory(path.parent)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise RunError("State directory must be a real directory owned by this UID")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise RunError("State directory must have mode 0700: " + str(path))
    # Also sync existing entries: a previous writer could have died after mkdir.
    fsync_directory(path)
    fsync_directory(path.parent)
    return path


def atomic_json(path: Path, value: dict) -> None:
    """Commit JSON and its directory entry before returning."""
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def lock(path: Path, blocking: bool = True):
    """Lock a private, non-symlink file; never unlink a lock inode."""
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode):
            raise RunError("Unsafe lock file: " + str(path))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError as exc:
            raise RunError("Run is locked by an active supervisor or lifecycle worker") from exc
        yield fd
    finally:
        os.close(fd)


class Store:
    """One allocator per real Unix user, independent of clone and XDG overrides."""

    def __init__(self, root: Path = None):
        if root is None:
            import pwd

            root = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".idarsi-test-runs"
        self.root = private_directory(root)

    def ephemeral(self, run_id: str) -> Path:
        """Disposable Molecule state is never an ancestor of the journal."""
        self.directory(run_id)
        return self.root / ".work" / run_id / "ephemeral"

    def directory(self, run_id: str) -> Path:
        if str(uuid.UUID(run_id)) != run_id:
            raise RunError("Run ID must be a canonical UUID")
        directory = self.root / run_id
        for path in (self.root, directory):
            info = path.lstat()
            if (
                not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise RunError("Unsafe state/run directory")
        return directory

    def load(self, run_id: str) -> dict:
        path = self.directory(run_id) / "manifest.json"
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise RunError("Manifest must be a private regular file owned by this UID")
            data = json.load(stream)
        if data["version"] != 1 or data["uid"] != os.getuid() or data["id"] != run_id:
            raise RunError("Manifest schema, owner or identity mismatch")
        return data

    def save(self, data: dict) -> None:
        atomic_json(self.directory(data["id"]) / "manifest.json", data)

    def runs(self) -> list:
        result = []
        for path in sorted(self.root.iterdir()):
            if path.name.startswith("."):
                continue
            # Incomplete directory creation holds no lease and has no resources.
            if (path / "manifest.json").exists():
                result.append(self.load(path.name))
        return result

    def allocate(self, backend: str, context: dict, discover, role: Path, scenario: str) -> dict:
        """Discovery and reservation share one lock; a manifest IS the lease."""
        with lock(self.root / ".allocator.lock"):
            occupied = list(discover())
            for run in self.runs():
                if run["status"] != "cleaned":
                    occupied.append(ipaddress.ip_network(run["subnet"]))
            subnet = None
            candidates = itertools.chain.from_iterable(
                ipaddress.ip_network(pool).subnets(new_prefix=24)
                for pool in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            )
            for candidate in candidates:
                if not any(candidate.overlaps(other) for other in occupied if other.version == 4):
                    subnet = candidate
                    break
            if subnet is None:
                raise RunError("No disjoint private /24 available")
            run_id = str(uuid.uuid4())
            private_directory(self.root / run_id)
            private_directory(self.root / ".work")
            private_directory(self.root / ".work" / run_id)
            private_directory(self.ephemeral(run_id))
            data = {
                "version": 1, "id": run_id, "uid": os.getuid(), "backend": backend,
                "context": context, "subnet": str(subnet), "status": "allocated",
                "role": str(role), "scenario": scenario, "network": None,
                "guests": [], "workers": [], "config": None,
            }
            self.save(data)
            return data
