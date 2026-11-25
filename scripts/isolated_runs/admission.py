"""Closeable supervised admission for normal tools that create child sessions."""

import contextlib
import json
import os
from pathlib import Path
import stat
from typing import Iterator

from .processes import boot_id, process
from .state import RunError, Store, atomic_json, existing_lock, lock

PROTOCOL = "session-v1"


def gate(store: Store, run_id: str) -> dict:
    """Read the independent private gate; missing or malformed is never open."""
    path = store.directory(run_id) / "admission.json"
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
        ):
            raise RunError("Unsafe supervised admission gate")
        data = json.load(stream)
    return validate_gate(data, run_id)


def validate_gate(data, run_id):
    """Shared gate schema check for ordinary and bounded existing-only readers."""
    if (
        not isinstance(data, dict) or data.get("version") != 1 or data.get("id") != run_id
        or data.get("state") not in ("open", "closed")
    ):
        raise RunError("Invalid supervised admission gate")
    return data


def initialize(store: Store, run_id: str) -> None:
    """Supervisor-only initialization, before any scenario worker is launched."""
    with lock(store.directory(run_id) / ".admission.lock"):
        path = store.directory(run_id) / "admission.json"
        if path.exists() or path.is_symlink():
            raise RunError("Admission gate already exists; never reopen it")
        atomic_json(path, {"version": 1, "id": run_id, "state": "open"})


def close(store: Store, run_id: str) -> dict:
    """Caller owns supervisor. Never wait for resources or workers under this lock."""
    with lock(store.directory(run_id) / ".admission.lock"):
        data = store.load(run_id)
        if data.get("admission_protocol") != PROTOCOL:
            raise RunError("Unsupported supervised admission protocol")
        control = gate(store, run_id)
        if control["state"] == "open":
            control["state"] = "closed"
            atomic_json(store.directory(run_id) / "admission.json", control)
        # Registration cannot commit after closure; this snapshot includes every
        # admitted session even if its mutation still holds the resource lock.
        return store.load(run_id)


def binding(data: dict, expected: dict) -> None:
    """Revalidate immutable identity and running authority without logging values."""
    for field in ("id", "role", "scenario", "backend"):
        if data[field] != expected[field]:
            raise RunError("Supervised binding mismatch: " + field)
    if data.get("mode") != "supervised":
        raise RunError("Supervised binding mismatch: mode")
    if data["status"] != "running":
        raise RunError("Supervised binding mismatch: status")
    if data.get("admission_protocol") != PROTOCOL or data.get("mutation_protocol") != "sealed-v1":
        raise RunError("Unsupported supervised admission protocol")
    if (
        os.environ.get("IDARSI_RUN_ID") != data["id"] or os.environ.get("IDARSI_HANDOFF") != "v1"
        or any(key.startswith("IDARSI_HANDOFF") and key != "IDARSI_HANDOFF" for key in os.environ)
    ):
        raise RunError("Supervised binding mismatch: handoff")
    supplied = os.environ.get("MOLECULE_EPHEMERAL_DIRECTORY")
    if not supplied or Path(supplied).resolve() != Path(expected["ephemeral"]):
        raise RunError("Supervised binding mismatch: ephemeral")


@contextlib.contextmanager
def prove_sessions(data: dict) -> Iterator[list]:
    """Pin and recheck the entire PPID chain to a live journalled outer worker."""
    epoch = boot_id()
    if not data["workers"]:
        raise RunError("Supervised ancestry has no outer worker")
    root = data["workers"][0]
    if root["boot"] != epoch:
        raise RunError("Supervised ancestry boot mismatch")
    chain = []
    fds = []
    seen = set()
    pid = os.getpid()
    try:
        while True:
            item = process(pid)
            if (
                item is None or item["zombie"] or item["uid"] != os.getuid()
                or pid in seen or pid <= 1
            ):
                raise RunError("Supervised ancestry is missing, foreign or inconsistent")
            seen.add(pid)
            try:
                fds.append(os.pidfd_open(pid))
            except ProcessLookupError as exc:
                raise RunError("Supervised ancestry disappeared") from exc
            if process(pid) != item:
                raise RunError("Supervised ancestry changed while pinning")
            chain.append(item)
            if pid == root["pid"]:
                if item["start"] != root["start"] or item["session"] != root["pid"]:
                    raise RunError("Supervised outer worker birth/session mismatch")
                break
            parent = item["parent"]
            if parent <= 1:
                raise RunError("Helper is not descended from the supervised outer worker")
            pid = parent
        by_pid = {item["pid"]: item for item in chain}
        if any(int(parent["start"]) > int(child["start"]) for child, parent in zip(chain, chain[1:])):
            raise RunError("Supervised ancestry birth order mismatch")
        sessions = []
        for item in chain:
            leader = by_pid.get(item["session"])
            if leader is None or leader["session"] != leader["pid"]:
                raise RunError("Supervised session leader is outside the proven ancestry")
            if int(leader["start"]) > int(item["start"]):
                raise RunError("Supervised ancestry birth order mismatch")
            record = {"pid": leader["pid"], "start": leader["start"], "boot": epoch}
            if record not in sessions:
                sessions.append(record)
        # Re-read WHOLE chain after all pidfds are held. Reparenting, exits,
        # reused PIDs, changed SIDs/UIDs and zombie transitions all fail closed.
        if boot_id() != epoch or any(process(item["pid"]) != item for item in chain):
            raise RunError("Supervised ancestry changed before admission")
        yield sessions
    finally:
        for fd in fds:
            os.close(fd)


def registered_current(data: dict) -> dict:
    """Validate the live current session leader against its immutable record."""
    sid = os.getsid(0)
    leader = process(sid)
    if leader is None or leader["zombie"] or leader["uid"] != os.getuid() or leader["session"] != sid:
        raise RunError("Supervised binding mismatch: session leader")
    record = {"pid": sid, "start": leader["start"], "boot": boot_id()}
    if record not in data["workers"]:
        raise RunError("Supervised binding mismatch: unregistered session")
    return record


def authorize(store: Store, run_id: str, expected: dict) -> dict:
    """Resources -> admission; journal every proven session before authorization."""
    with lock(store.directory(run_id) / ".resources.lock"):
        with lock(store.directory(run_id) / ".admission.lock"):
            data = store.load(run_id)
            binding(data, expected)
            if gate(store, run_id)["state"] != "open":
                raise RunError("Supervised admission is closed")
            with prove_sessions(data) as sessions:
                for record in sessions:
                    matches = [old for old in data["workers"] if old["pid"] == record["pid"]]
                    if matches and matches != [record]:
                        raise RunError("Supervised session identity is stale or ambiguous")
                    if not matches:
                        data["workers"].append(record)
                registered = registered_current(data)
                store.save(data)
                return registered


def validate_existing(store: Store, run_id: str, expected: dict, *, _existing_lock=None) -> None:
    """Caller holds resources: prove read-only ancestry without registering it."""
    from .readonly import read_file, strict_json

    lock_existing = existing_lock if _existing_lock is None else _existing_lock
    with lock_existing(store.directory(run_id) / ".admission.lock"):
        data = store.load(run_id)
        binding(data, expected)
        control = validate_gate(strict_json(read_file(
            store.directory(run_id) / "admission.json", 16384,
        )), run_id)
        if control["state"] != "open":
            raise RunError("Supervised admission is closed")
        with prove_sessions(data) as sessions:
            for record in sessions:
                matches = [old for old in data["workers"] if old["pid"] == record["pid"]]
                if matches and matches != [record]:
                    raise RunError("Supervised session identity is stale or ambiguous")


@contextlib.contextmanager
def mutation_boundary(store: Store, run_id: str, expected: dict) -> Iterator[tuple]:
    """Caller holds resources; persist create intent before releasing admission."""
    with lock(store.directory(run_id) / ".admission.lock"):
        data = store.load(run_id)
        binding(data, expected)
        if gate(store, run_id)["state"] != "open":
            raise RunError("Supervised admission is closed")
        yield data, registered_current(data)


def cleanup_boundary(store: Store, run_id: str, operation: dict) -> None:
    """Only the supervisor's separately gated, exact journalled cleanup may enter."""
    with lock(store.directory(run_id) / ".admission.lock"):
        data = store.load(run_id)
        if (
            data.get("admission_protocol") != PROTOCOL or data.get("mode") != "supervised"
            or data["status"] != "cleaning" or gate(store, run_id)["state"] != "closed"
            or operation.get("purpose") != "supervisor-cleanup"
            or operation["action"] != "destroy"
        ):
            raise RunError("Invalid supervised cleanup admission")
