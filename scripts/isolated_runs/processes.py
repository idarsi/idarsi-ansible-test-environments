"""Linux worker sessions with a durable start gate and explicit recovery."""

import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from .state import RunError


def boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def process(pid: int):
    """Return Linux session and birth ticks, handling exited processes only."""
    try:
        path = Path("/proc") / str(pid)
        fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
        return {
            "pid": pid, "session": int(fields[3]), "start": fields[19],
            "uid": path.stat().st_uid, "zombie": fields[0] == "Z",
        }
    except (FileNotFoundError, ProcessLookupError):
        return None


def members(worker: dict) -> list:
    """A session may survive its original leader; inspect ALL members."""
    if worker["boot"] != boot_id():
        return []
    leader = process(worker["pid"])
    if leader and leader["start"] != worker["start"]:
        raise RunError("Worker PID was reused; refusing to signal that session")
    result = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            item = process(int(entry.name))
            if item and item["session"] == worker["pid"] and not item["zombie"]:
                if item["uid"] != os.getuid():
                    raise RunError("Worker session contains a different UID")
                result.append(item)
    return result


def stop_workers(data: dict) -> None:
    """Bounded TERM/KILL, with identity checks before each signal."""
    if any(
        worker["boot"] == boot_id() and worker["pid"] == os.getsid(0)
        for worker in data["workers"]
    ):
        raise RunError("Cannot quiesce the caller's own worker session; defer to the supervisor")
    for worker in data["workers"]:
        for sig, duration in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
            for item in members(worker):
                # pidfds prevent signalling a process that reuses this PID.
                try:
                    fd = os.pidfd_open(item["pid"])
                except ProcessLookupError:
                    continue
                try:
                    current = process(item["pid"])
                    if current and current["start"] == item["start"]:
                        signal.pidfd_send_signal(fd, sig)
                finally:
                    os.close(fd)
            deadline = time.monotonic() + duration
            while members(worker) and time.monotonic() < deadline:
                time.sleep(0.1)
            if not members(worker):
                break
        if members(worker):
            raise RunError("Worker session did not stop; retaining all resources")


def spawn(store, data: dict, argv: list, env: dict, cwd: str):
    """Journal a new session before allowing it to execute any lifecycle work."""
    read_fd, write_fd = os.pipe()
    helper = (
        "import os,sys; fd=int(sys.argv[1]); "
        "token=os.read(fd,1); os.close(fd); "
        "sys.exit(125) if token != b'G' else os.execvpe(sys.argv[2],sys.argv[2:],os.environ)"
    )
    try:
        child = subprocess.Popen(
            [sys.executable, "-c", helper, str(read_fd)] + argv,
            pass_fds=(read_fd,), start_new_session=True, env=env, cwd=cwd,
        )
        identity = process(child.pid)
        if not identity:
            raise RunError("Worker exited before start could be journalled")
        data["workers"].append({
            "pid": child.pid, "start": identity["start"], "boot": boot_id(),
        })
        store.save(data)
        os.write(write_fd, b"G")
        return child
    finally:
        os.close(read_fd)
        os.close(write_fd)
