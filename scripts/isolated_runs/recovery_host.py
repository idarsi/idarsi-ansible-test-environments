"""Bounded local journal identity proof; never accepts caller-supplied receipts."""

from pathlib import Path
import re
import stat
import subprocess
import tempfile
import uuid

from .state import RunError


def canonical_uuid(value: str) -> str:
    """Reject aliases, non-strings and noncanonical UUID spellings."""
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise RunError("invalid_identity")
    return value


def trusted_root_path(path: Path, directory: bool = False):
    """Require an absolute, unsubstituted, root-controlled local metadata path."""
    if not path.is_absolute():
        raise RunError("historical_host_identity_unproven")
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        if (
            info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode)
            or (item != path and not stat.S_ISDIR(info.st_mode))
        ):
            raise RunError("historical_host_identity_unproven")
    info = path.lstat()
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise RunError("historical_host_identity_unproven")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RunError("historical_host_identity_unproven")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def journal_command(argv: list) -> str:
    """Bound metadata output and time; never request journal MESSAGE fields."""
    with tempfile.TemporaryFile() as output, subprocess.Popen(
        argv, stdout=output, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
    ) as child:
        try:
            child.wait(timeout=15)
        except subprocess.TimeoutExpired as exc:
            child.kill()
            child.wait()
            raise RunError("historical_host_identity_unproven") from exc
        if child.returncode or output.tell() > 8192:
            raise RunError("historical_host_identity_unproven")
        output.seek(0)
        return output.read(8193).decode("utf-8", errors="strict")


def machine_identity() -> str:
    """Measure the current root-controlled machine identity, not manifest history."""
    path = Path("/etc/machine-id")
    stamp = trusted_root_path(path)
    value = path.read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{32}", value) or trusted_root_path(path) != stamp:
        raise RunError("historical_host_identity_unproven")
    return value


def boot_fence(workers: list, current_boot: str) -> dict:
    """Match every historical boot to local root-controlled journal machine ID."""
    canonical_uuid(current_boot)
    old_boots = sorted({canonical_uuid(worker["boot"]) for worker in workers})
    if not old_boots:
        raise RunError("historical_host_identity_unproven")
    if current_boot in old_boots:
        raise RunError("same_boot_not_fenced")
    machine_path = Path("/etc/machine-id")
    machine_stamp = trusted_root_path(machine_path)
    machine = machine_path.read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{32}", machine):
        raise RunError("historical_host_identity_unproven")
    executable = Path("/usr/bin/journalctl")
    executable_stamp = trusted_root_path(executable)
    directory = Path("/var/log/journal") / machine
    directory_stamp = trusted_root_path(directory, directory=True)
    # No journal traversal outside the current machine's persistent local store.
    files = sorted(directory.glob("system*.journal"))
    if not files or len(files) > 256:
        raise RunError("historical_host_identity_unproven")
    stamps = {path: trusted_root_path(path) for path in files}
    selectors = [argument for path in files for argument in ("--file", str(path))]
    # --verify validates the actual selected journal files, not an unrelated source.
    with subprocess.Popen(
        [str(executable), *selectors, "--verify"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
    ) as child:
        try:
            code = child.wait(timeout=30)
        except subprocess.TimeoutExpired as exc:
            child.kill()
            child.wait()
            raise RunError("historical_host_identity_unproven") from exc
        if code:
            raise RunError("historical_host_identity_unproven")
    for boot in old_boots:
        output = journal_command([
            str(executable), *selectors, "--quiet", "--no-pager",
            "--field=_MACHINE_ID",
            "_BOOT_ID=" + boot.replace("-", ""),
        ])
        # --field returns all unique trusted identities for the exact boot,
        # unlike tailing two entries, which could miss a conflicting origin.
        if output.splitlines() != [machine]:
            raise RunError("historical_host_identity_unproven")
    if (
        trusted_root_path(machine_path) != machine_stamp
        or trusted_root_path(executable) != executable_stamp
        or trusted_root_path(directory, directory=True) != directory_stamp
        or any(trusted_root_path(path) != stamp for path, stamp in stamps.items())
    ):
        raise RunError("historical_host_identity_unproven")
    return {"route": "host-boot", "current_boot": current_boot, "old_boots": old_boots}
