"""Strict kernel mount metadata parsing shared by recovery-only proofs."""

from pathlib import Path
import re

from .state import RunError


def mount_path(value: str) -> Path:
    """Decode the four escapes emitted by procfs, refusing unknown spellings."""
    escapes = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    if re.search(r"\\(?!040|011|012|134)", value):
        raise RunError("mount_metadata_unproven")
    decoded = re.sub(r"\\(040|011|012|134)", lambda match: escapes[match[1]], value)
    path = Path(decoded)
    if not path.is_absolute() or ".." in path.parts:
        raise RunError("mount_metadata_unproven")
    return path


def parse_mountinfo(text: str) -> list:
    """Parse complete kernel records, never discarding escaped mount points."""
    result = []
    for line in text.splitlines():
        try:
            left, right = line.split(" - ")
            fields, super_fields = left.split(), right.split()
            if len(fields) < 6 or len(super_fields) != 3:
                raise ValueError
            result.append({
                "root": mount_path(fields[3]), "point": mount_path(fields[4]),
                "filesystem": super_fields[0],
                "options": fields[5].split(",") + super_fields[2].split(","),
            })
        except (ValueError, IndexError) as exc:
            raise RunError("mount_metadata_unproven") from exc
    if not result:
        raise RunError("mount_metadata_unproven")
    return result


def mounts() -> list:
    """Read actual kernel metadata, not a caller-supplied proof."""
    return parse_mountinfo(Path("/proc/self/mountinfo").read_text())


def containing(records: list, path: Path) -> dict:
    candidates = [
        record for record in records
        if path == record["point"] or record["point"] in path.parents
    ]
    if not candidates:
        raise RunError("mount_metadata_unproven")
    depth = max(len(record["point"].parts) for record in candidates)
    candidates = [record for record in candidates if len(record["point"].parts) == depth]
    if len(candidates) != 1:
        raise RunError("mount_metadata_unproven")
    return candidates[0]


def complete_proc_view() -> None:
    """Only a full root procfs with unrestricted PID visibility is supported.

    No UID/gid/CAP_SYS_PTRACE exception is guessed for hidepid mounts. Namespace
    identity is checked separately, and readable per-process metadata is still
    mandatory in the subsequent scan.
    """
    records = mounts()
    proc = containing(records, Path("/proc"))
    if proc["point"] != Path("/proc") or proc["root"] != Path("/") or proc["filesystem"] != "proc":
        raise RunError("process_visibility_unproven")
    allowed = {
        "rw", "ro", "nosuid", "nodev", "noexec", "relatime", "noatime",
        "strictatime", "lazytime", "seclabel", "hidepid=0", "hidepid=off",
        "subset=all",
    }
    for option in proc["options"]:
        if option not in allowed and not re.fullmatch(r"gid=[0-9]+", option):
            raise RunError("process_visibility_unproven")
    for record in records:
        parts = record["point"].parts
        if len(parts) > 2 and parts[1] == "proc" and (
            parts[2].isdigit() or parts[2] in ("self", "thread-self")
        ):
            raise RunError("process_visibility_unproven")
