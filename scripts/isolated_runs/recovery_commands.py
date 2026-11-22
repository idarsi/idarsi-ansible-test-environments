"""Recovery-only, authenticated root-tool read queries with no inherited config."""

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import uuid

from .state import RunError

TOOLS = {
    "ip": "/usr/sbin/ip", "nft": "/usr/sbin/nft",
    "iptables-save": "/usr/sbin/iptables-save",
    "ip6tables-save": "/usr/sbin/ip6tables-save", "virsh": "/usr/bin/virsh",
}
ENVIRONMENT = {
    "PATH": "/usr/bin:/usr/sbin", "HOME": "/", "XDG_CONFIG_HOME": "/",
    "XDG_CACHE_HOME": "/", "XDG_DATA_HOME": "/", "XDG_CONFIG_DIRS": "/",
    "LC_ALL": "C", "LANG": "C", "VIRSH_HISTSIZE": "0",
}


def root_path(path: Path, depth: int = 0) -> Path:
    """Authenticate every component and symlink hop, including merged-/usr links."""
    if not path.is_absolute() or depth > 40:
        raise RunError("recovery_tool_untrusted")
    current = Path("/")
    parts = path.parts[1:]
    for index, part in enumerate(("", *parts)):
        if part:
            current = current / part
        info = current.lstat()
        link = stat.S_ISLNK(info.st_mode)
        if info.st_uid != 0 or (not link and (
            info.st_mode & 0o022 or os.access(current, os.W_OK, effective_ids=True)
        )):
            raise RunError("recovery_tool_untrusted")
        if link:
            target = current.readlink()
            target = target if target.is_absolute() else current.parent / target
            return root_path(target.joinpath(*parts[index:]), depth + 1)
        if index < len(parts) and not stat.S_ISDIR(info.st_mode):
            raise RunError("recovery_tool_untrusted")
    return current.resolve(strict=True)


def allowed(argv: list) -> None:
    """Only these complete read-only query grammars can cross the process boundary."""
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
        raise RunError("recovery_query_unsupported")
    fixed = (
        ["ip", "-j", "address", "show"], ["ip", "-j", "link", "show"],
        ["ip", "-j", "-4", "route", "show", "table", "all"],
        ["ip", "-j", "-6", "route", "show", "table", "all"],
        ["nft", "-j", "list", "ruleset"], ["iptables-save"], ["ip6tables-save"],
    )
    if argv in fixed:
        return
    if argv[:3] != ["virsh", "--connect", "qemu:///system"]:
        raise RunError("recovery_query_unsupported")
    query = argv[3:]
    if query in (
        ["net-list", "--all", "--uuid"], ["list", "--all", "--uuid"],
        ["list", "--uuid"], ["list", "--all", "--persistent", "--uuid"],
    ):
        return
    if (
        len(query) in (2, 3) and query[0] in ("net-dumpxml", "dumpxml")
        and (len(query) == 2 or query == ["dumpxml", query[1], "--inactive"])
    ):
        try:
            if str(uuid.UUID(query[1])) == query[1]:
                return
        except ValueError:
            pass
    raise RunError("recovery_query_unsupported")


def command(argv: list, timeout: int = 60) -> str:
    """Run a bounded authenticated query; no PATH search, stdin or caller environment."""
    allowed(argv)
    if os.geteuid() == 0:
        raise RunError("recovery_tool_uid_unsupported")
    try:
        executable = root_path(Path(TOOLS[argv[0]]))
        info = executable.lstat()
        if (
            not stat.S_ISREG(info.st_mode) or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or not os.access(executable, os.X_OK, effective_ids=True)
        ):
            raise RunError("recovery_tool_untrusted")
        # All child search/config roots are root-controlled; no caller HOME/XDG,
        # loader, URI, auth, hook, shell-function or Python environment survives.
        for directory in ("/", "/usr/bin", "/usr/sbin"):
            root_path(Path(directory))
        # Preserve the authenticated alias as argv[0] for xtables multicall
        # binaries, but exec the authenticated resolved target explicitly.
        arguments = [TOOLS[argv[0]], *argv[1:]]
        if argv[0] == "virsh":
            arguments.insert(1, "--readonly")
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(
                arguments, executable=str(executable), stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.DEVNULL, env=dict(ENVIRONMENT), cwd="/",
                timeout=timeout, check=False,
            )
            if result.returncode or output.tell() > 8 * 1024 * 1024:
                raise RunError("recovery_query_failed")
            output.seek(0)
            return output.read(8 * 1024 * 1024 + 1).decode("utf-8", errors="strict").strip()
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise RunError("recovery_query_failed") from exc
