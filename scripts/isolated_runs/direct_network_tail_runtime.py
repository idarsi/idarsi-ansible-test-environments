"""Rootless standard-libvirt profile: measured installation, explicitly trusted runtime."""

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

from . import processes, recovery, recovery_commands
from .backends import REPO
from .state import RunError

PROFILE = "direct-standard-libvirt-network-tail-v1"
PACKAGE = "libvirt-daemon-driver-network"
BUILD = "12.0.0-3.fc44"
SOURCE_RPM = "libvirt-12.0.0-3.fc44.src.rpm"
DAEMON = "/usr/bin/virtnetworkd"
DRIVER = "/usr/lib64/libvirt/connection-driver/libvirt_driver_network.so"
UNIT = "/usr/lib/systemd/system/virtnetworkd.service"
DROPIN = "/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
SYSTEMD_BUILD = "259.8-1.fc44"
SYSTEMD_SOURCE_RPM = "systemd-259.8-1.fc44.src.rpm"
DROPIN_BYTES = 596
DROPIN_SHA256 = "ae6b234f92bc22f1201a7572b59b454c9809f33c80d13f361b9674e1801acc37"
PROPERTIES = (
    "ActiveState", "SubState", "MainPID", "ExecStart", "PrivateNetwork",
    "NetworkNamespacePath", "FragmentPath", "DropInPaths", "TimeoutStopFailureMode",
)
CLAIMS = {
    "scope": "normal-libvirt-api-teardown-reconciliation",
    "original_destroy_completed": False,
    "independent_firewall_verification": "unverified",
    "independent_helper_verification": "unverified",
    "loaded_image_attestation": "unverified",
    "generic_rpc_drain": "not-claimed",
    "fresh_original_guest_disk_identity_absence": "not-claimed",
}
ASSUMPTIONS = {
    "historical_source": "operator-accepted-cooperative-attribution-to-reviewed-producing-bytes-not-attestation",
    "historical_removal": "durable-empty-guests-checkpoint-accepted-as-historical-removal-not-fresh-identity-proof",
    "runtime": "standard-running-packaged-libvirt-driver-trusted-to-perform-normal-firewall-and-helper-cleanup",
    "automation": "no-detaching-hooks-untracked-writers-external-automation-or-resource-recreation",
    "identity": "historical-network-uuid-name-and-bridge-not-reused",
    "visibility": "normal-host-network-view-not-isolated-or-filtered",
    "late_rpc": "audited-remaining-old-destroy-is-deletion-only-not-a-generic-rpc-drain",
}


def _run(argv: list, *, readonly: bool) -> str:
    """Fixed authenticated tool invocation, no shell/config/environment inheritance."""
    if os.geteuid() == 0:
        raise RunError("standard_profile_requires_unprivileged_controller")
    executable = recovery_commands.root_path(Path(argv[0]))
    info = executable.stat()
    if (
        not stat.S_ISREG(info.st_mode) or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or not os.access(executable, os.X_OK, effective_ids=True)
    ):
        raise RunError("standard_profile_tool_untrusted")
    try:
        result = subprocess.run(
            argv, executable=str(executable), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=dict(recovery_commands.ENVIRONMENT), cwd="/",
            timeout=30 if readonly else 60, check=False,
        )
        if result.returncode or len(result.stdout) > 8 * 1024 * 1024:
            raise RunError("standard_profile_query_failed" if readonly else "standard_network_destroy_uncertain")
        return result.stdout.decode("utf-8", errors="strict").strip()
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise RunError("standard_profile_query_failed" if readonly else "standard_network_destroy_uncertain") from exc


def read_query(argv: list, **kwargs) -> str:
    """Complete read-only grammar, including dependency guards' C-locale adapter."""
    if set(kwargs) - {"env"}:
        raise RunError("standard_profile_query_unsupported")
    if argv in (
        ["ip", "-j", "link", "show"], ["ip", "-j", "address", "show"],
        ["ip", "-j", "-4", "route", "show", "table", "all"],
        ["ip", "-j", "-6", "route", "show", "table", "all"],
    ):
        return _run(["/usr/sbin/ip", *argv[1:]], readonly=True)
    if argv[:3] == ["virsh", "--connect", "qemu:///system"]:
        arguments = argv[3:]
        if arguments in (
            ["net-list", "--all", "--uuid"], ["net-list", "--uuid"],
            ["net-list", "--all", "--persistent", "--uuid"],
            ["list", "--all", "--uuid"], ["list", "--uuid"], ["list", "--all", "--persistent", "--uuid"],
        ):
            return _run(["/usr/bin/virsh", "--readonly", *argv[1:]], readonly=True)
        if (
            len(arguments) in (2, 3) and arguments[0] in ("net-dumpxml", "dumpxml", "domstate")
            and str(uuid.UUID(arguments[1])) == arguments[1]
            and (len(arguments) == 2 or arguments[0] != "domstate" and arguments[2] == "--inactive")
        ):
            return _run(["/usr/bin/virsh", "--readonly", *argv[1:]], readonly=True)
    raise RunError("standard_profile_query_unsupported")


def destroy_exact_network(identity: str) -> None:
    """The sole mutation grammar: synchronous exact UUID destroy, never undefine."""
    if not isinstance(identity, str) or str(uuid.UUID(identity)) != identity:
        raise RunError("standard_profile_target_invalid")
    _run(["/usr/bin/virsh", "--connect", "qemu:///system", "net-destroy", identity], readonly=False)


def controller(data: dict) -> dict:
    """Measure current trusted controller separately from missing historical annotations."""
    prefix = Path(sys.prefix)
    root = recovery.trusted_path(REPO)
    if prefix.parent != root / ".venv" or prefix.name not in recovery.CONTROLLERS:
        raise RunError("unsupported_standard_controller")
    python, ansible, molecule = recovery.CONTROLLERS[prefix.name]
    if tuple(sys.version_info[:2]) != python or sys.prefix == sys.base_prefix:
        raise RunError("unsupported_standard_controller")
    recovery.trusted_path(prefix)
    entry = Path(sys.argv[0]).absolute()
    if entry != root / "scripts/scenario-context" or recovery.trusted_path(entry) != entry:
        raise RunError("standard_controller_entry_changed")
    executable = Path(sys.executable)
    if executable.parent != prefix / "bin" or executable.name not in (
        "python", "python3", "python" + ".".join(map(str, python)),
    ):
        raise RunError("standard_controller_interpreter_changed")
    target = recovery.trusted_path(executable, interpreter_entry=True)
    actual = {"IDARSI_TEST_ENVIRONMENT": str(root), "VIRTUAL_ENV": str(prefix)}
    if any(os.environ.get(key) != value for key, value in actual.items()):
        raise RunError("standard_controller_activation_required")
    if any(key in os.environ for key in (
        "IDARSI_RUN_ID", "IDARSI_HANDOFF", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH",
        "LIBVIRT_DEFAULT_URI", "LIBVIRT_AUTH_FILE", "CONTAINER_HOST", "CONTAINER_CONNECTION",
    )):
        raise RunError("standard_controller_override_unsupported")
    missing = []
    for key, expected in actual.items():
        original = data["config"]["_idarsi_effective_env"]
        if key not in original:
            missing.append(key)
        elif original[key] != expected:
            raise RunError("historical_controller_annotation_conflicting")
    for action in ("create", "destroy"):
        paths = [
            data["config"].get(section, {}).get("playbooks", {}).get(action)
            for section in ("ansible", "provisioner")
            if data["config"].get(section, {}).get("playbooks", {}).get(action)
        ]
        if not paths:
            raise RunError("historical_managed_playbook_binding_unproven")
        for value in paths:
            path = Path(value)
            if not path.is_absolute():
                path = Path(data["role"]) / "molecule" / data["scenario"] / path
            if recovery.trusted_path(path) != root / "molecule/managed" / (action + ".yml"):
                raise RunError("historical_managed_playbook_binding_changed")
    tooling = {}
    for name, expected in (("ansible-core", ansible), ("molecule", molecule)):
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RunError("standard_controller_tooling_unavailable") from exc
        if distribution.version != expected:
            raise RunError("standard_controller_tooling_changed")
        origin = recovery.package_origin(Path(distribution.locate_file("")), prefix, python)
        tooling[name] = {"version": expected, "origin": str(origin)}
    sources = {}
    package = sys.modules[__package__]
    package_path = root / "scripts/isolated_runs"
    if Path(package.__file__) != package_path / "__init__.py" or list(package.__path__) != [str(package_path)]:
        raise RunError("standard_controller_module_origin_changed")
    for path in sorted((root / "scripts/isolated_runs").glob("*.py")):
        recovery.trusted_path(path)
        sources[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
        module = sys.modules.get(__package__ + "." + path.stem)
        if module is not None and Path(module.__file__) != path:
            raise RunError("standard_controller_module_origin_changed")
    sources["scripts/scenario-context"] = hashlib.sha256(entry.read_bytes()).hexdigest()
    return {
        "root": str(root), "prefix": str(prefix), "lane": prefix.name,
        "executable": str(executable), "interpreter_target": str(target),
        "interpreter_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "python": list(sys.version_info[:3]), "tooling": tooling, "sources": sources,
        "missing_historical_annotations": missing,
    }


def daemon_arguments(pid: int, identity: dict) -> list:
    """Read bounded actual argv while pinning and rechecking the exact daemon birth."""
    try:
        pin = os.pidfd_open(pid)
    except OSError as exc:
        raise RunError("standard_profile_daemon_arguments_unproven") from exc
    try:
        if processes.process(pid) != identity:
            raise RunError("standard_profile_daemon_birth_changed")
        fd = os.open(
            "/proc/" + str(pid) + "/cmdline",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
                raise RunError("standard_profile_daemon_arguments_unproven")
            content = stream.read(4097)
        if processes.process(pid) != identity:
            raise RunError("standard_profile_daemon_birth_changed")
        if not content or len(content) > 4096 or not content.endswith(b"\0"):
            raise RunError("standard_profile_daemon_arguments_unproven")
        arguments = content[:-1].split(b"\0")
        allowed = (
            [DAEMON.encode()], [DAEMON.encode(), b"--timeout", b"120"],
            [DAEMON.encode(), b"--timeout=120"],
        )
        if arguments not in allowed:
            raise RunError("standard_profile_daemon_arguments_unsupported")
        return [argument.decode("ascii") for argument in arguments]
    except OSError as exc:
        # Unreadable procfs is unknown, never an empty/default expansion.
        raise RunError("standard_profile_daemon_arguments_unproven") from exc
    finally:
        os.close(pin)


def service_arguments(service: dict) -> str:
    """Accept only the measured packaged fragment and its one known variable form."""
    command = service["ExecStart"]
    path = re.findall(r"(?:^|[ {;])path=([^;]*?)\s*;", command)
    arguments = re.findall(r"(?:^|[ {;])argv\[\]=([^;]*?)\s*;", command)
    allowed = (
        DAEMON, DAEMON + " --timeout 120", DAEMON + " --timeout=120",
        DAEMON + " $VIRTNETWORKD_ARGS",
    )
    if (
        service["FragmentPath"] != UNIT
        or service["DropInPaths"] not in ("", DROPIN)
        or service["TimeoutStopFailureMode"] != ("abort" if service["DropInPaths"] == DROPIN else "terminate")
        or path != [DAEMON] or len(arguments) != 1 or arguments[0] not in allowed
        or command.count("path=") != 1 or command.count("argv[]=") != 1
    ):
        raise RunError("standard_profile_service_unsupported")
    return arguments[0]


def rpm_file_digests(argv: list) -> dict:
    """Decode the same RPM file-digest inventory for the two fixed packages."""
    files = {}
    for line in _run(argv, readonly=True).splitlines():
        path, checksum = line.split("|", 1)
        if path in files:
            raise RunError("standard_profile_package_metadata_invalid")
        files[path] = checksum
    return files


def distribution_dropin(service: dict) -> dict:
    """Authenticate only Fedora's reviewed global timeout-abort policy, never ignore overrides."""
    selected = service["DropInPaths"]
    expected_mode = "abort" if selected == DROPIN else "terminate"
    if selected not in ("", DROPIN) or service["TimeoutStopFailureMode"] != expected_mode:
        raise RunError("standard_profile_dropin_unsupported")
    if not selected:
        return {"paths": [], "effective_timeout_stop_failure_mode": expected_mode}
    metadata = _run([
        "/usr/bin/rpm", "-qf", "--qf",
        "%{NAME}|%{VERSION}-%{RELEASE}|%{SOURCERPM}|%{FILEDIGESTALGO}", DROPIN,
    ], readonly=True)
    if metadata != f"systemd|{SYSTEMD_BUILD}|{SYSTEMD_SOURCE_RPM}|8":
        raise RunError("standard_profile_dropin_package_unsupported")
    files = rpm_file_digests([
        "/usr/bin/rpm", "-qf", "--qf", "[%{FILENAMES}|%{FILEDIGESTS}\\n]", DROPIN,
    ])
    if files.get(DROPIN) != DROPIN_SHA256:
        raise RunError("standard_profile_dropin_package_digest_changed")
    path = recovery_commands.root_path(Path(DROPIN))
    if path != Path(DROPIN):
        raise RunError("standard_profile_dropin_path_changed")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
            or before.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
            or before.st_size != DROPIN_BYTES
        ):
            raise RunError("standard_profile_dropin_file_untrusted")
        content = stream.read(DROPIN_BYTES + 1)
        after = os.fstat(stream.fileno())
        entry = path.lstat()
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if identity(before) != identity(after) or identity(before) != identity(entry):
        raise RunError("standard_profile_dropin_changed_during_read")
    if len(content) != DROPIN_BYTES or hashlib.sha256(content).hexdigest() != DROPIN_SHA256:
        raise RunError("standard_profile_dropin_bytes_changed")
    return {
        "paths": [DROPIN], "package": "systemd", "build": SYSTEMD_BUILD,
        "source_rpm": SYSTEMD_SOURCE_RPM, "sha256": DROPIN_SHA256, "bytes": DROPIN_BYTES,
        "effective_timeout_stop_failure_mode": expected_mode,
    }


def qualify_current_runtime() -> dict:
    """Measure installed bytes/service birth; never claim loaded-image or hook attestation."""
    release = recovery_commands.root_path(Path("/etc/os-release")).read_text()
    values = dict(line.split("=", 1) for line in release.splitlines() if "=" in line and not line.startswith("#"))
    if values.get("ID", "").strip('"') != "fedora" or values.get("VERSION_ID", "").strip('"') != "44":
        raise RunError("standard_profile_platform_unsupported")
    metadata = _run([
        "/usr/bin/rpm", "-q", "--qf",
        "%{NAME}|%{VERSION}-%{RELEASE}|%{SOURCERPM}|%{FILEDIGESTALGO}", PACKAGE,
    ], readonly=True)
    if metadata != f"{PACKAGE}|{BUILD}|{SOURCE_RPM}|8":
        raise RunError("standard_profile_build_unsupported")
    files = rpm_file_digests([
        "/usr/bin/rpm", "-q", "--qf", "[%{FILENAMES}|%{FILEDIGESTS}\\n]", PACKAGE,
    ])
    measured = {}
    for name in (DAEMON, DRIVER, UNIT):
        path = recovery_commands.root_path(Path(name))
        expected = files.get(name, "")
        if not re.fullmatch(r"[a-f0-9]{64}", expected) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RunError("standard_profile_installed_bytes_changed")
        measured[name] = expected
    if _run([DAEMON, "--version"], readonly=True) not in (
        "virtnetworkd (libvirt) 12.0.0", "/usr/bin/virtnetworkd (libvirt) 12.0.0",
    ):
        raise RunError("standard_profile_version_unsupported")
    service = {}
    for line in _run([
        "/usr/bin/systemctl", "show", "virtnetworkd.service", "--property=" + ",".join(PROPERTIES),
    ], readonly=True).splitlines():
        key, value = line.split("=", 1)
        if key in service:
            raise RunError("standard_profile_service_invalid")
        service[key] = value
    if (
        set(service) != set(PROPERTIES) or service["ActiveState"] != "active" or service["SubState"] != "running"
        or service["PrivateNetwork"] != "no" or service["NetworkNamespacePath"]
        or not re.fullmatch(r"[1-9][0-9]*", service["MainPID"])
    ):
        raise RunError("standard_profile_service_unsupported")
    declared_arguments = service_arguments(service)
    dropin = distribution_dropin(service)
    pid = int(service["MainPID"])
    identity = processes.process(pid)
    if not identity or identity["zombie"] or identity["uid"] != 0:
        raise RunError("standard_profile_daemon_birth_unproven")
    arguments = daemon_arguments(pid, identity)
    if declared_arguments != DAEMON + " $VIRTNETWORKD_ARGS" and declared_arguments != " ".join(arguments):
        raise RunError("standard_profile_daemon_arguments_conflicting")
    tools = {}
    for name in ("/usr/bin/virsh", "/usr/sbin/ip", "/usr/bin/rpm", "/usr/bin/systemctl"):
        path = recovery_commands.root_path(Path(name))
        tools[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    if processes.process(pid) != identity:
        raise RunError("standard_profile_daemon_birth_changed")
    return {
        "profile": PROFILE, "platform": "fedora44", "build": BUILD, "source_rpm": SOURCE_RPM,
        "installed_files": measured, "tools": tools,
        "service_digest": hashlib.sha256(json.dumps(service, sort_keys=True).encode()).hexdigest(),
        "daemon": {"pid": pid, "start": identity["start"], "boot": processes.boot_id()},
        "daemon_arguments": arguments,
        "distribution_dropin": dropin,
        "claims": dict(CLAIMS),
    }
