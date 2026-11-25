"""Installed Molecule parsing with private dependency scratch and existing state."""

import contextlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Iterator

from .backends import REPO
from .readonly import canonical, directory, read_file, read_molecule_state, strict_json
from .state import RunError
from .guest_refusal import GuestRefusal, checked, parse as parse_refusal, tagged

ENVIRONMENT_KEYS = ("PATH", "TMPDIR", "ANSIBLE_LOCAL_TEMP", "ANSIBLE_LOG_PATH")
LIMIT = 4 * 1024 * 1024


@tagged("AUTHORITY_PARSE")
def approved_controller(environment: dict) -> Path:
    prefix = Path(sys.prefix).resolve(strict=True)
    activation = environment.get("VIRTUAL_ENV")
    helper = environment.get("IDARSI_TEST_ENVIRONMENT")
    candidates = set()
    for lane in ("ansible-min", "ansible-current", "ansible-next"):
        try:
            candidates.add((REPO / ".venv" / lane).resolve(strict=True))
        except FileNotFoundError:
            continue
    if (
        not activation or not Path(activation).is_absolute()
        or Path(activation).resolve(strict=True) != prefix or prefix not in candidates
        or prefix == Path(sys.base_prefix).resolve(strict=True)
        or not helper or not Path(helper).is_absolute() or Path(helper).resolve(strict=True) != REPO
        or Path(sys.executable).absolute().parent.resolve(strict=True) != prefix / "bin"
        or not Path(sys.executable).is_file()
    ):
        raise RunError("Unbound approved controller")
    for name in ("ansible", "ansible-config"):
        executable = shutil.which(name, path=environment.get("PATH", ""))
        if (
            not executable or Path(executable).parent.resolve(strict=True) != prefix / "bin"
            or not Path(executable).is_file()
            or Path(executable).resolve(strict=True).parent != prefix / "bin"
        ):
            raise RunError("Unbound controller dependency")
    return prefix


@tagged("READONLY_STATE")
def prevalidate(role: Path, ephemeral: Path, environment: dict) -> list:
    directory(role)
    directory(ephemeral)
    directory(ephemeral / "inventory")
    read_molecule_state(ephemeral / "state.yml", LIMIT)
    prefix = approved_controller(environment)
    caches = []
    # Runtime(isolated=False) on the minimum lane has no cache directory.
    if importlib.metadata.version("molecule") != "6.0.3":
        caches.append(directory(prefix / ".ansible"))
        home = Path(environment.get("ANSIBLE_HOME", "~/.ansible")).expanduser()
        home = directory(home)
        caches.extend(directory(path) for path in (home, home / "roles", home / "collections"))
    return caches


def wrapper_source(real: Path, original_path: str, scratch: Path) -> str:
    return (
        "#!" + sys.executable + " -B\n"
        "import os, sys\n"
        "if sys.argv[1:] != ['dump']:\n    sys.exit(2)\n"
        "os.umask(0o077)\n"
        "environment = dict(os.environ)\n"
        "environment.update(" + repr({
            "PATH": original_path, "TMPDIR": str(scratch),
            "ANSIBLE_LOCAL_TEMP": str(scratch / "ansible-local"),
            "ANSIBLE_LOG_PATH": str(scratch / "dependency.log"),
        }) + ")\n"
        "os.execve(" + repr(str(real)) + ", [" + repr(str(real)) + ", 'dump'], environment)\n"
    )


@contextlib.contextmanager
def invocation_environment(original: dict) -> Iterator[None]:
    processing = {key: os.environ.get(key) for key in ENVIRONMENT_KEYS}
    try:
        for key in ENVIRONMENT_KEYS:
            if key in original:
                os.environ[key] = original[key]
            else:
                os.environ.pop(key, None)
        yield
    finally:
        for key, value in processing.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@tagged("READONLY_STATE")
def scratch_parent(environment: dict) -> Path:
    """Select an existing Linux temp parent without gettempdir probe writes."""
    parent = canonical(Path(environment.get("TMPDIR", "/tmp")))
    if not parent.is_dir() or not os.access(parent, os.W_OK | os.X_OK):
        raise RunError("Unusable existing temporary parent")
    return parent


@tagged("READONLY_STATE")
def parse_existing_configuration(role: Path, scenario: str, environment: dict, ephemeral: Path) -> dict:
    """No normal-parser temporary directory, initialization or producer writes."""
    prevalidate(role, ephemeral, environment)
    real = Path(shutil.which("ansible-config", path=environment["PATH"]))
    temporary_root = scratch_parent(environment)
    with tempfile.TemporaryDirectory(prefix="idarsi-guest-config-", dir=temporary_root) as value:
        scratch = Path(value)
        scratch.chmod(0o700)
        (scratch / "ansible-local").mkdir(mode=0o700)
        wrapper = scratch / "ansible-config"
        wrapper.write_text(wrapper_source(real, environment["PATH"], scratch))
        wrapper.chmod(0o700)
        protocol = scratch / "invocation.json"
        protocol.write_text(json.dumps({
            "environment": {key: environment[key] for key in ENVIRONMENT_KEYS if key in environment},
            "scratch": str(scratch), "ephemeral": str(ephemeral), "role": str(role),
        }))
        protocol.chmod(0o600)
        processing = {
            **environment, "PATH": str(scratch) + os.pathsep + environment["PATH"],
            "TMPDIR": str(scratch), "ANSIBLE_LOCAL_TEMP": str(scratch / "ansible-local"),
            "ANSIBLE_LOG_PATH": str(scratch / "bridge.log"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        try:
            child = subprocess.run(
                [sys.executable, "-B", str(REPO / "scripts/isolated_runs/molecule_config.py"),
                 str(role / "molecule" / scenario / "molecule.yml"),
                 "--existing-only", str(protocol)],
                env=processing, cwd=role, capture_output=True, timeout=60, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise GuestRefusal("PROCESS_SUPERVISION") from None
        if len(child.stdout) > LIMIT or len(child.stderr) > LIMIT:
            raise GuestRefusal("PROCESS_SUPERVISION")
        if type(child.returncode) is not int:
            raise GuestRefusal("UNKNOWN_REFUSAL")
        if child.returncode:
            if child.returncode < 0:
                raise GuestRefusal("PROCESS_SUPERVISION")
            if child.returncode == 1 and child.stdout in (b"", ""):
                raise GuestRefusal(parse_refusal(child.stderr))
            raise GuestRefusal("UNKNOWN_REFUSAL")
        data = checked("AUTHORITY_PARSE", strict_json, child.stdout)
        if not isinstance(data, dict):
            raise GuestRefusal("AUTHORITY_PARSE")
        # Reuse all normal shared-playbook, driver and shared-state postvalidation.
        from .cli import validate_configuration

        return checked("AUTHORITY_PARSE", validate_configuration, data, role / "molecule" / scenario / "molecule.yml")


def install_guard(scratch: Path, caches: list) -> None:
    """Subprocess-scoped rejection, not monkeypatching upstream writer functions."""
    def inside(path):
        if isinstance(path, int):
            return False
        path = Path(os.fsdecode(path)).absolute()
        if ".." in path.parts:
            return False
        resolved = path.resolve()
        return resolved == scratch or scratch in resolved.parents

    def audit(event, args):
        if event == "open":
            path, mode, flags = args
            writing = flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
            devnull = (
                path == os.devnull and flags & ~os.O_CLOEXEC == os.O_RDWR
                and stat.S_ISCHR(os.stat(path).st_mode)
            )
            if writing and not inside(path) and not devnull:
                raise GuestRefusal("READONLY_STATE")
        elif event == "os.mkdir":
            path = Path(os.fsdecode(args[0])).absolute()
            if not inside(path) and not (path in caches and path.is_dir() and not path.is_symlink()):
                raise GuestRefusal("READONLY_STATE")
        elif event in ("os.remove", "os.rmdir", "os.rename", "os.link", "os.symlink", "os.chmod", "os.truncate"):
            if not inside(args[0]) or (event in ("os.rename", "os.link", "os.symlink") and not inside(args[1])):
                raise GuestRefusal("READONLY_STATE")
        elif event == "subprocess.Popen":
            argv, environment = args[1], args[3]
            if argv == ["/sbin/ldconfig", "-p"]:
                return  # stdlib ctypes' read-only libc discovery, not a shell.
            if (
                not isinstance(argv, (list, tuple)) or len(argv) != 2
                or (Path(argv[0]).name, argv[1]) not in (("ansible", "--version"), ("ansible-config", "dump"))
                or environment is None or environment.get("ANSIBLE_LOCAL_TEMP") != str(scratch / "ansible-local")
                or environment.get("ANSIBLE_LOG_PATH") != str(scratch / "bridge.log")
            ):
                raise GuestRefusal("PROCESS_SUPERVISION")

    sys.addaudithook(audit)


@tagged("AUTHORITY_PARSE")
def bridge_main(source: str, protocol_path: str) -> None:
    """Private launch protocol; never exposed as guest-validation proof input."""
    sys.dont_write_bytecode = True
    os.umask(0o077)
    protocol = checked("AUTHORITY_PARSE", strict_json, checked("READONLY_STATE", read_file, Path(protocol_path), LIMIT))
    if set(protocol) != {"environment", "scratch", "ephemeral", "role"}:
        raise RunError("Invalid private bridge protocol")
    scratch = checked("READONLY_STATE", directory, Path(protocol["scratch"]), private=True)
    if Path(protocol_path).parent != scratch or Path(os.environ["TMPDIR"]) != scratch:
        raise RunError("Private scratch mismatch")
    original = protocol["environment"]
    role, ephemeral = Path(protocol["role"]), Path(protocol["ephemeral"])
    restored = dict(os.environ)
    for key in ENVIRONMENT_KEYS:
        restored.pop(key, None)
        if key in original:
            restored[key] = original[key]
    caches = prevalidate(role, ephemeral, restored)
    if Path(source).resolve(strict=True) != role / "molecule" / Path(source).parent.name / "molecule.yml":
        raise RunError("Invalid role source")
    install_guard(scratch, caches)
    # Imports and Runtime initialization remain in the processing environment.
    from molecule.config import Config
    from molecule.scenario import Scenario
    from molecule.state import State
    from molecule.shell import LOCAL_CONFIG
    from molecule import app, util
    from functools import cached_property

    if hasattr(app, "get_app"):
        app.get_app(Path())
        app.get_app(role)

    class ExistingScenario(Scenario):
        @property
        def ephemeral_directory(self):
            return str(ephemeral)

        def _setup(self):
            directory(Path(self.inventory_directory))

    class ExistingState(State):
        def __init__(self, config):
            self._config = config
            self._state_file = self._get_state_file()
            self._data = util.safe_load(checked("READONLY_STATE", read_molecule_state, Path(self._state_file), LIMIT).decode())
            if not isinstance(self._data, dict):
                raise RunError("Missing existing Molecule state")

        def _write_state_file(self):
            raise GuestRefusal("READONLY_STATE")

        def change_state(self, *args, **kwargs):
            raise GuestRefusal("READONLY_STATE")

        def reset(self):
            raise GuestRefusal("READONLY_STATE")

    class ExistingManagedConfig(Config):
        @cached_property
        def scenario(self):
            return ExistingScenario(self)

        @cached_property
        def state(self):
            return ExistingState(self)

        def _get_config(self):
            with invocation_environment(original):
                data = super()._get_config()
            if data.get("shared_state") or data.get("scenario", {}).get("shared_state"):
                raise RunError("Unsupported shared state")
            return data

        def _reget_config(self):
            with invocation_environment(original):
                return super()._reget_config()

        def _apply_env_overrides(self):
            with invocation_environment(original):
                return super()._apply_env_overrides()

        def write(self):
            raise GuestRefusal("READONLY_STATE")

    config = ExistingManagedConfig(
        source, args={
            "base_config": [LOCAL_CONFIG] if LOCAL_CONFIG else [],
            "env_file": os.environ.get("MOLECULE_ENV_FILE", ".env.yml"),
        }, command_args={"parallel": False},
    )
    if not hasattr(config, "config_data"):
        config.after_init()
        data = config.config
    else:
        data = config.config_data
    if (
        config.is_parallel or data.get("shared_state")
        or data.get("scenario", {}).get("shared_state")
        or data["scenario"]["test_sequence"] != config._get_defaults()["scenario"]["test_sequence"]
    ):
        raise RunError("Unsupported effective sequence")
    environment = dict(config.env)
    for key in ("VIRTUAL_ENV", "IDARSI_TEST_ENVIRONMENT"):
        if key in os.environ:
            environment[key] = os.environ[key]
    data.update(
        _idarsi_effective_ephemeral=str(config.scenario.ephemeral_directory),
        _idarsi_effective_scenario=config.scenario.name,
        _idarsi_effective_role=str(config.project_directory),
        _idarsi_effective_env=environment,
    )
    for key in (
        "MOLECULE_PROJECT_DIRECTORY", "MOLECULE_SCENARIO_DIRECTORY", "MOLECULE_SCENARIO_NAME",
        "MOLECULE_EPHEMERAL_DIRECTORY", "MOLECULE_FILE", "MOLECULE_INSTANCE_CONFIG",
    ):
        if key not in os.environ or os.environ[key] != environment[key]:
            raise RunError("Effective selector mismatch")
    sys.__stdout__.write(json.dumps(data) + "\n")
    sys.__stdout__.flush()
