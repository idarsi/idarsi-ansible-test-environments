"""Thin stdlib CLI; Ansible supplies the project's existing YAML parser."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
import tempfile

from .backends import Backend, REPO, validate_platforms
from .discovery import command, discover, podman_context
from .processes import spawn, stop_workers
from .state import RunError, Store, atomic_json, lock


def parse_configuration(role: Path, scenario: str, environment: dict) -> dict:
    """Validate the actual installed Molecule's merged, interpolated config."""
    source = role / "molecule" / scenario / "molecule.yml"
    with tempfile.TemporaryDirectory(prefix="idarsi-config-") as temporary:
        effective_environment = dict(
            environment, MOLECULE_EPHEMERAL_DIRECTORY=str(Path(temporary) / "ephemeral"),
        )
        data = json.loads(command(
            ["python3", str(REPO / "scripts/isolated_runs/molecule_config.py"), str(source)],
            env=effective_environment, cwd=str(role),
        ))
    if not isinstance(data, dict):
        raise RunError("Scenario config must be a mapping")
    if data.get("driver", {}).get("name") != "default":
        raise RunError("Managed runs require the default driver, never the legacy Podman driver")
    if data.get("driver", {}).get("options", {}).get("managed", True) is not True:
        raise RunError("Managed runs require driver.options.managed: true")
    for action in ("create", "destroy"):
        expected = REPO / "molecule/managed" / (action + ".yml")
        configured = []
        for section in ("ansible", "provisioner"):
            value = data.get(section, {}).get("playbooks", {}).get(action)
            if value:
                path = Path(value)
                if not path.is_absolute():
                    path = source.parent / path
                configured.append(path.resolve())
        if not configured or any(path != expected for path in configured):
            raise RunError("Scenario must use shared managed " + action + ".yml")
    if data.get("shared_state") or data.get("scenario", {}).get("shared_state"):
        raise RunError("Molecule shared_state is not supported for managed runs")
    return data


def cleanup_locked(store: Store, run_id: str) -> None:
    """Caller owns the supervisor lock; stop workers before resource mutation."""
    data = store.load(run_id)
    if data["status"] == "cleaned":
        return
    # Do not write even a status here: a lifecycle worker may still be
    # committing ownership intent. Failure to stop it leaves the journal alone.
    stop_workers(data)
    with lock(store.directory(run_id) / ".resources.lock", blocking=False):
        cleanup_resources_locked(store, run_id)


def cleanup_resources_locked(store: Store, run_id: str) -> None:
    """Workers are stopped and the resource lock is held for every journal write."""
    data = store.load(run_id)
    data["status"] = "cleaning"
    store.save(data)
    try:
        backend = Backend(store, data)
        backend.destroy_guests()
        backend.destroy_network()
        with lock(store.root / ".allocator.lock"):
            data["status"] = "cleaned"
            store.save(data)
    except (RunError, OSError, ValueError, KeyError, TypeError) as exc:
        data = store.load(run_id)
        data["status"] = "cleanup_failed"
        data["error"] = str(exc)
        store.save(data)
        raise


def cleanup(store: Store, run_id: str) -> None:
    with lock(store.directory(run_id) / ".supervisor.lock", blocking=False):
        cleanup_locked(store, run_id)


def lifecycle(store: Store, action: str, run_id: str) -> None:
    """Internal synchronous Molecule adapter, never a standalone retained run."""
    if os.environ.get("IDARSI_RUN_ID") != run_id:
        raise RunError("Lifecycle actions require the supervisor environment")
    with lock(store.directory(run_id) / ".resources.lock"):
        data = store.load(run_id)
        if data["status"] != "running":
            raise RunError("Run is not in supervised running state")
        backend = Backend(store, data)
        if action == "destroy":
            # A timed-out tool can leave same-session libguestfs/QEMU children.
            # Molecule's failure destroy runs *inside* that session and cannot
            # safely quiesce it (it includes Molecule itself). Defer ALL removal
            # to the outer supervisor, which stops the journalled session first.
            # This adapter supports one full test, never retained create/destroy.
            instances = []
        else:
            platforms = data["config"]["platforms"]
            instances = backend.create(platforms)
        destination = Path(os.environ["MOLECULE_INSTANCE_CONFIG"])
        ephemeral = store.ephemeral(run_id)
        if destination.parent.resolve() != ephemeral.resolve():
            raise RunError("Instance configuration is outside the run ephemeral directory")
        # JSON is valid YAML and accepted by all supported Molecule versions.
        atomic_json(destination, instances)


def run(args, store: Store) -> int:
    role = Path(args.role).resolve(strict=True)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.scenario):
        raise RunError("Invalid scenario name")
    for executable in ("molecule", "ansible-playbook", "podman", "virsh", "ip"):
        if not shutil.which(executable):
            raise RunError("Required tool is missing from the approved environment: " + executable)
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RunError("Linux pidfds and Python 3.9+ are required")
    environment = managed_environment()
    config = parse_configuration(role, args.scenario, environment)
    config["platforms"] = validate_platforms(
        args.backend, config.get("platforms"), role / "molecule" / args.scenario,
    )
    context = {"podman": podman_context(), "libvirt": "qemu:///system"}
    data = store.allocate(args.backend, context, discover, role, args.scenario)
    run_id = data["id"]
    print("Run ID: " + run_id, flush=True)
    directory = store.directory(run_id)
    with lock(directory / ".supervisor.lock", blocking=False):
        # Recovery may have acquired this lock immediately after allocation.
        # Never revive a lease it released while we were waiting to supervise.
        data = store.load(run_id)
        if data["status"] != "allocated":
            raise RunError("Run was recovered before supervision started; start a new run")
        data["config"] = config
        data["status"] = "running"
        store.save(data)
        environment.update(
            IDARSI_RUN_ID=run_id, MOLECULE_EPHEMERAL_DIRECTORY=str(store.ephemeral(run_id)),
        )
        # Do not let an inherited role/scenario identity contaminate this invocation.
        for key in ("MOLECULE_FILE", "MOLECULE_INSTANCE_CONFIG", "MOLECULE_SCENARIO_DIRECTORY"):
            environment.pop(key, None)
        cancelled = []

        def interrupt(signum, frame):
            del frame
            cancelled.append(signum)

        previous = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGINT, signal.SIGTERM)}
        result = 1
        child = None
        try:
            child = spawn(
                store, data, ["molecule", "test", "--scenario-name", args.scenario],
                environment, str(role),
            )
            import time

            while child.poll() is None and not cancelled:
                time.sleep(0.1)
            if cancelled:
                stop_workers(store.load(run_id))
                child.wait(timeout=5)
                result = 128 + cancelled[0]
            else:
                result = child.returncode
                if result < 0:
                    result = 128 - result
        finally:
            try:
                cleanup_locked(store, run_id)
            except (RunError, OSError, ValueError, KeyError, TypeError) as exc:
                print("Cleanup failed; lease retained: " + str(exc), file=sys.stderr)
                result = result or 1
            finally:
                if child is not None and child.poll() is not None:
                    child.wait()
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
        return result


def managed_environment() -> dict:
    """Remove inherited CLI defaults, including min's truthy 'false' parallel flag."""
    environment = {key: value for key, value in os.environ.items() if not key.startswith("MOLECULE_")}
    environment.update(IDARSI_TEST_ENVIRONMENT=str(REPO), LC_ALL="C.UTF-8")
    return environment


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Supervise isolated same-user Molecule test runs")
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("run", help="Run the full Molecule test sequence")
    start.add_argument("--backend", choices=("kvm", "podman"), required=True)
    start.add_argument("--scenario", required=True)
    start.add_argument("role", nargs="?", default=".", help="Role checkout (default: cwd)")
    commands.add_parser("list")
    for name in ("inspect", "cleanup"):
        commands.add_parser(name).add_argument("run_id")
    reap = commands.add_parser("reap", help="Explicit recovery; never age-based")
    mode = reap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    internal = commands.add_parser("_lifecycle", help="Internal synchronous lifecycle adapter")
    internal.add_argument("action", choices=("create", "destroy"))
    internal.add_argument("run_id")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        store = Store()
        if args.command == "run":
            return run(args, store)
        if args.command == "inspect":
            print(json.dumps(store.load(args.run_id), indent=2))
        elif args.command == "list":
            for data in store.runs():
                print(data["id"], data["backend"], data["status"], data["subnet"], data["scenario"])
        elif args.command == "cleanup":
            cleanup(store, args.run_id)
        elif args.command == "_lifecycle":
            lifecycle(store, args.action, args.run_id)
        else:
            failed = False
            for data in store.runs():
                if data["status"] == "cleaned":
                    continue
                try:
                    with lock(store.directory(data["id"]) / ".supervisor.lock", blocking=False):
                        print(data["id"], "recovery requested" if args.apply else "unlocked; explicit recovery candidate")
                        if args.apply:
                            cleanup_locked(store, data["id"])
                except RunError as exc:
                    print(data["id"], str(exc), file=sys.stderr)
                    failed = True
            return int(failed)
    except (RunError, OSError, ValueError, KeyError, TypeError) as exc:
        print("test-run: " + str(exc), file=sys.stderr)
        return 1
    return 0
