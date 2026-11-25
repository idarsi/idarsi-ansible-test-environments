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
import uuid
import xml.etree.ElementTree as ET

from .backends import Backend, REPO, validate_platforms
from . import admission
from .discovery import command, discover, podman_context
from .processes import spawn, stop_workers
from .state import RunError, Store, atomic_json, lock


def parse_configuration(role: Path, scenario: str, environment: dict, direct: bool = False) -> dict:
    """Validate the actual installed Molecule's merged, interpolated config."""
    source = role / "molecule" / scenario / "molecule.yml"
    with tempfile.TemporaryDirectory(prefix="idarsi-config-") as temporary:
        effective_environment = dict(environment)
        if not direct:
            effective_environment["MOLECULE_EPHEMERAL_DIRECTORY"] = str(Path(temporary) / "ephemeral")
        response = command(
            ["python3", str(REPO / "scripts/isolated_runs/molecule_config.py"), str(source)]
            + ([] if direct else ["--supervised"]),
            env=effective_environment, cwd=str(role),
        )
        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            reason = "empty" if not response.strip() else "malformed"
            raise RunError("Molecule config bridge returned " + reason + " JSON response") from None
    return validate_configuration(data, source)


def validate_configuration(data, source):
    """Shared postvalidation, independent of how installed Molecule was invoked."""
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
    """Caller owns supervisor; drain admitted mutations, stop workers, then clean."""
    data = store.load(run_id)
    if data["status"] == "cleaned":
        return
    if "mutation_protocol" in data and data["mutation_protocol"] != "sealed-v1":
        raise RunError("Unsupported mutation protocol; retaining resources and lease")
    if data.get("mode") == "direct":
        from .context import require_completed

        stop_workers(data)
        with lock(store.directory(run_id) / ".resources.lock", blocking=False):
            require_completed(store.load(run_id))
        raise RunError(
            "Direct generation: use scenario-context inspect/destroy for its bound context; "
            "incomplete mutations permit inspection only"
        )
    # Do not write even a status here: a lifecycle worker may still be
    # committing ownership intent. Failure to stop it leaves the journal alone.
    if "admission_protocol" in data:
        from .cooperative_stop import drain_mutations

        # Closing admission alone is not a cancellation barrier. A normal Stop
        # must let the admitted create finish and seal before stopping sessions.
        data = drain_mutations(store, run_id)
    stop_workers(data)
    if data.get("mutation_protocol") == "sealed-v1":
        cleanup_sealed_locked(store, run_id)
        return
    with lock(store.directory(run_id) / ".resources.lock", blocking=False):
        cleanup_resources_locked(store, run_id)


def cleanup_sealed_locked(store: Store, run_id: str) -> None:
    """Supervisor-owned new protocol: no cleanup after an uncertain mutation."""
    from .context import require_completed

    with lock(store.directory(run_id) / ".resources.lock", blocking=False):
        data = store.load(run_id)
        require_completed(data)
        operation = {"id": str(uuid.uuid4()), "action": "destroy", "purpose": "supervisor-cleanup"}
        data["operations"].append(operation)
        data["status"] = "cleaning"
        child = spawn(
            store, data,
            [sys.executable, str(REPO / "scripts/scenario-context"), "_worker",
             run_id, operation["id"], "destroy"],
            dict(os.environ), str(REPO), operation=operation,
        )
    # The cleanup worker must acquire resources itself; never wait holding them.
    code = child.wait()
    stop_workers(store.load(run_id))
    with lock(store.directory(run_id) / ".resources.lock", blocking=False):
        data = store.load(run_id)
        require_completed(data)
        if code or data["status"] != "destroyed":
            raise RunError("Cleanup worker failed; retaining resources and lease")
        with lock(store.root / ".allocator.lock"):
            data["status"] = "cleaned"
            store.save(data)


def cleanup_resources_locked(store: Store, run_id: str) -> None:
    """Workers are stopped and the resource lock is held for every journal write."""
    data = store.load(run_id)
    if data.get("mode") == "direct" or "mutation_protocol" in data:
        raise RunError("Sealed cleanup requires its journalled scenario-context mutation worker")
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
    data = store.load(run_id)
    if data["status"] == "cleaned":
        return
    if data.get("mode") == "direct" and data.get("context_publication") == "pending":
        from .context import recover_unpublished

        recover_unpublished(store, run_id)
        return
    with lock(store.directory(run_id) / ".supervisor.lock", blocking=False):
        cleanup_locked(store, run_id)


def lifecycle(store: Store, action: str, run_id: str) -> None:
    """Internal synchronous Molecule adapter, never a standalone retained run."""
    if os.environ.get("IDARSI_RUN_ID") != run_id:
        raise RunError("Lifecycle actions require the supervisor environment")
    from .context import require_completed, resolved

    binding = store.load(run_id)
    resolved(argparse.Namespace(
        role=binding["role"], scenario=binding["scenario"], backend=binding["backend"],
    ), store)
    with lock(store.directory(run_id) / ".resources.lock"):
        data = store.load(run_id)
        if data["status"] != "running":
            raise RunError("Run is not in supervised running state")
        if "mutation_protocol" in data and data["mutation_protocol"] != "sealed-v1":
            raise RunError("Unsupported mutation protocol")
        if "admission_protocol" in data:
            expected = {
                key: binding[key] for key in ("id", "role", "scenario", "backend")
            }
            expected["ephemeral"] = str(store.ephemeral(run_id).resolve())
            with admission.mutation_boundary(store, run_id, expected) as (data, worker):
                if action == "destroy":
                    from .context import mapping

                    mapping({"ephemeral_directory": expected["ephemeral"]}, [])
                    return
                require_completed(data, quiescent=False)
                operation_id = str(uuid.uuid4())
                data["operations"].append({
                    "id": operation_id, "action": "create", "worker": worker,
                })
                store.save(data)
            from .cooperative_stop import CreateStopped, seal_stopped_create

            try:
                instances = Backend(store, data).create(data["config"]["platforms"])
            except CreateStopped as stopped:
                seal_stopped_create(store, run_id, operation_id, stopped)
                raise RunError(
                    "Create stopped cooperatively before readiness; "
                    "the supervisor will clean the owned resources"
                ) from stopped
            from .context import mapping

            mapping({"ephemeral_directory": expected["ephemeral"]}, instances)
            data = store.load(run_id)
            if data["operations"][-1]["id"] != operation_id:
                raise RunError("Create mutation journal changed before completion")
            data["operations"][-1]["completion"] = operation_id
            data["instances_ready"] = instances
            store.save(data)
            return
        backend = Backend(store, data)
        if action == "destroy":
            # A timed-out tool can leave same-session libguestfs/QEMU children.
            # Molecule's failure destroy runs *inside* that session and cannot
            # safely quiesce it (it includes Molecule itself). Defer ALL removal
            # to the outer supervisor, which stops the journalled session first.
            # This adapter supports one full test, never retained create/destroy.
            instances = []
        else:
            operation_id = None
            if data.get("mutation_protocol") == "sealed-v1":
                require_completed(data, quiescent=False)
                operation_id = str(uuid.uuid4())
                worker = next(
                    worker for worker in data["workers"] if worker["pid"] == os.getsid(0)
                )
                data["operations"].append({
                    "id": operation_id, "action": "create", "worker": worker,
                })
                store.save(data)
            platforms = data["config"]["platforms"]
            instances = backend.create(platforms)
        destination = Path(os.environ["MOLECULE_INSTANCE_CONFIG"])
        ephemeral = store.ephemeral(run_id)
        if destination.parent.resolve() != ephemeral.resolve():
            raise RunError("Instance configuration is outside the run ephemeral directory")
        # JSON is valid YAML and accepted by all supported Molecule versions.
        atomic_json(destination, instances)
        if action == "create" and operation_id is not None:
            data = store.load(run_id)
            if data["operations"][-1]["id"] != operation_id:
                raise RunError("Create mutation journal changed before completion")
            data["operations"][-1]["completion"] = operation_id
            data["instances_ready"] = instances
            store.save(data)


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
    # Public control identity: first stdout line, flushed before ANY worker.
    # Consumers latch it once; later worker output must never replace it.
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
        data["mode"] = "supervised"
        data["mutation_protocol"] = "sealed-v1"
        data["operations"] = []
        data["admission_protocol"] = admission.PROTOCOL
        admission.initialize(store, run_id)
        store.save(data)
        environment.update(
            IDARSI_RUN_ID=run_id, MOLECULE_EPHEMERAL_DIRECTORY=str(store.ephemeral(run_id)),
            IDARSI_HANDOFF="v1",
            IDARSI_MOLECULE_BACKEND=args.backend,
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
    if any(key == "IDARSI_RUN_ID" or key.startswith("IDARSI_HANDOFF") for key in os.environ):
        raise RunError("Cannot start a supervisor from an inherited supervised handoff")
    helper = os.environ.get("IDARSI_TEST_ENVIRONMENT")
    if helper is not None:
        try:
            valid = bool(helper) and Path(helper).is_absolute() and Path(helper).resolve(strict=True) == REPO
        except (OSError, RuntimeError, ValueError):
            valid = False
        if not valid:
            raise RunError("Supervised runs require the activated shared helper binding")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("MOLECULE_")}
    environment.update(LC_ALL="C.UTF-8")
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
    recovery = commands.add_parser(
        "recover-destroy", help="Exact supervised KVM network-tail recovery; no force or automatic maintenance",
        description=(
            "Boot-fenced absence-only recovery. Absent historical controller environment "
            "annotations use measured canonical ansible-current context; conflicting values "
            "refuse. Preparation writes a new current-host observation, not historical proof "
            "or reboot authorization."
        ),
    )
    recovery.add_argument("run_id")
    recovery.add_argument("--operation", required=True)
    recovery_mode = recovery.add_mutually_exclusive_group(required=True)
    recovery_mode.add_argument("--dry-run", action="store_true")
    recovery_mode.add_argument("--apply", action="store_true")
    recovery_mode.add_argument(
        "--prepare-maintenance", action="store_true",
        help="Write a current-host audit observation only; never reboot or clean resources",
    )
    reap = commands.add_parser("reap", help="Explicit recovery; never age-based")
    mode = reap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    internal = commands.add_parser("_lifecycle", help="Internal synchronous lifecycle adapter")
    internal.add_argument("action", choices=("create", "destroy"))
    internal.add_argument("run_id")
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.command == "recover-destroy":
        from . import recovery
        from .recovery_host import canonical_uuid

        identity = {}
        store = None
        try:
            canonical_uuid(args.run_id)
            canonical_uuid(args.operation)
            identity = {"run_id": args.run_id, "operation": args.operation}
            store = Store.open_existing()
            action = recovery.prepare if args.prepare_maintenance else (
                recovery.apply if args.apply else recovery.inspect
            )
            result = action(store, args.run_id, args.operation)
            print(json.dumps(result, sort_keys=True))
            return 0 if result.get("eligible") or result.get("outcome") == "maintenance_prepared" else 1
        except (RunError, OSError, ValueError, KeyError, TypeError, AttributeError, ET.ParseError) as exc:
            # Do not publish backend stderr, private config, paths or journals.
            reason = str(exc) if isinstance(exc, RunError) else "recovery_validation_failed"
            if isinstance(exc, ET.ParseError):
                reason = "network_inventory_xml_invalid"
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", reason):
                reason = "recovery_probe_failed"
            outcome = "blocked"
            if store is not None and args.apply and identity:
                try:
                    current = store.load(args.run_id)
                    if current.get("recoveries", {}).get("attempts") and current.get("status") != "cleaned":
                        outcome = "partial"
                except (RunError, OSError, ValueError, KeyError, TypeError, AttributeError):
                    pass
            print(json.dumps({
                **identity, "eligible": False,
                "outcome": outcome, "blockers": [reason],
            }, sort_keys=True))
            return 1
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
                    if args.apply:
                        cleanup(store, data["id"])
                        print(data["id"], "recovery requested")
                    else:
                        with lock(store.directory(data["id"]) / ".supervisor.lock", blocking=False):
                            print(data["id"], "unlocked; explicit recovery candidate")
                except RunError as exc:
                    print(data["id"], str(exc), file=sys.stderr)
                    failed = True
            return int(failed)
    except (RunError, OSError, ValueError, KeyError, TypeError) as exc:
        print("test-run: " + str(exc), file=sys.stderr)
        return 1
    return 0
