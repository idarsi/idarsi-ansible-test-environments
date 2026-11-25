"""Persistent direct contexts and fail-closed supervised lifecycle bindings."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

from .backends import Backend, REPO, validate_platforms
from . import admission
from . import guest_control
from .cli import lifecycle, parse_configuration
from .discovery import discover, podman_context
from .processes import members, spawn, stop_workers
from .state import RunError, Store, atomic_json, lock, private_directory

SCHEMA = "idarsi.scenario-context/v1"


def read_private(path: Path) -> dict:
    """Read an authoritative pointer without following substituted files."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
        ):
            raise RunError("Unsafe context pointer")
        return json.load(stream)


def require_completed(data: dict, quiescent: bool = True) -> None:
    """A negative backend query is never proof of cancellation."""
    for operation in data.get("operations", []):
        if (
            operation.get("completion") != operation["id"]
            or operation.get("action") not in ("create", "destroy") + guest_control.ACTIONS
            or operation.get("worker") not in data["workers"]
        ):
            raise RunError(
                "Incomplete mutation " + operation["id"]
                + "; retain resources and lease. Recovery is inspection-only; "
                "a backend-specific cancellation barrier is not implemented."
            )
        if operation["action"] in guest_control.ACTIONS:
            guest_control.validate_operation(operation, data)
    if quiescent and any(members(worker) for worker in data["workers"]):
        raise RunError("Mutation worker session is not empty")


def resolved(args: argparse.Namespace, store: Store, *, existing_config=None, _existing_lock=None) -> tuple:
    """Resolve actual effective identity; never replace the direct ephemeral."""
    role = Path(args.role).resolve(strict=True)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.scenario):
        raise RunError("Invalid scenario name")
    config = existing_config if existing_config is not None else parse_configuration(
        role, args.scenario, dict(os.environ), direct=True,
    )
    config["platforms"] = validate_platforms(
        args.backend, config.get("platforms"), role / "molecule" / args.scenario,
    )
    backends = [
        config.get(section, {}).get("env", {}).get("IDARSI_MOLECULE_BACKEND")
        for section in ("ansible", "provisioner")
    ]
    if args.backend not in backends or any(value and value != args.backend for value in backends):
        raise RunError("Effective scenario must declare the matching IDARSI_MOLECULE_BACKEND")
    if config["_idarsi_effective_scenario"] != args.scenario:
        raise RunError("Effective scenario identity mismatch")
    if Path(config["_idarsi_effective_role"]).resolve() != role:
        raise RunError("Effective role identity mismatch")
    ephemeral = Path(config["_idarsi_effective_ephemeral"])
    if not ephemeral.is_absolute() or ephemeral == Path("/") or ephemeral.is_symlink():
        raise RunError("Unsafe effective Molecule ephemeral directory")
    ephemeral = ephemeral.resolve()
    if str(ephemeral / "collections" / "*") not in config.get("driver", {}).get("safe_files", []):
        raise RunError(
            "driver.safe_files must preserve ${MOLECULE_EPHEMERAL_DIRECTORY}/collections/*"
        )
    for target in (ephemeral, ephemeral / "collections"):
        if target.is_symlink():
            raise RunError("Collection destination must not be a symlink")
        if target.exists():
            info = target.lstat()
            if (
                not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022
            ):
                raise RunError("Unsafe Molecule collection destination")
    supplied = os.environ.get("MOLECULE_EPHEMERAL_DIRECTORY")
    if supplied and Path(supplied).resolve() != ephemeral:
        raise RunError("Molecule ephemeral binding mismatch")
    source = os.environ.get("MOLECULE_FILE")
    if source and Path(source).resolve() != Path(config["_idarsi_effective_env"]["MOLECULE_FILE"]).resolve():
        raise RunError("Molecule role/scenario binding mismatch")
    for key, expected in (
        ("MOLECULE_PROJECT_DIRECTORY", role),
        ("MOLECULE_SCENARIO_DIRECTORY", role / "molecule" / args.scenario),
    ):
        if os.environ.get(key) and Path(os.environ[key]).resolve() != expected:
            raise RunError("Molecule project/scenario directory binding mismatch")
    result = {
        "schema": SCHEMA, "mode": "direct", "role": str(role),
        "scenario": args.scenario, "backend": args.backend,
        "ephemeral_directory": str(ephemeral),
        "collections_directory": str(ephemeral / "collections"), "generation": None,
        "lifecycle_modes": ["direct", "supervised"], "effective_config_validated": True,
    }
    if args.backend == "kvm":
        result.update(
            guest_control_protocol=guest_control.PROTOCOL,
            guest_control_actions=list(guest_control.ACTIONS),
        )
    markers = any(
        key == "IDARSI_RUN_ID" or key.startswith("IDARSI_HANDOFF")
        for key in os.environ
    )
    if not markers and (
        ephemeral.is_relative_to(store.root.resolve())
        or store.root.resolve().is_relative_to(ephemeral)
        or role.is_relative_to(ephemeral)
    ):
        raise RunError("Direct ephemeral must be disjoint from authoritative state and not contain the role")
    if markers:
        if (
            os.environ.get("IDARSI_HANDOFF") != "v1" or not os.environ.get("IDARSI_RUN_ID")
            or any(key.startswith("IDARSI_HANDOFF") and key != "IDARSI_HANDOFF" for key in os.environ)
        ):
            raise RunError("Partial or unsupported supervised handoff")
        data = store.load(os.environ["IDARSI_RUN_ID"])
        for field, valid in (
            ("mode", data.get("mode") != "direct"), ("status", data["status"] == "running"),
            ("role", data["role"] == str(role)), ("scenario", data["scenario"] == args.scenario),
            ("backend", data["backend"] == args.backend),
            ("ephemeral", store.ephemeral(data["id"]).resolve() == ephemeral),
        ):
            if not valid:
                raise RunError("Supervised binding mismatch: " + field)
        if "admission_protocol" in data:
            authorize = admission.authorize if existing_config is None else admission.validate_existing
            expected = {
                "id": data["id"], "role": str(role), "scenario": args.scenario,
                "backend": args.backend, "ephemeral": str(ephemeral),
            }
            if existing_config is not None and _existing_lock is not None:
                authorize(store, data["id"], expected, _existing_lock=_existing_lock)
            else:
                authorize(store, data["id"], expected)
        elif not any(
                member["session"] == os.getsid(0)
                for worker in data["workers"] for member in members(worker)
        ):
            raise RunError("Supervised binding mismatch: session")
        result.update(mode="supervised", generation=data["id"])
    return result, config


def pointer_path(store: Store, result: dict) -> tuple:
    path, identity = existing_pointer_path(store, result)
    private_directory(path.parent)
    return path, identity


def existing_pointer_path(store: Store, result: dict) -> tuple:
    """Compute the direct identity without initializing its directory or locks."""
    identity = {key: result[key] for key in (
        "role", "scenario", "backend", "ephemeral_directory",
    )}
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    return store.root / ".contexts" / (key + ".json"), identity


def mapping(result: dict, instances: list) -> None:
    """Write only Molecule's real current ephemeral instance configuration."""
    ephemeral = Path(result["ephemeral_directory"])
    if not ephemeral.is_dir() or ephemeral.is_symlink():
        raise RunError("Molecule ephemeral directory must already exist")
    value = os.environ.get("MOLECULE_INSTANCE_CONFIG")
    if not value:
        raise RunError("MOLECULE_INSTANCE_CONFIG is required for lifecycle actions")
    destination = Path(value)
    if (
        not destination.is_absolute() or destination.parent.resolve() != ephemeral
        or destination.is_symlink() or destination.name == "collections"
    ):
        raise RunError("Instance configuration is outside the actual ephemeral directory")
    atomic_json(destination, instances)


def recover_unpublished(store: Store, run_id: str) -> None:
    """Release only an unpublished direct allocation with no mutation history."""
    data = store.load(run_id)
    path, identity = pointer_path(store, data["direct_context"])
    with lock(path.with_suffix(".lock"), blocking=False):
        with lock(store.directory(run_id) / ".supervisor.lock", blocking=False):
            with lock(store.directory(run_id) / ".resources.lock", blocking=False):
                data = store.load(run_id)
                if (
                    data.get("mode") != "direct" or data.get("context_publication") != "pending"
                    or data.get("direct_identity") != identity or data["status"] != "running"
                    or data.get("operations") != [] or data["workers"] != []
                    or data["guests"] != [] or data["network"] is not None
                    or data.get("storage_probe") or data.get("instances_ready")
                ):
                    raise RunError("Allocation is not proven unpublished and never mutated")
                if path.exists() or path.is_symlink():
                    pointer = read_private(path)
                    if (
                        pointer["identity"] != identity or pointer["generation"] == run_id
                        or store.load(pointer["generation"])["status"] != "cleaned"
                    ):
                        raise RunError("Context is published or points to an active generation")
                with lock(store.root / ".allocator.lock"):
                    data["status"] = "cleaned"
                    store.save(data)


def worker(store: Store, run_id: str, operation_id: str, action: str) -> None:
    """Only the durable gated session may mutate a direct generation."""
    if action not in ("create", "destroy") + guest_control.ACTIONS:
        raise RunError("Unsupported mutation worker action")
    with lock(store.directory(run_id) / ".resources.lock"):
        data = store.load(run_id)
        operation = data["operations"][-1]
        if (
            (data.get("mode") != "direct" and data.get("mutation_protocol") != "sealed-v1")
            or operation["id"] != operation_id
            or operation["action"] != action or operation.get("completion")
            or operation.get("worker") not in data["workers"]
            or not any(
                member["session"] == os.getsid(0)
                for member in members(operation["worker"])
            )
        ):
            raise RunError("Invalid direct mutation worker binding")
        if "admission_protocol" in data:
            admission.cleanup_boundary(store, run_id, operation)
        result = data.get("direct_context")
        if action in guest_control.ACTIONS:
            if data.get("mode") != "direct" or result is None:
                raise RunError("Guest worker requires a direct generation")
            history = dict(data, operations=data["operations"][:-1])
            guest_control.target(history, result, data["config"], operation["guest"])
            outcome = guest_control.execute(store, data, operation)
            guest_control.seal(store, run_id, operation, outcome)
            return
        if action == "create":
            instances = Backend(store, data).create(data["config"]["platforms"])
            if result is not None:
                mapping(result, instances)
            data["instances_ready"] = instances
            store.save(data)
        elif action == "destroy":
            backend = Backend(store, data)
            backend.destroy_guests()
            backend.destroy_network()
            if result is not None:
                mapping(result, [])
        # Reload: backend journal writes must never be overwritten by stale data.
        data = store.load(run_id)
        data["operations"][-1]["completion"] = operation_id
        if action == "destroy":
            # The controller releases the lease only after the sealed session exits.
            data["status"] = "destroyed"
            data.pop("instances_ready", None)
        store.save(data)


def direct(args: argparse.Namespace, store: Store, result: dict, config: dict) -> dict:
    path, identity = pointer_path(store, result)
    with lock(path.with_suffix(".lock")):
        data = None
        if path.exists() or path.is_symlink():
            pointer = read_private(path)
            if pointer["identity"] != identity:
                raise RunError("Direct context identity mismatch")
            data = store.load(pointer["generation"])
            if data.get("direct_identity") != identity or data.get("mode") != "direct":
                raise RunError("Direct generation provenance mismatch")
            if data["status"] != "cleaned":
                result["generation"] = data["id"]
            else:
                data = None
        if args.action in ("resolve", "capabilities", "inspect"):
            if data is not None and args.action == "inspect":
                result["manifest"] = data
            return result
        if data is None:
            if args.action == "destroy":
                mapping(result, [])
                return result
            # Allocate the authoritative manifest BEFORE publishing its pointer.
            data = store.allocate(
                args.backend, {"podman": podman_context(), "libvirt": "qemu:///system"},
                discover, Path(result["role"]), args.scenario,
            )
            with lock(store.directory(data["id"]) / ".supervisor.lock", blocking=False):
                data = store.load(data["id"])
                if data["status"] != "allocated":
                    raise RunError("Generation recovered before context publication; retry")
                result["generation"] = data["id"]
                data.update(
                    mode="direct", direct_identity=identity, direct_context=dict(result),
                    config=config, operations=[], status="running", context_publication="pending",
                )
                store.save(data)
                atomic_json(path, {"identity": identity, "generation": data["id"]})
                data["context_publication"] = "published"
                store.save(data)
        if args.action == "init":
            return result
        run_id = data["id"]
        with lock(store.directory(run_id) / ".supervisor.lock", blocking=False):
            # Never hold resources while waiting for a mutation session to stop.
            stop_workers(store.load(run_id))
            with lock(store.directory(run_id) / ".resources.lock", blocking=False):
                data = store.load(run_id)
                require_completed(data)
                if args.action == "create" and data["status"] == "destroyed":
                    raise RunError("Completed destroy awaits lease release; run destroy before a new create")
                if args.action == "create" and data["config"] != config:
                    raise RunError("Configuration changed; destroy the current generation first")
                if args.action == "create" and data.get("instances_ready"):
                    mapping(result, data["instances_ready"])
                    return result
                operation_id = str(uuid.uuid4())
                data["operations"].append({"id": operation_id, "action": args.action})
                # spawn() persists both intent and worker identity before its gate opens.
                child = spawn(
                    store, data,
                    [sys.executable, str(REPO / "scripts/scenario-context"), "_worker",
                     run_id, operation_id, args.action],
                    dict(os.environ), result["role"], operation=data["operations"][-1],
                )
            code = child.wait()
            stop_workers(store.load(run_id))
            with lock(store.directory(run_id) / ".resources.lock", blocking=False):
                data = store.load(run_id)
                require_completed(data)
                if code:
                    raise RunError("Mutation worker failed; lease retained")
                if args.action == "destroy":
                    with lock(store.root / ".allocator.lock"):
                        data["status"] = "cleaned"
                        store.save(data)
                    result["generation"] = None
                else:
                    if not data.get("instances_ready"):
                        raise RunError("Completed create has no instance mapping")
        return result


def main(argv=None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments and arguments[0] == "validate-guest":
        from .guest_validation import main as validate_guest

        return validate_guest(arguments[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=(
        "resolve", "init", "create", "destroy", "inspect", "capabilities", "_worker",
        "recover-network-tail",
        "_network-tail-worker",
        *guest_control.ACTIONS,
    ))
    parser.add_argument("worker_args", nargs="*")
    parser.add_argument("--backend", choices=("podman", "kvm"))
    parser.add_argument("--scenario")
    parser.add_argument("--role", default=".")
    parser.add_argument("--guest")
    parser.add_argument("--operation")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--producing-source-root")
    parser.add_argument("--profile")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--plan")
    parser.add_argument("--accept-profile")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.action == "_network-tail-worker":
            if (
                len(args.worker_args) != 4 or args.backend or args.scenario or args.guest
                or args.operation or args.dry_run or args.producing_source_root or args.profile
                or args.apply or args.plan or args.accept_profile
            ):
                raise RunError("Invalid private network-tail worker arguments")
            from . import direct_network_tail_standard

            direct_network_tail_standard.worker(Store.open_existing(), *args.worker_args)
            return 0
        if args.action == "recover-network-tail":
            if (
                args.backend != "kvm" or not args.scenario or not args.operation
                or args.dry_run == args.apply or args.guest is not None or args.worker_args
            ):
                raise RunError("Network-tail actions require KVM, scenario, operation and exactly one mode")
            if args.profile is None:
                if args.apply or args.plan is not None or args.accept_profile is not None:
                    raise RunError("Default network-tail diagnosis is dry-run only")
                from . import direct_network_tail

                result = direct_network_tail.inspect(args)
            else:
                from . import direct_network_tail_standard, direct_network_tail_runtime

                if args.profile != direct_network_tail_runtime.PROFILE:
                    raise RunError("Unsupported network-tail profile")
                if args.dry_run:
                    if args.plan is not None or args.accept_profile is not None:
                        raise RunError("Dry-run cannot accept an apply plan or profile")
                    result = direct_network_tail_standard.inspect(args)
                else:
                    result = direct_network_tail_standard.apply(args)
            print(json.dumps(result, sort_keys=True))
            return 0
        if (
            args.operation is not None or args.dry_run or args.producing_source_root is not None
            or args.profile is not None or args.apply or args.plan is not None or args.accept_profile is not None
        ):
            raise RunError("Recovery diagnostic options are only valid for recover-network-tail")
        store = Store()
        if args.action == "_worker":
            worker(store, *args.worker_args)
            return 0
        if not args.backend or not args.scenario or args.worker_args:
            raise RunError("--backend and --scenario are required")
        if args.action in guest_control.ACTIONS:
            if args.backend != "kvm" or not args.guest:
                raise RunError("Guest control requires --backend kvm and --guest LOGICAL")
        elif args.guest is not None:
            raise RunError("--guest is only valid for guest control")
        result, config = resolved(args, store)
        if args.action in guest_control.ACTIONS:
            result = guest_control.control(args, store, result, config)
        elif result["mode"] == "supervised":
            if args.action in ("create", "destroy"):
                lifecycle(store, args.action, result["generation"])
            elif args.action == "inspect":
                result["manifest"] = store.load(result["generation"])
        else:
            result = direct(args, store, result, config)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (RunError, OSError, ValueError, KeyError, TypeError) as exc:
        print("scenario-context: " + str(exc), file=sys.stderr)
        return 1
