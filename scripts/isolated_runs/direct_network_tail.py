"""Read-only diagnosis of unsupported direct network tails, never recovery authority."""

from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from . import context
from . import direct_network_tail_source as source
from .network_recovery import expected_network
from .recovery import validate_worker
from .state import RunError, Store, existing_lock

ACTION = "recover-network-tail"
FIELDS = {
    "version", "id", "uid", "backend", "context", "subnet", "status", "role",
    "scenario", "network", "guests", "workers", "config", "mode", "operations",
    "direct_identity", "direct_context", "context_publication", "instances_ready", "error",
}


def canonical_uuid(value) -> None:
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise RunError("invalid_operation_identity")


def directory_identity(info) -> tuple:
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode


@contextmanager
def existing_directories(paths):
    """Pin existing directory inodes, allowing only the approved sticky /tmp ancestor.

    This exception applies to role/ephemeral data, never executables or Store's
    private metadata policy. Nothing is created, repaired, chmodded or synced.
    """
    pinned = {}
    with ExitStack() as stack:
        for leaf in paths:
            if not leaf.is_absolute():
                raise RunError("noncanonical_direct_context_path")
            for path in reversed((leaf, *leaf.parents)):
                if path in pinned:
                    continue
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
                stack.callback(os.close, fd)
                info = os.fstat(fd)
                sticky = (
                    path == Path("/tmp") and leaf.is_relative_to(Path("/tmp/opencode"))
                    and info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                )
                if (
                    not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                    or (info.st_mode & 0o022 and not sticky)
                    or directory_identity(path.lstat()) != directory_identity(info)
                ):
                    raise RunError("unsafe_direct_context_directory")
                pinned[path] = directory_identity(info)
            if leaf.lstat().st_uid != os.getuid():
                raise RunError("foreign_direct_context_directory")
        yield
        if any(directory_identity(path.lstat()) != identity for path, identity in pinned.items()):
            raise RunError("direct_context_directory_replaced")


def identity_for(args) -> dict:
    """Use the current exported direct ephemeral binding, never a config subprocess."""
    if (
        args.backend != "kvm" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.scenario)
        or any(key == "IDARSI_RUN_ID" or key.startswith("IDARSI_HANDOFF") for key in os.environ)
    ):
        raise RunError("unsupported_direct_context_or_handoff")
    canonical_uuid(args.operation)
    role = Path(args.role).absolute()
    if role.resolve(strict=True) != role:
        raise RunError("noncanonical_direct_context_path")
    value = os.environ.get("MOLECULE_EPHEMERAL_DIRECTORY")
    if not value:
        raise RunError("export_actual_molecule_ephemeral_directory")
    ephemeral = Path(value)
    if not ephemeral.is_absolute() or ephemeral.resolve(strict=True) != ephemeral:
        raise RunError("noncanonical_direct_context_path")
    if ephemeral == Path("/") or role.is_relative_to(ephemeral):
        raise RunError("unsafe_direct_context_directory")
    return {
        "role": str(role), "scenario": args.scenario, "backend": "kvm",
        "ephemeral_directory": str(ephemeral),
    }


def validate_record(data: dict, identity: dict, operation_id: str) -> None:
    """Validate only the original authoritative checkpoint; never adopt a resource."""
    canonical_uuid(data["id"])
    if (
        set(data) - FIELDS or data.get("version") != 1 or data.get("uid") != os.getuid()
        or data.get("mode") != "direct" or data.get("backend") != "kvm"
        or data.get("status") != "running" or data.get("context_publication") != "published"
        or data.get("direct_identity") != identity
        or any(data.get(key) != identity[key] for key in ("role", "scenario", "backend"))
        or data.get("context", {}).get("libvirt") != "qemu:///system"
    ):
        raise RunError("unsupported_original_direct_record")
    binding = data.get("direct_context", {})
    if (
        binding.get("schema") != context.SCHEMA or binding.get("mode") != "direct"
        or binding.get("generation") != data["id"]
        or any(binding.get(key) != value for key, value in identity.items())
        or binding.get("collections_directory") != str(Path(identity["ephemeral_directory"]) / "collections")
    ):
        raise RunError("original_direct_context_binding_changed")
    config = data.get("config", {})
    environment = config.get("_idarsi_effective_env", {})
    if (
        not isinstance(environment, dict)
        or config.get("_idarsi_effective_role") != identity["role"]
        or config.get("_idarsi_effective_scenario") != identity["scenario"]
        or config.get("_idarsi_effective_ephemeral") != identity["ephemeral_directory"]
        or any(environment.get(key) != value for key, value in (
            ("MOLECULE_PROJECT_DIRECTORY", identity["role"]),
            ("MOLECULE_SCENARIO_DIRECTORY", str(Path(identity["role"]) / "molecule" / identity["scenario"])),
            ("MOLECULE_EPHEMERAL_DIRECTORY", identity["ephemeral_directory"]),
        ))
    ):
        raise RunError("original_effective_context_binding_changed")
    if type(data.get("guests")) is not list or data["guests"] != []:
        raise RunError("empty_guest_checkpoint_unproven")
    if "instances_ready" in data and not isinstance(data["instances_ready"], list):
        raise RunError("unsupported_stale_instance_mapping")
    network = data.get("network")
    if not isinstance(network, dict) or set(network) != {"id", "name"}:
        raise RunError("unsupported_original_network_intent")
    expected_network(data)
    workers, operations = data.get("workers"), data.get("operations")
    if not isinstance(workers, list) or not workers or not isinstance(operations, list) or not operations:
        raise RunError("invalid_original_operation_journal")
    for worker in workers:
        validate_worker(worker)
    if len({(worker["boot"], worker["pid"]) for worker in workers}) != len(workers):
        raise RunError("ambiguous_original_worker_journal")
    ids = set()
    for index, operation in enumerate(operations):
        canonical_uuid(operation["id"])
        if operation["id"] in ids or operation.get("worker") not in workers:
            raise RunError("invalid_original_operation_journal")
        ids.add(operation["id"])
        if index < len(operations) - 1:
            if operation.get("action") == "create":
                if set(operation) != {"id", "action", "worker", "completion"}:
                    raise RunError("unsupported_original_operation")
            elif operation.get("action") in context.guest_control.ACTIONS:
                if set(operation) != {
                    "id", "action", "worker", "completion", "protocol", "guest", "domain_uuid", "result",
                }:
                    raise RunError("unsupported_original_operation")
            else:
                raise RunError("unsupported_original_operation")
    context.require_completed(dict(data, operations=operations[:-1]), quiescent=False)
    tail = operations[-1]
    if (
        set(tail) != {"id", "action", "worker"} or tail["id"] != operation_id
        or tail["action"] != "destroy"
        or not any(operation.get("action") == "create" for operation in operations[:-1])
    ):
        raise RunError("not_exact_original_incomplete_destroy")


def inspect(args, store=None) -> dict:
    """Return a bounded, non-writing refusal; no plan or mutation profile exists."""
    result = {
        "schema": "idarsi.direct-network-tail-diagnostic/v1", "action": ACTION,
        "eligible": False, "apply_authorized": False, "lease_release_authorized": False,
        "audit_written": False,
    }
    try:
        identity = identity_for(args)
        store = Store.open_existing() if store is None else store
        directories = store.root / ".contexts"
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        pointer = directories / (key + ".json")
        with existing_directories([
            Path(identity["role"]), Path(identity["ephemeral_directory"]), directories,
        ]):
            if (
                Path(identity["ephemeral_directory"]).is_relative_to(store.root)
                or store.root.is_relative_to(Path(identity["ephemeral_directory"]))
                or stat.S_IMODE(directories.lstat().st_mode) != 0o700
            ):
                raise RunError("unsafe_direct_context_directory")
            with existing_lock(pointer.with_suffix(".lock")):
                selected = context.read_private(pointer)
                if set(selected) != {"identity", "generation"} or selected["identity"] != identity:
                    raise RunError("direct_context_pointer_mismatch")
                canonical_uuid(selected["generation"])
                run_id = selected["generation"]
                with existing_lock(store.directory(run_id) / ".supervisor.lock"):
                    with existing_lock(store.directory(run_id) / ".resources.lock"):
                        data = store.load(run_id)
                        validate_record(data, identity, args.operation)
                        if context.read_private(pointer) != selected or store.load(run_id) != data:
                            raise RunError("direct_context_changed_during_inspection")
                        result.update(
                            generation=run_id, operation=args.operation,
                            blockers=["original_resource_identity_ledger_unavailable"],
                            network_only_scope_insufficient_for_terminal_cleanup=True,
                            guest_checkpoint="recorded-empty-not-fresh-resource-absence",
                        )
                        location = getattr(args, "producing_source_root", None)
                        if location is None:
                            result["producing_source"] = {
                                "verified": False, "blockers": ["approved_producing_source_unavailable"],
                            }
                        else:
                            receipt = source.verify_source(location)
                            # Location identity is private binding material. Never
                            # publish the caller's source-root path in diagnostics.
                            result["producing_source"] = {
                                "verified": True, "subset_digest": receipt["subset_digest"],
                                "provenance": receipt["provenance"],
                            }
                            result["blockers"].extend([
                                "runtime_visibility_unavailable", "firewall_visibility_unavailable",
                                "helper_visibility_unavailable",
                            ])
                            result["qualification"] = {
                                "status": "not-performed-default-forensic-contract-unavailable",
                                "claim": "required-measurements-unavailable-not-live-permission-evidence",
                            }
                        if context.read_private(pointer) != selected or store.load(run_id) != data:
                            raise RunError("direct_context_changed_during_inspection")
    except (RunError, OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        code = str(exc) if isinstance(exc, RunError) else "existing_direct_context_unproven"
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
            code = "original_direct_record_validation_failed"
        result["blockers"] = [code]
    return result
