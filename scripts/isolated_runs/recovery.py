"""Exact-target, additive recovery for boot-fenced supervised KVM network tails.

Only absence reconciliation is currently supported. No network teardown profile
has been approved; present resources remain leased. Original seals are immutable.
"""

import copy
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import stat
import sys
import uuid

from . import admission, network_recovery, recovery_host, recovery_system
from .backends import REPO
from .processes import boot_id, members, stop_workers
from .state import RunError, existing_lock

PROTOCOL = "network-tail-v1"
BACKEND_SOURCE = "4d5db9b6bdec79547781b8471b0ce38ccc5bb7b721f5ebabe23bcca690cadcf8"
CONTROLLERS = {
    "ansible-min": ((3, 9), "2.15.13", "6.0.3"),
    "ansible-current": ((3, 12), "2.20.8", "26.8.0"),
    "ansible-next": ((3, 14), "2.21.3", "26.8.0"),
}


def digest(value: dict) -> str:
    """Bind private state without publishing configuration/environment contents."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def trusted_path(path: Path, *, interpreter_entry: bool = False) -> Path:
    """Validate canonical parents; only a venv interpreter entry may be a link."""
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        is_link = stat.S_ISLNK(info.st_mode)
        if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not is_link):
            raise RunError("untrusted_controller_path")
        if is_link and not (ancestor == path and interpreter_entry):
            raise RunError("original_context_path_changed")
    target = path.resolve(strict=True)
    if interpreter_entry and target != path:
        # Validate target's ownership/parents too, not just a safe symlink inode.
        trusted_path(target)
    return target


def namespace_context() -> None:
    for namespace in ("net", "mnt", "pid", "user"):
        own = (Path("/proc/self/ns") / namespace).stat()
        init = (Path("/proc/1/ns") / namespace).stat()
        if (own.st_dev, own.st_ino) != (init.st_dev, init.st_ino):
            raise RunError("unsupported_controller_namespace")


def executing_context() -> dict:
    """Measure actual executing modules and approved interpreter, never env claims."""
    root = trusted_path(REPO)
    prefix = Path(sys.prefix)
    if prefix.parent != root / ".venv" or prefix.name not in CONTROLLERS:
        raise RunError("unsupported_controller_lane")
    trusted_path(prefix)
    expected_python, ansible, molecule = CONTROLLERS[prefix.name]
    if tuple(sys.version_info[:2]) != expected_python:
        raise RunError("unsupported_controller_python")
    executable = Path(sys.executable)
    if executable.parent != prefix / "bin" or executable.name not in (
        "python", "python3", "python" + ".".join(map(str, expected_python)),
    ):
        raise RunError("unsupported_controller_interpreter")
    target = trusted_path(executable, interpreter_entry=True)
    if not stat.S_ISREG(target.stat().st_mode) or not os.access(target, os.X_OK):
        raise RunError("unsupported_controller_interpreter")
    activation = trusted_path(prefix / "bin/activate")
    if not stat.S_ISREG(activation.stat().st_mode):
        raise RunError("approved_controller_tooling_unproven")
    entry = Path(sys.argv[0]).absolute()
    if trusted_path(entry) != root / "scripts/test-run":
        raise RunError("executing_helper_entry_mismatch")
    sources = {}
    package = sys.modules[__package__]
    package_path = root / "scripts/isolated_runs"
    if (
        Path(package.__file__) != package_path / "__init__.py"
        or list(package.__path__) != [str(package_path)]
    ):
        raise RunError("executing_module_root_mismatch")
    trusted_path(package_path / "__init__.py")
    sources["package"] = hashlib.sha256((package_path / "__init__.py").read_bytes()).hexdigest()
    for name in (
        "recovery", "recovery_host", "recovery_system", "recovery_commands", "recovery_routes",
        "network_recovery", "network_references",
        "cli", "backends", "discovery", "processes", "admission", "state", "storage", "storage_references",
    ):
        module = sys.modules[__package__ + "." + name]
        source = Path(module.__file__)
        expected = root / "scripts/isolated_runs" / (name + ".py")
        if source != expected or trusted_path(source) != expected:
            raise RunError("executing_module_root_mismatch")
        sources[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    sources["entry"] = hashlib.sha256(entry.read_bytes()).hexdigest()
    for action in ("create", "destroy"):
        path = root / "molecule/managed" / (action + ".yml")
        trusted_path(path)
        sources[action] = hashlib.sha256(path.read_bytes()).hexdigest()
    if sources["backends"] != BACKEND_SOURCE:
        raise RunError("unsupported_original_source_profile")
    site = prefix / "lib" / ("python" + ".".join(map(str, expected_python))) / "site-packages"
    for package, expected in (("ansible-core", ansible), ("molecule", molecule)):
        try:
            distribution = importlib.metadata.distribution(package)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RunError("approved_controller_tooling_unproven") from exc
        location = Path(distribution.locate_file(""))
        if distribution.version != expected or trusted_path(location) != site:
            raise RunError("approved_controller_tooling_unproven")
    namespace_context()
    return {
        "root": str(root), "prefix": str(prefix), "lane": prefix.name,
        "executable": str(executable), "interpreter_target": str(target),
        "interpreter_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "activation_sha256": hashlib.sha256(activation.read_bytes()).hexdigest(),
        "python_version": list(sys.version_info[:3]),
        "tooling": {"ansible-core": ansible, "molecule": molecule},
        "sources": sources,
    }


def trusted_context(data: dict) -> dict:
    """Separate strict recorded identity from measured current legacy binding."""
    config = data["config"]
    if not isinstance(config, dict) or not isinstance(config.get("_idarsi_effective_env"), dict):
        raise RunError("original_context_unproven")
    environment = config["_idarsi_effective_env"]
    if (
        config["_idarsi_effective_role"] != data["role"]
        or config["_idarsi_effective_scenario"] != data["scenario"]
        or data["context"].get("libvirt") != "qemu:///system"
    ):
        raise RunError("original_context_mismatch")
    current = executing_context()
    trusted_path(Path(data["role"]))
    for action in ("create", "destroy"):
        configured = [
            config.get(section, {}).get("playbooks", {}).get(action)
            for section in ("ansible", "provisioner")
            if config.get(section, {}).get("playbooks", {}).get(action)
        ]
        paths = [
            Path(value) if Path(value).is_absolute()
            else Path(data["role"]) / "molecule" / data["scenario"] / value
            for value in configured
        ]
        if not paths or any(
            trusted_path(path) != REPO / "molecule/managed" / (action + ".yml")
            for path in paths
        ):
            raise RunError("original_playbook_binding_changed")
    missing = []
    for key, expected in (
        ("IDARSI_TEST_ENVIRONMENT", current["root"]), ("VIRTUAL_ENV", current["prefix"]),
    ):
        if key not in environment:
            missing.append(key)
            continue
        value = environment[key]
        if not isinstance(value, str) or not value or not Path(value).is_absolute():
            raise RunError("historical_controller_environment_conflicting")
        if str(trusted_path(Path(value))) != expected:
            raise RunError("historical_controller_environment_conflicting")
    if any(os.environ.get(key) for key in (
        "LIBVIRT_DEFAULT_URI", "LIBVIRT_AUTH_FILE", "CONTAINER_HOST", "CONTAINER_CONNECTION",
        "IDARSI_RUN_ID", "IDARSI_HANDOFF", "PYTHONPATH", "PYTHONHOME",
    )):
        raise RunError("unsupported_controller_override")
    for key, expected in (("IDARSI_TEST_ENVIRONMENT", current["root"]), ("VIRTUAL_ENV", current["prefix"])):
        if key in os.environ and os.environ[key] != expected:
            raise RunError("unsupported_controller_override")
    if missing and current["lane"] != "ansible-current":
        raise RunError("unsupported_legacy_controller_lane")
    return {
        "mode": "legacy_runtime_measured" if missing else "recorded_runtime_measured",
        "missing": missing, "current": current,
    }


def validate_worker(worker: dict) -> None:
    if (
        not isinstance(worker, dict) or set(worker) != {"pid", "start", "boot"}
        or type(worker["pid"]) is not int or worker["pid"] <= 1
        or not isinstance(worker["start"], str) or not worker["start"].isdigit()
    ):
        raise RunError("invalid_worker_identity")
    recovery_host.canonical_uuid(worker["boot"])


def original_binding(data: dict, workers: list, network: dict) -> str:
    """Status and additive audit records are not immutable resource identity."""
    fields = (
        "version", "uid", "id", "mode", "mutation_protocol", "admission_protocol",
        "role", "scenario", "backend", "context", "subnet", "config", "operations", "guests",
    )
    value = {field: data[field] for field in fields}
    value.update(workers=workers, network=network)
    return digest(value)


def validate(data: dict, operation_id: str) -> tuple:
    """Validate exact supported original history and every additive record."""
    recovery_host.canonical_uuid(operation_id)
    if (
        data.get("version") != 1 or data.get("uid") != os.getuid()
        or data.get("mode") != "supervised" or data.get("backend") != "kvm"
        or data.get("mutation_protocol") != "sealed-v1"
        or data.get("admission_protocol") != "session-v1"
        or data.get("status") not in ("cleaning", "cleanup_failed", "cleaned")
        or data.get("guests") != [] or type(data.get("guests")) is not list
        or "storage_probe" in data or data.get("instances_ready")
        or any(key.startswith("pending") for key in data)
    ):
        raise RunError("unsupported_network_tail")
    history = data.get("operations")
    workers = data.get("workers")
    if not isinstance(history, list) or not history or not isinstance(workers, list) or not workers:
        raise RunError("invalid_operation_journal")
    for worker in workers:
        validate_worker(worker)
    if len({(worker["boot"], worker["pid"]) for worker in workers}) != len(workers):
        raise RunError("ambiguous_worker_journal")
    ids = set()
    for index, operation in enumerate(history):
        if not isinstance(operation, dict):
            raise RunError("invalid_operation_journal")
        recovery_host.canonical_uuid(operation["id"])
        if (
            operation["id"] in ids or operation.get("worker") not in workers
            or operation.get("action") not in ("create", "destroy")
        ):
            raise RunError("invalid_operation_journal")
        ids.add(operation["id"])
        if index < len(history) - 1 and operation.get("completion") != operation["id"]:
            raise RunError("multiple_incomplete_operations")
    tail = history[-1]
    if (
        tail["id"] != operation_id or tail["action"] != "destroy"
        or tail.get("purpose") != "supervisor-cleanup" or "completion" in tail
    ):
        raise RunError("not_exact_incomplete_destroy_tail")
    record = data.get("recoveries")
    if "recoveries" in data and record is None:
        raise RunError("unsupported_recovery_protocol")
    original_workers = workers
    network = data.get("network")
    if record is not None:
        if (
            not isinstance(record, dict)
            or set(record) - {
                "protocol", "target", "binding", "original_workers", "network",
                "host_observation", "attempts", "current_context",
            }
            or record.get("protocol") != PROTOCOL or record.get("target") != operation_id
            or not isinstance(record.get("attempts"), list)
        ):
            raise RunError("unsupported_recovery_protocol")
        original_workers = record["original_workers"]
        network = record["network"]
        if not isinstance(original_workers, list) or not original_workers:
            raise RunError("invalid_recovery_workers")
        expected_workers = list(original_workers)
        attempt_ids = set()
        for attempt in record["attempts"]:
            if (
                not isinstance(attempt, dict)
                or set(attempt) - {"id", "phase", "boot", "binding", "evidence", "outcome", "blocker"}
                or attempt.get("phase") not in ("intent", "resources_verified", "reconciled", "blocked")
                or attempt.get("binding") != record["binding"]
            ):
                raise RunError("invalid_recovery_attempt")
            recovery_host.canonical_uuid(attempt["id"])
            recovery_host.canonical_uuid(attempt["boot"])
            if attempt["id"] in attempt_ids:
                raise RunError("invalid_recovery_attempt")
            attempt_ids.add(attempt["id"])
            if attempt.get("outcome") not in (None, "reconciled"):
                raise RunError("invalid_recovery_attempt")
            if "blocker" in attempt and (
                not isinstance(attempt["blocker"], str) or not attempt["blocker"].isidentifier()
                or len(attempt["blocker"]) >= 80
            ):
                raise RunError("invalid_recovery_attempt")
            if "evidence" in attempt and attempt["evidence"] != {
                "network": "absent", "kernel": "absent", "helpers": "absent", "mutation": False,
            }:
                raise RunError("invalid_recovery_evidence")
            if attempt["phase"] in ("resources_verified", "reconciled") and "evidence" not in attempt:
                raise RunError("invalid_recovery_evidence")
            if (attempt["phase"] == "reconciled") != (attempt.get("outcome") == "reconciled"):
                raise RunError("invalid_recovery_attempt")
        if workers != expected_workers or any(op["worker"] not in original_workers for op in history):
            raise RunError("recovery_worker_journal_changed")
        if original_binding(data, original_workers, network) != record["binding"]:
            raise RunError("recovery_binding_changed")
        if data["network"] != network and not (
            data["network"] is None and data["status"] == "cleaned"
            and record["attempts"] and record["attempts"][-1]["phase"] == "reconciled"
            and record["attempts"][-1].get("outcome") == "reconciled"
        ):
            raise RunError("recovery_network_intent_changed")
        if "host_observation" in record:
            observation = record["host_observation"]
            if (
                not isinstance(observation, dict)
                or set(observation) != {"protocol", "binding", "boot", "machine", "context_digest"}
                or observation["protocol"] != "current-host-v1"
                or observation["binding"] != record["binding"]
                or observation["context_digest"] != digest(record.get("current_context"))
                or any(worker["boot"] != observation["boot"] for worker in original_workers)
                or not isinstance(observation["machine"], str)
                or len(observation["machine"]) != 32
                or any(character not in "0123456789abcdef" for character in observation["machine"])
            ):
                raise RunError("invalid_host_observation")
            recovery_host.canonical_uuid(observation["boot"])
    if not isinstance(network, dict) or set(network) != {"id", "name"}:
        raise RunError("incomplete_network_intent")
    recovery_host.canonical_uuid(network["id"])
    expected = copy.deepcopy(data)
    expected["network"] = network
    network_recovery.expected_network(expected)
    current_context = trusted_context(data)
    if record is not None and record.get("current_context") != current_context:
        raise RunError("measured_controller_context_changed")
    binding = original_binding(data, original_workers, network)
    return binding, original_workers, network


def record_for(data: dict, operation_id: str, binding: str, workers: list, network: dict) -> dict:
    if "recoveries" not in data:
        data["recoveries"] = {
            "protocol": PROTOCOL, "target": operation_id, "binding": binding,
            "original_workers": copy.deepcopy(workers), "network": copy.deepcopy(network), "attempts": [],
            "current_context": trusted_context(data),
        }
    return data["recoveries"]


def prove_route(data: dict, workers: list, current_boot: str) -> dict:
    """No same-boot historical-hook profile exists; never manufacture one."""
    if any(worker["boot"] == current_boot for worker in workers):
        raise RunError("same_boot_not_fenced")
    observation = data.get("recoveries", {}).get("host_observation")
    if observation:
        if observation["machine"] != recovery_host.machine_identity():
            raise RunError("historical_host_identity_unproven")
        if observation["boot"] == current_boot:
            raise RunError("same_boot_not_fenced")
        return {"route": "observed-host-boot", "current_boot": current_boot}
    return recovery_host.boot_fence(workers, current_boot)


def persistent_store(store) -> None:
    """Preparation supports only known local persistent filesystem types."""
    root = store.root.resolve(strict=True)
    mount = recovery_system.containing(recovery_system.mounts(), root)
    if (
        mount["filesystem"] not in ("ext4", "xfs", "btrfs")
        or "rw" not in mount["options"] or "ro" in mount["options"]
    ):
        raise RunError("state_persistence_unproven")


def prepare(store, run_id: str, operation_id: str) -> dict:
    """Persist a present-time observation only; no gate closure or backend call."""
    with existing_lock(store.directory(run_id) / ".supervisor.lock"):
        with existing_lock(store.directory(run_id) / ".resources.lock"):
            data = store.load(run_id)
            binding, workers, network = validate(data, operation_id)
            if data["status"] == "cleaned":
                raise RunError("already_reconciled")
            current_boot = recovery_host.canonical_uuid(boot_id())
            if any(worker["boot"] != current_boot for worker in workers):
                raise RunError("preparation_requires_original_current_boot")
            persistent_store(store)
            observation = {
                "protocol": "current-host-v1", "binding": binding,
                "boot": current_boot, "machine": recovery_host.machine_identity(),
                "context_digest": digest(trusted_context(data)),
            }
            record = record_for(data, operation_id, binding, workers, network)
            previous = record.get("host_observation")
            if previous is not None and previous != observation:
                raise RunError("host_observation_already_bound")
            if boot_id() != current_boot or recovery_host.machine_identity() != observation["machine"]:
                raise RunError("host_identity_changed")
            if previous is None:
                record["host_observation"] = observation
                store.save(data)
            return {
                "run_id": run_id, "operation": operation_id, "outcome": "maintenance_prepared",
                "eligible": False, "audit_written": previous is None, "reboot_authorized": False,
                "blockers": ["same_boot_not_fenced", "historical_hook_receipt_missing"],
            }


def inspect(store, run_id: str, operation_id: str) -> dict:
    """Non-writing preflight: existing locks only, no signals or gate closure."""
    result = {
        "run_id": run_id, "operation": operation_id, "eligible": False,
        "route": None, "blockers": [], "audit_written": False,
    }
    with existing_lock(store.directory(run_id) / ".supervisor.lock"):
        with existing_lock(store.directory(run_id) / ".resources.lock"):
            data = store.load(run_id)
            binding, workers, network = validate(data, operation_id)
            result["binding"] = binding
            current_context = trusted_context(data)
            result["binding_mode"] = current_context["mode"]
            if current_context["missing"]:
                result["warnings"] = ["historical_controller_environment_unrecorded"]
            current_boot = recovery_host.canonical_uuid(boot_id())
            result["maintenance_preparation_available"] = False
            if all(worker["boot"] == current_boot for worker in workers):
                try:
                    persistent_store(store)
                    recovery_host.machine_identity()
                    result["maintenance_preparation_available"] = True
                except (RunError, OSError, ValueError):
                    pass
            try:
                route = prove_route(data, workers, current_boot)
            except RunError as exc:
                result["blockers"] = [str(exc), "historical_hook_receipt_missing"]
                return result
            result["route"] = route["route"]
            evidence_data = copy.deepcopy(data)
            evidence_data["network"] = network
            try:
                result["resources"] = network_recovery.verify_absent(store, evidence_data)
            except RunError as exc:
                reason = str(exc)
                result["blockers"] = [reason if reason.isidentifier() and len(reason) < 80 else "read_only_resource_query_failed"]
                return result
            if boot_id() != current_boot or validate(store.load(run_id), operation_id)[0] != binding:
                raise RunError("recovery_inputs_changed")
            prove_route(data, workers, current_boot)
            result["eligible"] = True
            return result


def apply(store, run_id: str, operation_id: str) -> dict:
    """Audit -> close -> quiesce -> revalidate absence -> allocator-last commit."""
    with existing_lock(store.directory(run_id) / ".supervisor.lock"):
        data = store.load(run_id)
        binding, workers, network = validate(data, operation_id)
        current_boot = recovery_host.canonical_uuid(boot_id())
        # No signals even to apparently old records until local-host provenance.
        prove_route(data, workers, current_boot)
        if data["status"] == "cleaned":
            with existing_lock(store.directory(run_id) / ".resources.lock"):
                evidence_data = copy.deepcopy(data)
                evidence_data["network"] = network
                network_recovery.verify_absent(store, evidence_data)
                if boot_id() != current_boot or validate(store.load(run_id), operation_id)[0] != binding:
                    raise RunError("host_identity_changed")
                prove_route(data, workers, current_boot)
            return {"run_id": run_id, "operation": operation_id, "outcome": "reconciled", "eligible": True}
        # Intent is additive. Never write stale data while a worker owns resources.
        with existing_lock(store.directory(run_id) / ".resources.lock"):
            fresh = store.load(run_id)
            if validate(fresh, operation_id)[0] != binding:
                raise RunError("recovery_inputs_changed")
            data = fresh
            record = record_for(data, operation_id, binding, workers, network)
            attempt = {
                "id": str(uuid.uuid4()), "phase": "intent", "boot": current_boot, "binding": binding,
            }
            record["attempts"].append(attempt)
            store.save(data)
        data = admission.close(store, run_id)
        if validate(data, operation_id)[0] != binding or data["workers"] != workers:
            raise RunError("recovery_inputs_changed")
        stop_workers(data)
        if any(members(worker) for worker in workers):
            raise RunError("worker_session_not_empty")
        with existing_lock(store.directory(run_id) / ".resources.lock"):
            data = store.load(run_id)
            if (
                validate(data, operation_id)[0] != binding or data["workers"] != workers
                or admission.gate(store, run_id)["state"] != "closed"
                or any(members(worker) for worker in workers)
                or boot_id() != current_boot
            ):
                raise RunError("recovery_inputs_changed")
            prove_route(data, workers, current_boot)
            attempt = data["recoveries"]["attempts"][-1]
            try:
                evidence = network_recovery.verify_absent(store, data)
                attempt.update(phase="resources_verified", evidence=evidence)
                store.save(data)
                # No recovery resource worker is necessary: this branch performs
                # no backend mutation and cannot dispatch hooks or daemon deletes.
                # A crash at any point requires all proofs again, not this seal.
                evidence = network_recovery.verify_absent(store, data)
                prove_route(data, workers, current_boot)
                if boot_id() != current_boot or admission.gate(store, run_id)["state"] != "closed":
                    raise RunError("recovery_inputs_changed")
                fresh = store.load(run_id)
                if validate(fresh, operation_id)[0] != binding or fresh["recoveries"] != data["recoveries"]:
                    raise RunError("recovery_inputs_changed")
                attempt.update(phase="reconciled", outcome="reconciled", evidence=evidence)
                store.save(data)
                # verify_absent has released the storage graph lock.
                with existing_lock(store.root / ".allocator.lock"):
                    data["network"] = None
                    data["status"] = "cleaned"
                    try:
                        store.save(data)
                    except OSError:
                        # Atomic replace may succeed before directory fsync
                        # reports failure. Restore a held lease while allocator
                        # is still exclusive; surface any rollback failure too.
                        data["network"] = copy.deepcopy(network)
                        data["status"] = "cleanup_failed"
                        store.save(data)
                        raise
            except (RunError, OSError, ValueError, KeyError, TypeError) as exc:
                # A failed final write may have replaced the file before fsync.
                # Never overwrite durable state with this possibly stale object.
                # In particular, never record success after a failed persistence.
                # Read failures retain the attempt, with a bounded reason when a
                # safe reload/write is still available. Storage errors are not
                # followed by speculative additional writes.
                if isinstance(exc, RunError):
                    reason = str(exc)
                    fresh = store.load(run_id)
                    if validate(fresh, operation_id)[0] == binding:
                        current_attempt = fresh["recoveries"]["attempts"][-1]
                        if current_attempt["id"] == attempt["id"]:
                            current_attempt["blocker"] = (
                                reason if reason.isidentifier() and len(reason) < 80 else "resource_proof_failed"
                            )
                            store.save(fresh)
                raise
        return {"run_id": run_id, "operation": operation_id, "outcome": "reconciled", "eligible": True}
