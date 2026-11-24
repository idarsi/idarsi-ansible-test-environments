"""Opt-in standard-libvirt reconciliation, separate from ordinary destroy and forensics."""

import copy
from contextlib import contextmanager, ExitStack
import hashlib
import importlib.metadata
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

from . import context, direct_network_tail as diagnostic, direct_network_tail_plan as draft
from . import direct_network_tail_source as source, direct_network_tail_runtime as runtime
from . import processes, recovery, recovery_routes, recovery_system
from .backends import REPO
from .discovery import VIRSH, libvirt_networks
from .network_recovery import expected_network
from .network_references import assert_network_unused
from .state import RunError, Store, existing_lock

KEY = "direct_network_tail_recovery"
PROTOCOL = "direct-standard-network-tail-v1"
PHASES = ("intent", "resources_verified", "settlement_verified", "completed")


def digest(value) -> str:
    return hashlib.sha256(draft.canonical_bytes(value)).hexdigest()


def absence_receipt() -> dict:
    return {
        "network_uuid": "absent", "network_name": "absent", "kernel_bridge": "absent",
        "subnet_addresses": "absent", "subnet_routes": "absent",
        "scope": runtime.CLAIMS["scope"],
        "independent_firewall_verification": "unverified", "independent_helper_verification": "unverified",
    }


def acceptance_receipt() -> dict:
    return {"profile": runtime.PROFILE, "provenance": "explicit-operator-cli-acceptance",
            "claims": runtime.CLAIMS, "assumptions": runtime.ASSUMPTIONS}


def settlement_receipt(plan: dict, attempt: dict) -> dict:
    return {
        "author": "parent-after-successful-worker-exit-v1", "attempt": attempt["id"],
        "worker": attempt["worker"], "worker_exit": 0, "plan_digest": attempt["plan_digest"],
        "binding": plan["binding"], "boot": plan["boot"], "absence": absence_receipt(),
    }


def validate_record(data: dict, identity: dict, operation: str) -> tuple:
    """Reconstruct only immutable original state, never backfill its resource ledger."""
    if set(data) - (diagnostic.FIELDS | {KEY}):
        raise RunError("unsupported_standard_tail_record")
    view = copy.deepcopy(data)
    record = view.pop(KEY, None)
    if record is not None:
        if (
            not isinstance(record, dict) or set(record) != {
                "protocol", "original_operation", "binding", "original_workers", "network",
                "original_instances_ready", "plan", "plan_digest", "acceptance", "attempts",
            }
            or record["protocol"] != PROTOCOL or record["original_operation"] != operation
            or record["acceptance"] != acceptance_receipt()
            or not isinstance(record["attempts"], list) or not record["attempts"]
            or digest(record["plan"]) != record["plan_digest"]
        ):
            raise RunError("invalid_standard_tail_journal")
        expected_workers = copy.deepcopy(record["original_workers"])
        attempts = set()
        for index, attempt in enumerate(record["attempts"]):
            if (
                not isinstance(attempt, dict) or set(attempt) - {
                    "id", "phase", "worker", "plan_digest", "evidence", "settlement", "error",
                }
                or attempt.get("phase") not in PHASES or attempt.get("plan_digest") != record["plan_digest"]
            ):
                raise RunError("invalid_standard_tail_attempt")
            diagnostic.canonical_uuid(attempt["id"])
            if attempt["id"] in attempts:
                raise RunError("ambiguous_standard_tail_attempt")
            attempts.add(attempt["id"])
            if "worker" in attempt:
                recovery.validate_worker(attempt["worker"])
                expected_workers.append(attempt["worker"])
            if attempt["phase"] != "intent":
                if "worker" not in attempt or attempt.get("evidence") != absence_receipt():
                    raise RunError("invalid_standard_tail_evidence")
            elif "evidence" in attempt:
                raise RunError("unexpected_standard_tail_evidence")
            if attempt["phase"] in ("settlement_verified", "completed"):
                if (
                    index != len(record["attempts"]) - 1
                    or attempt.get("settlement") != settlement_receipt(record["plan"], attempt)
                ):
                    raise RunError("invalid_standard_tail_settlement")
                if attempt["phase"] == "completed" and data["status"] != "cleaned":
                    raise RunError("invalid_standard_tail_terminal_state")
            elif "settlement" in attempt:
                raise RunError("unexpected_standard_tail_settlement")
            if "error" in attempt and not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", attempt["error"]):
                raise RunError("invalid_standard_tail_error")
        if data["workers"] != expected_workers or data["network"] not in (record["network"], None):
            raise RunError("standard_tail_original_binding_changed")
        view["workers"], view["network"] = record["original_workers"], record["network"]
        original_mapping = record["original_instances_ready"]
        if not isinstance(original_mapping, dict) or set(original_mapping) != {"present", "value"}:
            raise RunError("invalid_standard_tail_original_mapping")
        if original_mapping["present"] is True:
            view["instances_ready"] = original_mapping["value"]
        elif original_mapping["present"] is False and original_mapping["value"] is None:
            view.pop("instances_ready", None)
        else:
            raise RunError("invalid_standard_tail_original_mapping")
        if data["status"] == "cleaned":
            if data["network"] is not None or "instances_ready" in data or record["attempts"][-1]["phase"] != "completed":
                raise RunError("invalid_standard_tail_terminal_state")
            view["status"] = "running"
        elif data["status"] != "running" or data["network"] != record["network"]:
            raise RunError("invalid_standard_tail_status")
        elif ("instances_ready" in data) != original_mapping["present"] or data.get("instances_ready") != original_mapping["value"]:
            raise RunError("standard_tail_original_mapping_changed")
    binding = draft.binding_digest(draft.checkpoint_binding(view, identity, operation))
    if record and (binding != record["binding"] or record["plan"].get("binding") != binding):
        raise RunError("standard_tail_original_binding_changed")
    return binding, view, record


@contextmanager
def bound_context(args, store=None):
    """Existing direct context -> supervisor; resources are acquired separately."""
    identity = diagnostic.identity_for(args)
    store = Store.open_existing() if store is None else store
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    contexts = store.root / ".contexts"
    pointer = contexts / (key + ".json")
    with diagnostic.existing_directories([
        Path(identity["role"]), Path(identity["ephemeral_directory"]), contexts,
    ]):
        if stat.S_IMODE(contexts.lstat().st_mode) != 0o700:
            raise RunError("unsafe_standard_direct_context")
        ephemeral = Path(identity["ephemeral_directory"])
        if ephemeral.is_relative_to(store.root) or store.root.is_relative_to(ephemeral):
            raise RunError("unsafe_standard_direct_context")
        with existing_lock(pointer.with_suffix(".lock")):
            selected = context.read_private(pointer)
            if set(selected) != {"identity", "generation"} or selected["identity"] != identity:
                raise RunError("standard_direct_pointer_mismatch")
            run_id = selected["generation"]
            store.directory(run_id)
            with existing_lock(store.directory(run_id) / ".supervisor.lock"):
                yield store, run_id, identity
                if context.read_private(pointer) != selected:
                    raise RunError("standard_direct_pointer_changed")


def recheck_pointer(store, data: dict, identity: dict) -> None:
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    selected = context.read_private(store.root / ".contexts" / (key + ".json"))
    if selected != {"identity": identity, "generation": data["id"]}:
        raise RunError("standard_direct_pointer_changed")


def writer_barrier(data: dict, boot: str, own_worker=None) -> None:
    """Same boot, complete procfs, exact gone leaders/sessions; never signal."""
    recovery_system.complete_proc_view()
    seen = set()
    for worker in data["workers"]:
        recovery.validate_worker(worker)
        if worker["boot"] != boot or (worker["pid"], worker["start"]) in seen:
            raise RunError("standard_writer_boot_or_identity_changed")
        seen.add((worker["pid"], worker["start"]))
        if worker == own_worker:
            item = processes.process(os.getpid())
            if (
                not item or item["pid"] != worker["pid"] or item["start"] != worker["start"]
                or item["session"] != worker["pid"] or item["uid"] != os.getuid() or item["zombie"]
                or os.getsid(0) != worker["pid"]
            ):
                raise RunError("standard_recovery_worker_identity_changed")
        elif processes.members(worker) or processes.process(worker["pid"]) is not None:
            raise RunError("standard_old_writer_not_gone")
    if processes.boot_id() != boot:
        raise RunError("standard_host_boot_changed")


def generated_xml(store, data: dict) -> str:
    expected = ET.tostring(expected_network(data), encoding="unicode").encode()
    path = store.directory(data["id"]) / "network.xml"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
            or info.st_mode & 0o022 or stream.read(len(expected) + 1) != expected
        ):
            raise RunError("standard_original_network_xml_changed")
        after = os.fstat(stream.fileno())
        entry = path.lstat()
        if source.inode_identity(info) != source.inode_identity(after) or source.inode_identity(info) != source.inode_identity(entry):
            raise RunError("standard_original_network_xml_changed")
    return hashlib.sha256(expected).hexdigest()


def normalized_xml(root) -> str:
    root = copy.deepcopy(root)
    if root.attrib:
        raise RunError("standard_network_xml_not_generated")
    for node in root.iter():
        node.text, node.tail = (node.text or "").strip() or None, None
    bridge = root.find("bridge")
    if bridge is not None:
        for key, value in (("stp", "on"), ("delay", "0")):
            if key in bridge.attrib and bridge.attrib.pop(key) != value:
                raise RunError("standard_network_xml_not_generated")
    mac = root.findall("mac")
    if mac:
        if len(mac) != 1 or set(mac[0].attrib) != {"address"} or not re.fullmatch(
            r"52:54:00(?::[a-f0-9]{2}){3}", mac[0].get("address", ""),
        ) or list(mac[0]) or mac[0].text:
            raise RunError("standard_network_xml_not_generated")
        root.remove(mac[0])
    forward = root.find("forward")
    if forward is not None and list(forward):
        if ET.tostring(forward, encoding="unicode") != '<forward mode="nat"><nat><port start="1024" end="65535" /></nat></forward>':
            raise RunError("standard_network_xml_not_generated")
        forward.clear()
        forward.set("mode", "nat")
    def tree(node):
        return [node.tag, [list(item) for item in sorted(node.attrib.items())],
                node.text or "", sorted(tree(child) for child in node)]
    return digest(tree(root))


def kernel_absence(addresses, routes, subnet, bridge):
    if not isinstance(addresses, list):
        raise RunError("standard_address_inventory_invalid")
    for interface in addresses:
        if (
            not isinstance(interface, dict) or not isinstance(interface.get("ifname"), str)
            or type(interface.get("ifindex")) is not int or not isinstance(interface.get("addr_info"), list)
        ):
            raise RunError("standard_address_inventory_invalid")
        if interface["ifname"] == bridge or bridge in interface.get("altnames", []):
            raise RunError("standard_kernel_bridge_remains")
        for address in interface["addr_info"]:
            if not isinstance(address, dict) or address.get("family") not in ("inet", "inet6"):
                raise RunError("standard_address_inventory_invalid")
            local = ipaddress.ip_address(address["local"])
            prefix = address.get("prefixlen")
            if local.version != (4 if address["family"] == "inet" else 6):
                raise RunError("standard_address_inventory_invalid")
            if type(prefix) is not int or not 0 <= prefix <= local.max_prefixlen:
                raise RunError("standard_address_inventory_invalid")
            if local.version == subnet.version and ipaddress.ip_network(str(local) + "/" + str(prefix), strict=False).overlaps(subnet):
                raise RunError("standard_subnet_address_remains")
    for version, entries in routes.items():
        recovery_routes.verify(entries, subnet, bridge, version)


def address_lifetime(value):
    """Decode only iproute2's uint32 seconds or literal forever representation."""
    if value == "forever" and type(value) is str:
        return "forever"
    if type(value) is not int or not 0 <= value <= 4294967295:
        raise RunError("standard_address_lifetime_invalid")
    if value == 4294967295:
        return "forever"
    return "zero" if value == 0 else "finite-positive"


def comparable_addresses(addresses):
    """Normalize only validated lifetime counters; preserve all other observed fields."""
    if not isinstance(addresses, list):
        raise RunError("standard_address_inventory_invalid")
    normalized = copy.deepcopy(addresses)
    for interface in normalized:
        if (
            not isinstance(interface, dict) or not isinstance(interface.get("ifname"), str)
            or not interface["ifname"] or type(interface.get("ifindex")) is not int
            or interface["ifindex"] <= 0 or not isinstance(interface.get("addr_info"), list)
        ):
            raise RunError("standard_address_inventory_invalid")
        for address in interface["addr_info"]:
            if not isinstance(address, dict) or address.get("family") not in ("inet", "inet6"):
                raise RunError("standard_address_inventory_invalid")
            local = ipaddress.ip_address(address["local"])
            prefix = address.get("prefixlen")
            if (
                local.version != (4 if address["family"] == "inet" else 6)
                or type(prefix) is not int or not 0 <= prefix <= local.max_prefixlen
            ):
                raise RunError("standard_address_inventory_invalid")
            keys = ("valid_life_time", "preferred_life_time")
            if any(key in address for key in keys):
                if not all(key in address for key in keys):
                    raise RunError("standard_address_lifetime_invalid")
                valid, preferred = (address[key] for key in keys)
                classes = [address_lifetime(value) for value in (valid, preferred)]
                if classes[0] != "forever" and (classes[1] == "forever" or preferred > valid):
                    raise RunError("standard_address_lifetime_invalid")
                for key, classification in zip(keys, classes):
                    address[key] = classification
    return normalized


def compare_snapshots(first: dict, second: dict) -> None:
    """Allow ordinary finite countdowns, not renewal, deprecation or topology drift."""
    views = []
    for snapshot in (first, second):
        view = dict(snapshot)
        view["addresses"] = comparable_addresses(snapshot["addresses"])
        views.append(view)
    if json.dumps(views[0], sort_keys=True, separators=(",", ":")) != json.dumps(views[1], sort_keys=True, separators=(",", ":")):
        raise RunError("standard_dependency_snapshots_changed")
    # Equality above establishes exact interface/address ordering and every
    # non-lifetime field. Finite counters may decrease, never renew/increase.
    for before_interface, after_interface in zip(first["addresses"], second["addresses"]):
        for before, after in zip(before_interface["addr_info"], after_interface["addr_info"]):
            for key in ("valid_life_time", "preferred_life_time"):
                if key in before and address_lifetime(before[key]) == "finite-positive" and after[key] > before[key]:
                    raise RunError("standard_address_lifetime_not_countdown")


def observe_network(data: dict, *, require_absent=False) -> dict:
    """Two complete agreeing API/kernel dependency snapshots; no forensic claims."""
    expected = expected_network(data)
    bridge = expected.find("bridge").get("name")
    network = data["network"]
    def identities(arguments):
        values = runtime.read_query(VIRSH + arguments).splitlines()
        for value in values:
            diagnostic.canonical_uuid(value)
        if len(values) != len(set(values)):
            raise RunError("standard_inventory_duplicate")
        return set(values)
    def snapshot():
        networks = libvirt_networks(runner=runtime.read_query)
        ids, names = set(), set()
        for node in networks:
            identity, name = node.findtext("uuid"), node.findtext("name")
            diagnostic.canonical_uuid(identity)
            if (
                node.tag != "network" or len(node.findall("uuid")) != 1 or len(node.findall("name")) != 1
                or not name or identity in ids or name in names
            ):
                raise RunError("standard_network_inventory_invalid")
            ids.add(identity)
            names.add(name)
        active, persistent = identities(["net-list", "--uuid"]), identities(["net-list", "--all", "--persistent", "--uuid"])
        if identities(["net-list", "--all", "--uuid"]) != ids or active | persistent != ids:
            raise RunError("standard_network_inventory_changed")
        targets = [node for node in networks if node.findtext("uuid") == network["id"] or node.findtext("name") == network["name"]]
        present = bool(targets)
        if present:
            if require_absent or len(targets) != 1 or network["id"] not in active or network["id"] in persistent:
                raise RunError("standard_network_not_exact_active_transient")
            if normalized_xml(targets[0]) != normalized_xml(expected):
                raise RunError("standard_network_definition_changed")
        references = assert_network_unused(
            targets[0] if present else expected, network, data["subnet"], networks,
            bridge_absent=not present, runner=runtime.read_query,
            # Separate reviewed historical-checkpoint policy, not ordinary
            # cleanup provenance backfill. Former identities remain unknown.
            allow_inactive_dangling=True, owned_generation_id=data["id"],
        )
        addresses = json.loads(runtime.read_query(["ip", "-j", "address", "show"]))
        routes = {
            version: json.loads(runtime.read_query(["ip", "-j", "-" + str(version), "route", "show", "table", "all"]))
            for version in (4, 6)
        }
        if not present:
            if bridge in references[-2]:
                raise RunError("standard_kernel_bridge_remains")
            kernel_absence(addresses, routes, ipaddress.ip_network(data["subnet"]), bridge)
        return {"present": present, "references": references, "addresses": addresses, "routes": routes}
    first, second = snapshot(), snapshot()
    compare_snapshots(first, second)
    return {"network": "present" if first["present"] else "absent",
            "postcondition": None if first["present"] else absence_receipt()}


def proof(store, data: dict, identity: dict, operation: str, source_root, own_worker=None) -> tuple:
    binding, original, record = validate_record(data, identity, operation)
    recheck_pointer(store, data, identity)
    boot = processes.boot_id()
    diagnostic.canonical_uuid(boot)
    writer_barrier(data, boot, own_worker)
    producing = source.verify_source(source_root)
    current = runtime.controller(original)
    qualification = runtime.qualify_current_runtime()
    plan = {
        "protocol": PROTOCOL, "profile": runtime.PROFILE, "generation": data["id"],
        "operation": operation, "binding": binding, "boot": boot, "network": original["network"],
        "direct_identity": identity, "generated_xml_sha256": generated_xml(store, original),
        "producing_source": producing, "controller": current, "runtime": qualification,
        "claims": runtime.CLAIMS, "assumptions": runtime.ASSUMPTIONS,
    }
    if record and (record["plan"] != plan or record["plan_digest"] != digest(plan)):
        raise RunError("standard_plan_changed_new_review_required")
    writer_barrier(data, boot, own_worker)
    recheck_pointer(store, data, identity)
    return plan, original


def public_plan(plan: dict) -> dict:
    return {
        key: plan[key] for key in ("protocol", "profile", "generation", "operation", "binding", "boot", "network", "claims", "assumptions")
    } | {
        "producing_source_subset": plan["producing_source"]["subset_digest"],
        "source_location_binding": digest(plan["producing_source"]["root"]),
        "current_controller_binding": digest(plan["controller"]), "current_runtime_binding": digest(plan["runtime"]),
    }


def inspect(args, store=None) -> dict:
    result = {"eligible": False, "apply_authorized": False, "lease_release_authorized": False, "audit_written": False}
    try:
        with bound_context(args, store) as (store, run_id, identity):
            with existing_lock(store.directory(run_id) / ".resources.lock"):
                data = store.load(run_id)
                plan, original = proof(store, data, identity, args.operation, args.producing_source_root)
                record = data.get(KEY)
                if record and record["attempts"][-1]["phase"] not in ("settlement_verified", "completed"):
                    raise RunError("prior_recovery_attempt_requires_operator_review")
                with existing_lock(store.root / ".storage-graph.lock"):
                    observation = observe_network(original, require_absent=data["status"] == "cleaned")
                if store.load(run_id) != data or proof(store, data, identity, args.operation, args.producing_source_root)[0] != plan:
                    raise RunError("standard_plan_changed_new_review_required")
                result.update(
                    eligible=True, plan_digest=digest(plan), plan=public_plan(plan), observation=observation,
                    acceptance_required=runtime.PROFILE, separate_operator_apply_approval_required=True,
                )
    except (RunError, OSError, ValueError, KeyError, TypeError, AttributeError, importlib.metadata.PackageNotFoundError) as exc:
        code = str(exc) if isinstance(exc, RunError) else "standard_profile_context_or_visibility_unproven"
        result["blockers"] = [code if re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code) else "standard_profile_proof_failed"]
    return result


@contextmanager
def worker_resource_lock(path: Path):
    """Bounded handoff wait, pinning the exact existing resource lock inode."""
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        def check():
            entry = path.lstat()
            if (
                (entry.st_dev, entry.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid()
                or stat.S_IMODE(entry.st_mode) != 0o600 or entry.st_nlink != 1
            ):
                raise RunError("standard_worker_resource_lock_replaced")
        deadline = time.monotonic() + 10
        with ExitStack() as stack:
            while True:
                check()
                if time.monotonic() >= deadline:
                    raise RunError("standard_worker_resource_lock_timeout")
                try:
                    acquired = stack.enter_context(existing_lock(path))
                except RunError as exc:
                    if str(exc) != "recovery_lock_busy":
                        raise
                    time.sleep(0.05)
                    continue
                if (os.fstat(acquired).st_dev, os.fstat(acquired).st_ino) != (before.st_dev, before.st_ino):
                    raise RunError("standard_worker_resource_lock_replaced")
                break
            check()
            yield
            check()
    finally:
        os.close(fd)


def worker(store, run_id: str, operation: str, attempt_id: str, plan_digest: str) -> None:
    with worker_resource_lock(store.directory(run_id) / ".resources.lock"):
        data = store.load(run_id)
        identity = data["direct_identity"]
        validate_record(data, identity, operation)
        record = data[KEY]
        attempt = record["attempts"][-1]
        own = attempt.get("worker")
        if (
            not own or own["pid"] != os.getpid() or attempt["id"] != attempt_id
            or attempt["phase"] != "intent" or attempt["plan_digest"] != plan_digest
        ):
            raise RunError("standard_recovery_worker_not_admitted")
        location = record["plan"]["producing_source"]["root"]["path"]
        plan, original = proof(store, data, identity, operation, location, own)
        if digest(plan) != plan_digest:
            raise RunError("standard_plan_changed_new_review_required")
        with existing_lock(store.root / ".storage-graph.lock"):
            observation = observe_network(original)
            if observation["network"] == "present":
                runtime.destroy_exact_network(original["network"]["id"])
            observe_network(original, require_absent=True)
        if proof(store, store.load(run_id), identity, operation, location, own)[0] != plan:
            raise RunError("standard_plan_changed_new_review_required")
        fresh = store.load(run_id)
        validate_record(fresh, identity, operation)
        if fresh[KEY]["attempts"][-1] != attempt:
            raise RunError("standard_recovery_attempt_changed")
        fresh[KEY]["attempts"][-1].update(phase="resources_verified", evidence=absence_receipt())
        store.save(fresh)


def publish_terminal(store, data: dict, identity: dict, operation: str) -> dict:
    validate_record(data, identity, operation)
    if data[KEY]["attempts"][-1]["phase"] not in ("settlement_verified", "completed"):
        raise RunError("standard_parent_settlement_required")
    with existing_lock(store.root / ".allocator.lock"):
        data[KEY]["attempts"][-1]["phase"] = "completed"
        data["network"], data["status"] = None, "cleaned"
        data.pop("instances_ready", None)
        try:
            store.save(data)
        except Exception:
            # replace may be visible despite failed directory fsync. No rollback.
            return {
                "outcome": "terminal_commit_unconfirmed", "allocator_may_already_be_released": True,
                "fresh_inspection_required": True, "original_destroy_completed": False,
            }
    return {"outcome": "reconciled", "generation": data["id"], "original_destroy_completed": False,
            "claims": runtime.CLAIMS}


def finish_settlement(store, data, identity, operation, plan, original, location):
    attempt = data[KEY]["attempts"][-1]
    if attempt["phase"] not in ("resources_verified", "settlement_verified", "completed"):
        raise RunError("standard_parent_settlement_phase_invalid")
    if proof(store, data, identity, operation, location)[0] != plan:
        raise RunError("standard_plan_changed_new_review_required")
    with existing_lock(store.root / ".storage-graph.lock"):
        observe_network(original, require_absent=True)
    if store.load(data["id"]) != data or proof(store, data, identity, operation, location)[0] != plan:
        raise RunError("standard_plan_changed_new_review_required")
    if attempt["phase"] != "completed":
        attempt.update(phase="settlement_verified", settlement=settlement_receipt(plan, attempt))
        store.save(data)  # durable parent receipt MUST precede allocator entry
    return publish_terminal(store, data, identity, operation)


def apply(args, store=None) -> dict:
    if args.accept_profile != runtime.PROFILE:
        raise RunError("explicit_standard_profile_acceptance_required")
    if not isinstance(args.plan, str) or not re.fullmatch(r"[a-f0-9]{64}", args.plan):
        raise RunError("exact_standard_plan_digest_required")
    with bound_context(args, store) as (store, run_id, identity):
        with existing_lock(store.directory(run_id) / ".resources.lock"):
            data = store.load(run_id)
            plan, original = proof(store, data, identity, args.operation, args.producing_source_root)
            if digest(plan) != args.plan:
                raise RunError("standard_plan_changed_new_review_required")
            with existing_lock(store.root / ".storage-graph.lock"):
                observe_network(original, require_absent=data["status"] == "cleaned")
            if store.load(run_id) != data or proof(store, data, identity, args.operation, args.producing_source_root)[0] != plan:
                raise RunError("standard_plan_changed_new_review_required")
            if KEY in data:
                if data[KEY]["attempts"][-1]["phase"] in ("settlement_verified", "completed"):
                    return finish_settlement(store, data, identity, args.operation, plan, original, args.producing_source_root)
                raise RunError("prior_recovery_attempt_requires_operator_review")
            data[KEY] = {
                "protocol": PROTOCOL, "original_operation": args.operation, "binding": plan["binding"],
                "original_workers": copy.deepcopy(data["workers"]), "network": copy.deepcopy(original["network"]),
                "original_instances_ready": {"present": "instances_ready" in data, "value": data.get("instances_ready")},
                "plan": plan, "plan_digest": args.plan, "acceptance": acceptance_receipt(), "attempts": [],
            }
            attempt = {"id": str(uuid.uuid4()), "phase": "intent", "plan_digest": args.plan}
            data[KEY]["attempts"].append(attempt)
            store.save(data)
            environment = dict(runtime.recovery_commands.ENVIRONMENT)
            environment.update(
                VIRTUAL_ENV=plan["controller"]["prefix"], IDARSI_TEST_ENVIRONMENT=str(REPO),
                MOLECULE_EPHEMERAL_DIRECTORY=identity["ephemeral_directory"],
            )
            child = processes.spawn(
                store, data,
                [sys.executable, str(REPO / "scripts/scenario-context"), "_network-tail-worker",
                 run_id, args.operation, attempt["id"], args.plan],
                environment, str(REPO), operation=attempt,
            )
        try:
            code = child.wait(timeout=180)
        except subprocess.TimeoutExpired as exc:
            raise RunError("standard_recovery_worker_timeout_no_retry") from exc
        with existing_lock(store.directory(run_id) / ".resources.lock"):
            fresh = store.load(run_id)
            validate_record(fresh, identity, args.operation)
            latest = fresh[KEY]["attempts"][-1]
            if code or latest["id"] != attempt["id"] or latest["phase"] != "resources_verified":
                raise RunError("standard_recovery_worker_failed_lease_retained")
            # Actual wait success is required on this entry; retry never adopts
            # a worker-only receipt as a parent success observation.
            return finish_settlement(store, fresh, identity, args.operation, plan, original, args.producing_source_root)
