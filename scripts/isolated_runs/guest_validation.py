"""Existing-generation KVM target proof. No allocation or mutation authority."""

import argparse
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from typing import BinaryIO
import uuid

from . import admission, context
from .backends import Backend, kvm_instance
from .guest_control import ACTIONS, comparable_configuration, validate_interface
from .discovery import VIRSH, command, libvirt_networks
from .network_references import InterfaceReferences, owned_bridge
from .readonly import canonical, directory, read_file, read_molecule_state, strict_json
from .state import RunError, Store
from .guest_refusal import GuestRefusal, checked, emit, proof_lock, tagged

SCHEMA = "idarsi.scenario-context/guest-validation-v1"
INPUT_LIMIT = 16 * 1024
STATE_LIMIT = 4 * 1024 * 1024


class ExistingStore(Store):
    """Use the existing Store layout with bounded, strict private JSON reads."""

    @tagged("READONLY_STATE")
    def load(self, run_id: str) -> dict:
        data = checked("AUTHORITY_PARSE", strict_json, checked(
            "READONLY_STATE", read_file, self.directory(run_id) / "manifest.json", STATE_LIMIT,
        ))
        if (
            not isinstance(data, dict) or data.get("version") != 1
            or data.get("uid") != os.getuid() or data.get("id") != run_id
        ):
            raise GuestRefusal("AUTHORITY_PARSE")
        return data


@tagged("AUTHORITY_PARSE")
def connection(stream: BinaryIO) -> dict:
    value = stream.read(INPUT_LIMIT + 1)
    if len(value) > INPUT_LIMIT:
        raise RunError("Oversized guest connection")
    data = strict_json(value)
    if not isinstance(data, dict) or set(data) != {"address", "port", "user", "identity_file"}:
        raise RunError("Invalid guest connection fields")
    if (
        type(data["port"]) is not int or data["port"] != 22
        or not all(isinstance(data[key], str) and data[key] for key in ("address", "user", "identity_file"))
        or str(ipaddress.ip_address(data["address"])) != data["address"]
    ):
        raise RunError("Invalid guest connection values")
    if str(checked("READONLY_STATE", canonical, Path(data["identity_file"]))) != data["identity_file"]:
        raise RunError("Noncanonical key spelling")
    return data


@tagged("NATIVE_IDENTITY")
def binding(data: dict, args: argparse.Namespace) -> None:
    for field, expected in (
        ("role", str(args.role)), ("scenario", args.scenario), ("backend", "kvm"),
        ("status", "running"),
    ):
        if data.get(field) != expected:
            raise RunError("Existing generation identity mismatch")
    if data.get("storage_probe") or not isinstance(data.get("config"), dict):
        raise RunError("Incomplete generation")
    operations = data.get("operations")
    if (
        not isinstance(operations, list) or not operations
        or not all(isinstance(op, dict) for op in operations)
        or operations[0].get("action") != "create"
        # A cooperative stopped seal permits cleanup, not guest readiness.
        or operations[0].get("outcome") == "stopped"
        or any(op.get("action") not in ACTIONS for op in operations[1:])
        or any(not isinstance(op.get("id"), str) or not op["id"] for op in operations)
        or len({op["id"] for op in operations}) != len(operations)
    ):
        raise RunError("No completed create")
    context.require_completed(data, quiescent=False)
    for operation in operations:
        worker = operation.get("worker")
        if (
            not isinstance(worker, dict) or set(worker) != {"pid", "start", "boot"}
            or type(worker["pid"]) is not int or worker["pid"] <= 1
            or not isinstance(worker["start"], str) or not worker["start"]
            or not isinstance(worker["boot"], str) or not worker["boot"]
        ):
            raise RunError("Malformed recorded mutation worker")
    if data["mode"] == "direct":
        if data.get("context_publication") != "published" or not data.get("instances_ready"):
            raise RunError("Unpublished direct instance mapping")
    elif (
        data["mode"] != "supervised" or data.get("mutation_protocol") != "sealed-v1"
        or data.get("admission_protocol") != admission.PROTOCOL
    ):
        raise RunError("Unsupported generation shape")


@tagged("NETWORK_OBSERVATION")
def observations(backend: Backend, guest: dict, address: str) -> None:
    """Only fresh read-only native observations; no SSH or peer-key attestation."""
    data = backend.data
    if data["context"].get("libvirt") != "qemu:///system":
        raise GuestRefusal("NATIVE_IDENTITY")
    for disk in backend.disks(guest):
        if checked("NATIVE_IDENTITY", backend.verify_disk, disk) is None:
            raise GuestRefusal("NATIVE_IDENTITY")
    root = checked("NATIVE_IDENTITY", backend.owned_domain, guest)
    if (
        root is None or root.tag != "domain" or len(root.findall("uuid")) != 1
        or root.findtext("uuid") != guest["id"] or len(root.findall("name")) != 1
        or len(root.findall("description")) != 1 or len(root.findall("devices")) != 1
    ):
        raise GuestRefusal("NATIVE_IDENTITY")
    if checked("NATIVE_IDENTITY", command, VIRSH + ["domstate", guest["id"]], env={**os.environ, "LC_ALL": "C"}) != "running":
        raise GuestRefusal("NATIVE_IDENTITY")
    networks = libvirt_networks()
    intent = data["network"]
    matches = [net for net in networks if (
        net.findtext("uuid") == intent["id"] or net.findtext("name") == intent["name"]
    )]
    if len(matches) != 1:
        raise RunError("Missing or replaced owned network")
    bridge = owned_bridge(matches[0], intent, data["subnet"])
    active = command(VIRSH + ["net-list", "--uuid"]).splitlines()
    if (
        len(active) != len(set(active)) or any(str(uuid.UUID(item)) != item for item in active)
        or intent["id"] not in active
    ):
        raise RunError("Owned network is not active")
    interfaces = root.findall("./devices/interface")
    validate_interface(root, intent, bridge)
    interface = interfaces[0]
    if (
        interface.findall("virtualport")
        or any(link.get("state") != "up" for link in interface.findall("link"))
    ):
        raise RunError("Guest live interface is not the owned network")
    links = InterfaceReferences(bridge, intent, networks)
    links.load_links()
    ordinary = links.links[bridge]
    # Keep ordinary cleanup snapshots unchanged. Only this target proof needs
    # detailed linkinfo, and it must describe the same fresh kernel identity.
    details = strict_json(command(["ip", "-d", "-j", "link", "show", "dev", bridge]))
    if not isinstance(details, list) or len(details) != 1 or not isinstance(details[0], dict):
        raise RunError("Owned bridge observation is incomplete")
    detailed = details[0]
    if (
        ordinary.get("ifname") != bridge
        or not isinstance(ordinary.get("address"), str)
        or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", ordinary["address"])
        or detailed.get("ifname") != bridge
        or type(detailed.get("ifindex")) is not int
        or detailed["ifindex"] != ordinary["ifindex"]
        or detailed.get("address") != ordinary["address"]
        or not isinstance(detailed.get("linkinfo"), dict)
        or detailed["linkinfo"].get("info_kind") != "bridge"
    ):
        raise RunError("Owned bridge observation is incomplete")
    target = ipaddress.ip_address(address)
    if target.is_loopback or target.is_unspecified or target.is_multicast:
        raise RunError("Unsafe guest address")
    addresses = strict_json(command(["ip", "-j", "address", "show"]))
    if not isinstance(addresses, list) or not addresses:
        raise RunError("Incomplete controller address discovery")
    for item in addresses:
        if not isinstance(item, dict) or not isinstance(item.get("addr_info"), list):
            raise RunError("Incomplete controller address discovery")
        for assigned in item["addr_info"]:
            if not isinstance(assigned, dict) or assigned.get("family") not in ("inet", "inet6"):
                raise RunError("Incomplete controller address discovery")
            local = ipaddress.ip_address(assigned["local"])
            if local == target:
                raise RunError("Guest address belongs to controller")


def validate(args: argparse.Namespace, supplied: dict, store: Store) -> dict:
    """Lock an existing context before asking installed Molecule for its config."""
    args.role = checked("READONLY_STATE", canonical, Path(args.role))
    checked("READONLY_STATE", directory, args.role)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.scenario):
        raise GuestRefusal("AUTHORITY_PARSE")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,62}", args.platform):
        raise GuestRefusal("AUTHORITY_PARSE")
    ephemeral = checked("READONLY_STATE", directory, Path(os.environ.get("MOLECULE_EPHEMERAL_DIRECTORY", "")))
    checked("READONLY_STATE", directory, ephemeral / "inventory")
    checked("READONLY_STATE", read_molecule_state, ephemeral / "state.yml", STATE_LIMIT)
    checked("READONLY_STATE", directory, store.root, private=True)
    markers = any(key == "IDARSI_RUN_ID" or key.startswith("IDARSI_HANDOFF") for key in os.environ)
    result = {
        "role": str(args.role), "scenario": args.scenario, "backend": "kvm",
        "ephemeral_directory": str(ephemeral),
    }
    with contextlib.ExitStack() as stack:
        if markers:
            if (
                os.environ.get("IDARSI_HANDOFF") != "v1" or not os.environ.get("IDARSI_RUN_ID")
                or any(key.startswith("IDARSI_HANDOFF") and key != "IDARSI_HANDOFF" for key in os.environ)
            ):
                raise GuestRefusal("AUTHORITY_PARSE")
            run_id = os.environ["IDARSI_RUN_ID"]
            if store.ephemeral(run_id) != ephemeral:
                raise GuestRefusal("AUTHORITY_PARSE")
        else:
            path, identity = context.existing_pointer_path(store, result)
            checked("READONLY_STATE", directory, path.parent, private=True)
            stack.enter_context(proof_lock(path.with_suffix(".lock")))
            pointer = checked("AUTHORITY_PARSE", strict_json, checked("READONLY_STATE", read_file, path, INPUT_LIMIT))
            if not isinstance(pointer, dict) or set(pointer) != {"identity", "generation"} or pointer["identity"] != identity:
                raise GuestRefusal("AUTHORITY_PARSE")
            run_id = pointer["generation"]
        stack.enter_context(proof_lock(checked("READONLY_STATE", store.directory, run_id) / ".resources.lock"))
        data = store.load(run_id)
        if markers != (data.get("mode") == "supervised"):
            raise GuestRefusal("AUTHORITY_PARSE")
        binding(data, args)
        if not markers and (
            data.get("direct_identity") != identity
            or data.get("direct_context", {}).get("generation") != run_id
            or any(data["direct_context"].get(key) != value for key, value in result.items())
        ):
            raise GuestRefusal("NATIVE_IDENTITY")
        if markers:
            checked("AUTHORITY_PARSE", admission.validate_existing, store, run_id, {
                "id": run_id, "role": str(args.role), "scenario": args.scenario,
                "backend": "kvm", "ephemeral": str(ephemeral),
            }, _existing_lock=proof_lock)
        from .existing_config import parse_existing_configuration

        config = parse_existing_configuration(args.role, args.scenario, dict(os.environ), ephemeral)
        resolved, config = checked(
            "AUTHORITY_PARSE", context.resolved, args, store, existing_config=config, _existing_lock=proof_lock,
        )
        if resolved["mode"] != ("supervised" if markers else "direct"):
            raise GuestRefusal("AUTHORITY_PARSE")
        if (
            config.get("_idarsi_effective_ephemeral") != str(ephemeral)
            or comparable_configuration(config) != comparable_configuration(data["config"])
        ):
            raise GuestRefusal("AUTHORITY_PARSE")
        if markers:
            stack.enter_context(proof_lock(store.directory(run_id) / ".admission.lock"))
            control = admission.validate_gate(checked("AUTHORITY_PARSE", strict_json, checked(
                "READONLY_STATE", read_file, store.directory(run_id) / "admission.json", INPUT_LIMIT,
            )), run_id)
            if control["state"] != "open":
                raise GuestRefusal("AUTHORITY_PARSE")
        platforms = config["platforms"]
        if len([item for item in platforms if item["name"] == args.platform]) != 1:
            raise GuestRefusal("SSH_MAPPING")
        guests = data["guests"]
        if (
            not isinstance(guests, list) or len(guests) != len(platforms)
            or [guest["logical"] for guest in guests] != [item["name"] for item in platforms]
            or len({guest["name"] for guest in guests}) != len(guests)
            or len({guest["id"] for guest in guests}) != len(guests)
        ):
            raise GuestRefusal("NATIVE_IDENTITY")
        for guest in guests:
            if not re.fullmatch(r"itr-[a-f0-9]{32}", guest["name"]) or str(uuid.UUID(guest["id"])) != guest["id"]:
                raise GuestRefusal("NATIVE_IDENTITY")
        key = store.directory(run_id) / "kvm_ed25519"
        checked("READONLY_STATE", read_file, key, INPUT_LIMIT, contents=False)
        expected = [kvm_instance(item, data["subnet"], index, key) for index, item in enumerate(platforms)]
        artifact = ephemeral / "instance_config.yml"
        checked("READONLY_STATE", canonical, artifact)
        if os.environ.get("MOLECULE_INSTANCE_CONFIG") != str(artifact):
            raise GuestRefusal("SSH_MAPPING")
        actual = checked("SSH_MAPPING", strict_json, checked("READONLY_STATE", read_file, artifact, STATE_LIMIT))
        if actual != expected or any(
            not isinstance(item, dict) or set(item) != set(expected[0])
            or not all(isinstance(value, str) for value in item.values()) for item in actual
        ):
            raise GuestRefusal("SSH_MAPPING")
        if data.get("instances_ready") != expected:
            raise GuestRefusal("SSH_MAPPING")
        index = next(index for index, item in enumerate(platforms) if item["name"] == args.platform)
        target = expected[index]
        disks = guests[index].get("disks")
        specs = [{"name": "root"}] + platforms[index].get("data_disks", [])
        if (
            not isinstance(disks, list) or len(disks) != len(specs)
            or [disk.get("name") for disk in disks] != [spec["name"] for spec in specs]
            or any(
                disk.get("serial") != "itr-" + spec["name"]
                or type(disk.get("device")) is not int or type(disk.get("inode")) is not int
                for disk, spec in zip(disks, specs)
            )
        ):
            raise GuestRefusal("NATIVE_IDENTITY")
        if supplied != {**{key: target[key] for key in ("address", "user", "identity_file")}, "port": 22}:
            raise GuestRefusal("SSH_MAPPING")
        observations(Backend(store, data), guests[index], target["address"])
        if store.load(run_id) != data:
            raise GuestRefusal("NATIVE_IDENTITY")
    return {
        "schema": SCHEMA, "role": str(args.role), "scenario": args.scenario,
        "generation": run_id, "platform": args.platform, "backend": "kvm", "validated": True,
    }


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise GuestRefusal("AUTHORITY_PARSE")


def main(argv=None) -> int:
    try:
        parser = Parser(description=__doc__, allow_abbrev=False, add_help=False)
        parser.add_argument("--backend", required=True, choices=("kvm",))
        parser.add_argument("--role", required=True)
        parser.add_argument("--scenario", required=True)
        parser.add_argument("--platform", required=True)
        args = parser.parse_args(argv)
        supplied = connection(sys.stdin.buffer)
        result = validate(args, supplied, checked("READONLY_STATE", ExistingStore.open_existing))
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        emit(error)
        return 1
