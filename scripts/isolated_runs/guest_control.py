"""Sealed, generation-owned KVM power control without storage removal."""

import os
from pathlib import Path
import re
import shlex
import sys
import uuid
import xml.etree.ElementTree as ET

from . import admission
from .backends import Backend, REPO
from .discovery import VIRSH, command, libvirt_networks
from .network_references import owned_bridge
from .processes import spawn, stop_workers
from .state import RunError, lock
from .storage_references import (
    assert_owned_domain_unused, assert_pending_unused, image_chain, validated_chain, xml_evidence,
)

PROTOCOL = "owned-kvm-v1"
ACTIONS = ("guest-stop", "guest-start")


def comparable_configuration(config: dict) -> dict:
    """Normalize only relocation of Molecule's own effective ephemeral root.

    Keep every configuration field and environment export in the comparison;
    the caller separately proves the current root's generation binding.
    """
    ephemeral = config.get("_idarsi_effective_ephemeral")
    if not isinstance(ephemeral, str) or not Path(ephemeral).is_absolute():
        return config
    def path_value(value):
        # Lexical containment only: never adopt or resolve filesystem objects.
        # Even an internally cancelling traversal may refer outside the root.
        if ".." in value.split("/"):
            return value
        if value == ephemeral or value.startswith(ephemeral + "/"):
            # Configs originate as JSON: a typed tuple cannot collide with a
            # caller's literal placeholder string or list/dict value.
            return ("idarsi.ephemeral-path/v1", value[len(ephemeral):])
        return value

    def dependency_command(value):
        # Preserve the command's spelling/quoting and every unrelated argument.
        # Only the role's explicit path arguments are relocation fields. Simple
        # quoted tokens support spaces; escapes/unsupported forms stay literal.
        token_pattern = re.compile(r"""(?:[^\s"'\\]+|"[^"\\]*"|'[^']*')+""")
        matches = list(token_pattern.finditer(value))
        position, tokens = 0, []
        for match in matches:
            if value[position:match.start()].strip():
                return value
            parsed = shlex.split(match.group(), posix=True)
            if len(parsed) != 1:
                return value
            tokens.append(parsed[0])
            position = match.end()
        if value[position:].strip():
            return value
        replacements = []
        for index, option in enumerate(tokens[:-1]):
            if option not in ("--ephemeral-directory", "--molecule-file"):
                continue
            raw, decoded = matches[index + 1].group(), tokens[index + 1]
            normalized = path_value(decoded)
            if normalized == decoded:
                continue
            if raw == decoded:
                start, end = matches[index + 1].start(), matches[index + 1].end()
            elif raw in ('"' + decoded + '"', "'" + decoded + "'"):
                start, end = matches[index + 1].start() + 1, matches[index + 1].end() - 1
            else:
                return value
            replacements.append((start, end, normalized))
        if not replacements:
            return value
        parts, position = [], 0
        for start, end, replacement in replacements:
            parts.extend((value[position:start], replacement))
            position = end
        parts.append(value[position:])
        return ("idarsi.dependency-command/v1", tuple(parts))

    def normalize(value, location=()):
        if isinstance(value, str):
            if location == ("dependency", "command"):
                return dependency_command(value)
            return path_value(value)
        if isinstance(value, list):
            return [normalize(item, location + (index,)) for index, item in enumerate(value)]
        if isinstance(value, dict):
            return {key: normalize(item, location + (key,)) for key, item in value.items()}
        return value

    return normalize(config)


def validate_intent(operation: dict) -> None:
    """Reject unsupported dispatch and malformed durable target identities."""
    for key in ("id", "domain_uuid"):
        value = operation.get(key)
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise RunError("Invalid guest-control operation identity")
    worker = operation.get("worker", {})
    if (
        operation.get("action") not in ACTIONS or operation.get("protocol") != PROTOCOL
        or not isinstance(operation.get("guest"), str) or not operation["guest"]
        or not isinstance(worker, dict)
        or set(worker) != {"pid", "start", "boot"} or type(worker["pid"]) is not int
        or worker["pid"] <= 1 or not isinstance(worker["start"], str) or not worker["start"]
        or not isinstance(worker["boot"], str) or not worker["boot"]
    ):
        raise RunError("Invalid guest-control operation intent")


def validate_operation(operation: dict, data: dict) -> None:
    """Validate a completed guest mutation, not merely its completion token."""
    validate_intent(operation)
    result = operation.get("result", {})
    expected = "shut-off" if operation["action"] == "guest-stop" else "running"
    guests = [g for g in data["config"]["platforms"] if g.get("name") == operation.get("guest")]
    recorded = [g for g in data["guests"] if g.get("logical") == operation["guest"]]
    if (
        len(guests) != 1
        or (data["guests"] and (len(recorded) != 1 or recorded[0]["id"] != operation["domain_uuid"]))
        or not isinstance(result, dict)
        or result.get("state") != expected or type(result.get("changed")) is not bool
        or result.get("operation") != operation["id"]
        or result.get("guest") != operation["guest"]
        or result.get("action") != operation["action"]
    ):
        raise RunError("Invalid completed guest-control operation")


def target(data: dict, result: dict, config: dict, logical: str) -> dict:
    """Require the original running generation and exactly one declared guest."""
    from .context import require_completed

    require_completed(data, quiescent=False)
    if (
        data["status"] != "running" or data["backend"] != "kvm"
        or comparable_configuration(data["config"]) != comparable_configuration(config)
        or (
            "_idarsi_effective_ephemeral" in config
            and config["_idarsi_effective_ephemeral"] != result["ephemeral_directory"]
        )
        or any(data[key] != result[key] for key in ("role", "scenario", "backend"))
        or not any(op["action"] == "create" for op in data["operations"])
        or any(op["action"] == "destroy" for op in data["operations"])
        or not data.get("instances_ready")
    ):
        raise RunError("Guest control requires an unchanged successfully created generation")
    configured = [p for p in config["platforms"] if p["name"] == logical]
    guests = [g for g in data["guests"] if g.get("logical") == logical]
    if len(configured) != 1 or len(guests) != 1:
        raise RunError("Guest must uniquely match configuration and generation")
    if len([item for item in data["instances_ready"] if item.get("instance") == logical]) != 1:
        raise RunError("Guest has no unique completed instance mapping")
    return guests[0]


def validate_interface(root, network: dict, bridge: str) -> None:
    """Check all supplied network-source evidence, including resolved live XML."""
    interfaces = root.findall("./devices/interface")
    if len(interfaces) != 1:
        raise RunError("Guest network attachment changed")
    interface = interfaces[0]
    sources = interface.findall("source")
    if interface.get("type") != "network" or len(sources) != 1:
        raise RunError("Guest network source is unsupported or ambiguous")

    def source(node, required: str) -> None:
        allowed = {"network": network["name"], "bridge": bridge}
        if node.get(required) != allowed[required] or len(node):
            raise RunError("Guest network source changed")
        for key, value in node.attrib.items():
            if key == "portid":
                if str(uuid.UUID(value)) != value:
                    raise RunError("Guest network port identity is invalid")
            elif key not in allowed or value != allowed[key]:
                raise RunError("Guest network source evidence is contradictory")

    source(sources[0], "network")
    actuals = interface.findall("actual")
    if len(actuals) > 1:
        raise RunError("Guest has ambiguous resolved network sources")
    if actuals:
        actual = actuals[0]
        if actual.attrib != {"type": "bridge"} or len(actual.findall("source")) != 1:
            raise RunError("Guest resolved network source is unsupported")
        if any(child.tag != "source" for child in actual):
            raise RunError("Guest resolved network evidence is unsupported")
        source(actual.find("source"), "bridge")


def inspect_domain(backend: Backend, guest: dict) -> str:
    """Validate both definitions, owned network, inodes and authorized graphs."""
    data = backend.data
    identity = guest["id"]
    if str(uuid.UUID(identity)) != identity or not re.fullmatch(r"itr-[a-f0-9]{32}", guest["name"]):
        raise RunError("Invalid owned domain identity")
    if identity not in command(VIRSH + ["list", "--all", "--persistent", "--uuid"]).splitlines():
        raise RunError("Guest control requires the existing persistent domain")
    saved = re.findall(r"^Managed save:\s+(yes|no)\s*$", command(VIRSH + ["dominfo", identity]), re.MULTILINE)
    if saved != ["no"]:
        raise RunError("Guest managed-save state is present or uncertain")
    state = command(VIRSH + ["domstate", identity])
    if state not in ("running", "shut off", "shutoff"):
        raise RunError("Unsupported guest power state")
    network = data["network"]
    matches = [root for root in libvirt_networks() if (
        root.findtext("uuid") == network["id"] or root.findtext("name") == network["name"]
    )]
    if len(matches) != 1:
        raise RunError("Owned guest network is absent or ambiguous")
    bridge = owned_bridge(matches[0], network, data["subnet"])
    disks = backend.disks(guest)
    if not disks:
        raise RunError("Guest has no authorized disks")
    with backend.storage.directory() as directory_fd:
        for disk in disks:
            if backend.storage.verify(disk, directory_fd) is None:
                raise RunError("Owned guest disk is missing")
    for inactive in (False, True):
        root = ET.fromstring(command(VIRSH + ["dumpxml", identity] + (["--inactive"] if inactive else [])))
        for field, value in (
            ("uuid", identity), ("name", guest["name"]), ("description", "idarsi-run:" + data["id"]),
        ):
            if len(root.findall(field)) != 1 or root.findtext(field) != value:
                raise RunError("Guest live/persistent ownership mismatch")
        backend.verify_attachments(guest, root)
        allowed_devices = {
            "emulator", "disk", "controller", "interface", "serial", "console",
            "input", "graphics", "video", "audio", "sound", "memballoon", "rng",
            "watchdog", "panic",
        }
        if (
            len(root.findall("devices")) != 1
            or any(node.tag not in allowed_devices for node in root.find("devices"))
            or root.find("./os/nvram") is not None
        ):
            raise RunError("Guest has unsupported storage-bearing devices")
        validate_interface(root, network, bridge)
        evidence = xml_evidence(root, state == "running" and not inactive)
        if len(evidence) != len(disks):
            raise RunError("Guest has additional storage attachments")
        for disk in disks:
            chain = validated_chain(disk["image_chain"])
            if chain[0] != {
                "path": disk["path"], "device": disk["device"],
                "inode": disk["inode"], "format": "qcow2",
            }:
                raise RunError("Guest disk chain ownership changed")
            entries = [entry for entry in evidence if entry["head"] == disk["path"]]
            if len(entries) != 1:
                raise RunError("Guest storage graph is ambiguous")
            entry = entries[0]
            if (
                entry["chain"] != chain[:len(entry["chain"])]
                or any(str(path) not in {item["path"] for item in chain} for path in entry["refs"])
                or (entry["structurally_complete"] and entry["chain"] != chain)
            ):
                raise RunError("Guest storage graph changed")
            if state != "running":
                if image_chain(Path(disk["path"]))["members"] != chain:
                    raise RunError("Inactive guest image headers changed")
            elif not inactive and not entry["complete"]:
                raise RunError("Running guest lacks complete live storage evidence")
    return "running" if state == "running" else "shut-off"


def execute(store, data: dict, operation: dict) -> dict:
    """Caller holds resources; graph lock bounds validation and exact-UUID RPC."""
    validate_intent(operation)
    backend = Backend(store, data)
    if data["context"].get("libvirt") != "qemu:///system":
        raise RunError("Unsupported libvirt context")
    guests = [g for g in data["guests"] if g.get("logical") == operation["guest"]]
    if len(guests) != 1 or guests[0]["id"] != operation["domain_uuid"]:
        raise RunError("Guest mutation target changed")
    guest = guests[0]
    with lock(store.root / ".storage-graph.lock"):
        before = inspect_domain(backend, guest)
        assert_exclusive(backend, guest)
        desired = "shut-off" if operation["action"] == "guest-stop" else "running"
        changed = before != desired
        if changed:
            command(VIRSH + ["destroy" if desired == "shut-off" else "start", guest["id"]], timeout=60)
        if inspect_domain(backend, guest) != desired:
            raise RunError("Guest power transition was not confirmed")
    return {
        "action": operation["action"], "guest": operation["guest"],
        "operation": operation["id"], "changed": changed, "state": desired,
    }


def assert_exclusive(backend: Backend, guest: dict) -> None:
    """Reject pending managed claims and observable foreign disk consumers."""
    data = backend.data
    active = command(VIRSH + ["list", "--uuid"]).splitlines()
    persistent = command(VIRSH + ["list", "--all", "--persistent", "--uuid"]).splitlines()
    for disk in backend.disks(guest):
        assert_pending_unused(backend.store, data["context"], data["id"], disk)
        for identity in command(VIRSH + ["list", "--all", "--uuid"]).splitlines():
            if identity == guest["id"]:
                continue
            live = ET.fromstring(command(VIRSH + ["dumpxml", identity])) if identity in active else None
            defined = ET.fromstring(command(VIRSH + ["dumpxml", identity, "--inactive"])) if identity in persistent else None
            if live is None and defined is None:
                raise RunError("Foreign domain changed during guest storage discovery")
            assert_owned_domain_unused(
                live, defined, disk, backend.store, data["context"], data["id"],
                guest["id"], backend.storage.root,
            )


def seal(store, run_id: str, operation: dict, outcome: dict) -> None:
    """Never seal an interrupted, substituted or failed mutation."""
    data = store.load(run_id)
    if data["operations"][-1] != operation:
        raise RunError("Guest mutation journal changed before completion")
    completed = data["operations"][-1]
    completed["result"] = outcome
    completed["completion"] = completed["id"]
    validate_operation(completed, data)
    store.save(data)


def control(args, store, result: dict, config: dict) -> dict:
    """Use existing direct workers or the admitted supervised current session."""
    from .context import pointer_path, read_private, require_completed

    if result["mode"] == "supervised":
        run_id = result["generation"]
        expected = {key: result[key] for key in ("role", "scenario", "backend")}
        expected.update(id=run_id, ephemeral=result["ephemeral_directory"])
        with lock(store.directory(run_id) / ".resources.lock"):
            with admission.mutation_boundary(store, run_id, expected) as (data, worker):
                guest = target(data, result, config, args.guest)
                operation = intent(args, guest, worker)
                data["operations"].append(operation)
                store.save(data)
            outcome = execute(store, data, operation)
            seal(store, run_id, operation, outcome)
        return dict(result, **outcome)
    path, identity = pointer_path(store, result)
    with lock(path.with_suffix(".lock")):
        pointer = read_private(path)
        if pointer["identity"] != identity:
            raise RunError("Direct context identity mismatch")
        run_id = pointer["generation"]
        result["generation"] = run_id
        with lock(store.directory(run_id) / ".supervisor.lock", blocking=False):
            stop_workers(store.load(run_id))
            with lock(store.directory(run_id) / ".resources.lock", blocking=False):
                data = store.load(run_id)
                require_completed(data)
                if data.get("mode") != "direct" or data.get("direct_identity") != identity:
                    raise RunError("Direct generation provenance mismatch")
                guest = target(data, result, config, args.guest)
                operation = intent(args, guest)
                data["operations"].append(operation)
                child = spawn(
                    store, data, [sys.executable, str(REPO / "scripts/scenario-context"),
                                  "_worker", run_id, operation["id"], args.action],
                    dict(os.environ), result["role"], operation=operation,
                )
            code = child.wait()
            stop_workers(store.load(run_id))
            with lock(store.directory(run_id) / ".resources.lock", blocking=False):
                data = store.load(run_id)
                require_completed(data)
                if code or data["operations"][-1]["id"] != operation["id"]:
                    raise RunError("Guest mutation worker failed; lease retained")
                return dict(result, **data["operations"][-1]["result"])


def intent(args, guest: dict, worker=None) -> dict:
    """Create immutable target intent before any backend mutation."""
    operation = {
        "id": str(uuid.uuid4()), "action": args.action, "protocol": PROTOCOL,
        "guest": args.guest, "domain_uuid": guest["id"],
    }
    if worker is not None:
        operation["worker"] = worker
    return operation
