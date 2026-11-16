"""Fail-closed resolution of local libvirt disk and backing-file references."""

import json
from pathlib import Path
import re
import stat
import uuid
import xml.etree.ElementTree as ET

from .discovery import VIRSH, command
from .state import RunError
from .storage import PRIVATE_POLICY, PUBLICATION_PROTOCOL, STORAGE, Storage


def local_path(value: str, parent: Path = None) -> Path:
    """Resolve local absolute paths, or explicit relative backing paths."""
    if not isinstance(value, str) or not value:
        raise RunError("Empty or unsupported storage reference")
    path = Path(value)
    if not path.is_absolute():
        if parent is None or ":" in value:
            raise RunError("Storage reference is not a resolvable local path")
        path = parent.parent / path
    return path.resolve(strict=True)


def backing_paths(node, parent: Path) -> list:
    """Resolve both domain backingStore/source and volume backingStore/path."""
    result = []
    # Iterative traversal also bounds unexpectedly deep backend XML.
    backing = node.find("backingStore")
    for _ in range(64):
        if len(node.findall("backingStore")) > 1:
            raise RunError("Ambiguous volume backing store")
        if backing is None:
            return result
        if len(backing) == 0 and not backing.attrib:
            return result  # Explicit chain terminator.
        if backing.get("type", "file") not in ("file", "block"):
            raise RunError("Unsupported backing-store type")
        if (
            any(child.tag not in ("source", "path", "format", "backingStore") for child in backing)
            or len(backing.findall("source")) + len(backing.findall("path")) != 1
        ):
            raise RunError("Malformed volume backing-store source")
        formats = backing.findall("format")
        if len(formats) > 1 or (formats and formats[0].get("type") not in ("raw", "qcow2")):
            raise RunError("Unsupported volume backing-store format")
        source = backing.find("source")
        if source is not None:
            paths = source_paths(source, parent)
            if len(paths) != 1:
                raise RunError("Ambiguous backing-store source")
            path = paths[0]
        else:
            path = local_path(backing.findtext("path"), parent)
        result.append(path)
        parent = path
        node = backing
        backing = backing.find("backingStore")
    raise RunError("Backing chain is too deep to resolve safely")


def source_paths(source, parent: Path = None) -> list:
    """Resolve file, device, or checked libvirt pool/volume references."""
    if any(child.tag != "seclabel" for child in source):
        raise RunError("Unsupported storage source child")
    kinds = [key for key in ("file", "dev", "pool", "protocol", "name") if source.get(key)]
    allowed = {
        "file": {"file", "startupPolicy", "index"},
        "dev": {"dev", "startupPolicy", "index"},
        "pool": {"pool", "volume", "mode", "startupPolicy", "index"},
    }
    if len(kinds) != 1 or set(source.attrib) - allowed.get(kinds[0], set()):
        raise RunError("Unsupported or ambiguous storage source attributes")
    if kinds == ["file"]:
        return [local_path(source.get("file"), parent)]
    if kinds == ["dev"]:
        return [local_path(source.get("dev"), parent)]
    if kinds == ["pool"] and source.get("volume"):
        pool, volume = source.get("pool"), source.get("volume")
        if pool.startswith("-") or volume.startswith("-"):
            raise RunError("Unsupported pool/volume identifier")
        path = local_path(command(VIRSH + ["vol-path", "--pool", pool, "--vol", volume]))
        root = ET.fromstring(command(VIRSH + ["vol-dumpxml", "--pool", pool, "--vol", volume]))
        if root.tag != "volume":
            raise RunError("Unexpected libvirt volume definition")
        if len(root.findall("target")) != 1 or len(root.findall("./target/path")) != 1:
            raise RunError("Ambiguous libvirt volume target")
        formats = root.findall("./target/format")
        if len(formats) > 1 or (formats and formats[0].get("type") not in ("raw", "qcow2")):
            raise RunError("Unsupported libvirt volume format")
        target = local_path(root.findtext("./target/path"))
        if target != path:
            raise RunError("Libvirt volume path and definition disagree")
        return [path] + backing_paths(root, path)
    raise RunError("Unsupported or unresolvable storage source")


def image_chain(path: Path, *, before_start: bool = False) -> dict:
    """Capture the complete readable header chain; never override sharing locks."""
    info = path.stat()
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISBLK(info.st_mode)):
        raise RunError("Unsupported local storage object")
    chain = json.loads(command([
        "qemu-img", "info", "--backing-chain", "--output=json", str(path),
    ]))
    if not isinstance(chain, list) or not chain or len(chain) > 64:
        raise RunError("Incomplete image backing-chain query")
    paths = []
    expected = path
    for entry in chain:
        if not isinstance(entry, dict) or entry.get("format") not in ("raw", "qcow2"):
            raise RunError("Unsupported or ambiguous backing image format")
        specific = entry.get("format-specific", {})
        if not isinstance(specific, dict) or not isinstance(specific.get("data", {}), dict):
            raise RunError("Malformed image format details")
        if specific.get("data", {}).get("data-file"):
            raise RunError("External-data image references require manual reconciliation")
        actual = local_path(entry.get("filename"))
        if actual != expected:
            raise RunError("Image backing-chain identity disagrees with its parent")
        paths.append(member(actual, entry["format"]))
        backing = entry.get("full-backing-filename") or entry.get("backing-filename")
        expected = local_path(backing, actual) if backing else None
    if expected is not None:
        raise RunError("Incomplete backing chain; cannot prove disk is unused")
    return {
        "version": 1, "complete": True, "members": paths,
        "provenance": "qemu-img-before-start" if before_start else "qemu-img-header-query",
    }


def image_paths(path: Path) -> list:
    """Compatibility wrapper for callers needing paths only."""
    return [Path(item["path"]) for item in image_chain(path)["members"]]


def member(path: Path, image_format) -> dict:
    info = path.stat()
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISBLK(info.st_mode)):
        raise RunError("Unsupported storage object")
    return {"path": str(path), "device": info.st_dev, "inode": info.st_ino, "format": image_format}


def validated_chain(record: dict) -> list:
    """Validate durable capture structure and every current inode, without opening images."""
    if not isinstance(record, dict) or (
        record.get("version") != 1 or record.get("complete") is not True
        or record.get("provenance") != "qemu-img-before-start"
    ):
        raise RunError("Incomplete or unrecognized managed image-chain evidence")
    chain = record.get("members")
    if not isinstance(chain, list) or not 1 <= len(chain) <= 64:
        raise RunError("Invalid managed image-chain members")
    seen = set()
    for item in chain:
        if not isinstance(item, dict) or item.get("format") not in ("raw", "qcow2"):
            raise RunError("Unsupported managed image-chain member")
        if type(item.get("device")) is not int or type(item.get("inode")) is not int or item["inode"] <= 0:
            raise RunError("Invalid managed image-chain inode identity")
        path = local_path(item.get("path"))
        if str(path) != item["path"] or member(path, item["format"]) != item:
            raise RunError("Managed image-chain inode or canonical path changed")
        identity = (item["device"], item["inode"])
        if identity in seen:
            raise RunError("Cyclic or duplicate managed image-chain member")
        seen.add(identity)
    # Raw cannot have a backing file. A qcow2 leaf is valid only because the
    # original qemu-img query proved termination AND live evidence must match.
    if any(item["format"] == "raw" for item in chain[:-1]):
        raise RunError("Truncated or contradictory managed image chain")
    return chain


def xml_evidence(root, live: bool) -> list:
    """Return explicit references plus independently qualified completeness.

    Only authorized live XML can prove a chain complete. An explicit empty
    backingStore terminates qcow2; omission is unknown. Ordinary local raw
    files may terminate by format. Persistent XML never substitutes for fresh
    image evidence on inactive domains.
    """
    evidence = []
    if root.tag != "domain" or len(root.findall("devices")) != 1:
        raise RunError("Malformed foreign domain storage definition")
    for disk in root.findall("./devices/disk"):
        if disk.find("mirror") is not None or disk.find(".//dataStore") is not None:
            raise RunError("Unsupported mirror or external-data storage")
        source = disk.find("source")
        if source is None and disk.get("device") in ("cdrom", "floppy"):
            continue
        if len(disk.findall("source")) != 1 or len(disk.findall("driver")) > 1:
            raise RunError("Malformed disk source/driver definition")
        if source is None or disk.get("type", "file") not in ("file", "block", "volume"):
            raise RunError("Unresolvable foreign storage")
        refs = source_paths(source)
        path = refs[0]
        driver = disk.find("driver")
        image_format = driver.get("type") if driver is not None else None
        chain = []
        container = disk
        complete = False
        for _ in range(64):
            if image_format is not None and image_format not in ("raw", "qcow2"):
                raise RunError("Unsupported XML image format")
            chain.append(member(path, image_format))
            backing = container.find("backingStore")
            if len(container.findall("backingStore")) > 1:
                raise RunError("Ambiguous XML backing chain")
            if backing is None:
                complete = (
                    image_format == "raw" and container.get("type", "file") == "file"
                    and stat.S_ISREG(path.stat().st_mode)
                )
                break
            if len(backing) == 0 and not backing.attrib and not (backing.text or "").strip():
                complete = True
                break
            if image_format == "raw" or backing.get("type") not in ("file", "block"):
                raise RunError("Contradictory or unsupported XML backing store")
            if (
                len(backing.findall("source")) != 1 or len(backing.findall("format")) != 1
                or any(child.tag not in ("source", "format", "backingStore") for child in backing)
            ):
                raise RunError("Malformed XML backing store")
            extra = source_paths(backing.find("source"), path)
            refs.extend(extra)
            path = extra[0]
            image_format = backing.find("format").get("type")
            if image_format is None:
                raise RunError("Backing-store format is missing")
            container = backing
        else:
            raise RunError("XML backing chain exceeds the supported depth")
        evidence.append({
            "head": chain[0]["path"], "refs": refs, "chain": chain,
            "complete": live and complete and all(item["format"] for item in chain),
            "structurally_complete": complete and all(item["format"] for item in chain),
            "provenance": "live-libvirt-xml" if live else "persistent-libvirt-xml",
            "node": disk,
        })
    return evidence


def reject_reference(paths: list, disk: dict) -> None:
    for path in paths:
        info = path.stat()
        if str(path) == disk["path"] or (info.st_dev, info.st_ino) == (disk["device"], disk["inode"]):
            raise RunError("Owned disk is referenced by another domain's storage graph")


def managed_live_chains(store, context: dict, live, persistent, evidence: list,
                        persistent_evidence: list, storage_root: Path = STORAGE) -> dict:
    """Supplement omitted persistent chains only with matching validated LIVE proof."""
    description = live.findtext("description", "")
    if not description.startswith("idarsi-run:"):
        return {}
    run_id = description.removeprefix("idarsi-run:")
    try:
        if str(uuid.UUID(run_id)) != run_id:
            raise ValueError
        data = store.load(run_id)
    except FileNotFoundError:
        return {}  # Lost/legacy evidence still needs a readable image query.
    except ValueError as exc:
        raise RunError("Malformed managed domain owner") from exc
    if (
        data["backend"] != "kvm" or data["context"] != context
        or context.get("libvirt") != "qemu:///system" or data["status"] == "cleaned"
    ):
        raise RunError("Foreign managed run backend/context/state mismatch")
    identity = live.findtext("uuid")
    guests = [guest for guest in data["guests"] if guest.get("id") == identity]
    if len(guests) != 1:
        raise RunError("Managed domain UUID is not uniquely journalled")
    guest = guests[0]
    if not re.fullmatch(r"itr-[a-f0-9]{32}", guest["name"]) or str(uuid.UUID(identity)) != identity:
        raise RunError("Invalid managed domain identity")
    for root in (live, persistent):
        if root is not None and (
            root.findtext("uuid") != identity or root.findtext("name") != guest["name"]
            or root.findtext("description") != description
        ):
            raise RunError("Managed live/persistent domain identity mismatch")
    disks = guest.get("disks")
    if not disks or any("image_chain" not in disk for disk in disks):
        return {}  # Never upgrade legacy/root-only records into proof.
    owned = {}
    for disk in disks:
        Storage(storage_root).basename(disk)
        chain = validated_chain(disk["image_chain"])
        if chain[0] != {
            "path": disk["path"], "device": disk["device"], "inode": disk["inode"], "format": "qcow2",
        } or disk["path"] in owned:
            raise RunError("Managed root identity disagrees with image-chain capture")
        owned[disk["path"]] = (disk, chain)
    for entries in (evidence, persistent_evidence if persistent is not None else evidence):
        attached = [entry for entry in entries if entry["node"].get("device") == "disk"]
        if len(attached) != len(owned) or {entry["head"] for entry in attached} != set(owned):
            raise RunError("Managed domain complete attachment set changed")
        for entry in attached:
            disk, chain = owned[entry["head"]]
            node = entry["node"]
            if (
                node.findtext("serial") != disk["serial"]
                or node.find("target") is None or node.find("target").get("bus") != "virtio"
                or node.find("driver") is None or node.find("driver").get("type") != "qcow2"
            ):
                raise RunError("Managed attachment serial, bus or format changed")
            if entry["chain"] != chain[:len(entry["chain"])] or any(
                str(path) not in {item["path"] for item in chain} for path in entry["refs"]
            ):
                raise RunError("Explicit managed storage references disagree with the capture")
    live_by_head = {entry["head"]: entry for entry in evidence}
    for path, (_, chain) in owned.items():
        entry = live_by_head[path]
        if not entry["complete"]:
            return {}  # No manifest-only authorization; try fresh readable evidence.
        if entry["chain"] != chain:
            raise RunError("Managed capture disagrees with complete live storage evidence")
    return {path: chain for path, (_, chain) in owned.items()}


def assert_domain_unused(live, persistent, disk: dict, store=None, context=None,
                         storage_root: Path = STORAGE) -> None:
    """Compare explicit live/persistent references before considering supplementation."""
    active = xml_evidence(live, True) if live is not None else []
    defined = xml_evidence(persistent, False) if persistent is not None else []
    entries = active + defined
    for entry in entries:
        reject_reference(entry["refs"], disk)
    supplements = {}
    if store is not None and live is not None:
        supplements = managed_live_chains(
            store, context, live, persistent, active, defined, storage_root,
        )
    queried = {}
    for entry in entries:
        if entry["complete"]:
            continue
        if live is not None and entry["provenance"] == "persistent-libvirt-xml" and entry["structurally_complete"]:
            continue  # Both configurations have explicit, independent graphs.
        if entry["provenance"] == "persistent-libvirt-xml" and entry["head"] in supplements:
            reject_reference([Path(item["path"]) for item in supplements[entry["head"]]], disk)
            continue
        for path in entry["refs"]:
            if path not in queried:
                chain = image_chain(path)["members"]
                for index, item in enumerate(chain):
                    queried[Path(item["path"])] = chain[index:]
            reject_reference([Path(item["path"]) for item in queried[path]], disk)


def eligible_private_disk(store, context: dict, owner_id: str, guest_id: str,
                          disk: dict, storage_root: Path = STORAGE) -> bool:
    """Derive policy eligibility from trusted creation records, never a caller flag.

    Legacy journals are not retrofitted. An inode-journalled publication can
    qualify only when the actual named regular, single-link inode proves that
    its exclusive publication happened. An intent or a filename alone cannot.
    This function does not write or upgrade the manifest.
    """
    data = store.load(owner_id)
    guests = [guest for guest in data["guests"] if guest.get("id") == guest_id]
    if guest_id is None or len(guests) != 1:
        if "publication" in disk:
            raise RunError("Private publication has no unique owning domain")
        return False
    guest = guests[0]
    records = guest.get("disks", [])
    matches = [record for record in records if record.get("path") == disk.get("path")]
    if len(matches) != 1:
        if "publication" in disk:
            raise RunError("Private publication is not uniquely journalled")
        return False
    record = matches[0]
    if record != disk:
        raise RunError("Disk ownership changed since the cleanup snapshot")
    publication = record.get("publication")
    if publication is None:
        return False  # Existing O_TMPFILE journals without a policy stay strict.
    if (
        data["id"] != owner_id or str(uuid.UUID(owner_id)) != owner_id
        or data["backend"] != "kvm" or data["context"] != context
        or context.get("libvirt") != "qemu:///system"
        or data["status"] not in ("running", "cleaning", "cleanup_failed")
        or str(uuid.UUID(guest_id)) != guest_id
        or not re.fullmatch(r"itr-[a-f0-9]{32}", guest["name"])
        or guest.get("disk") is not None
    ):
        raise RunError("Private publication owner/context/identity mismatch")
    if (
        not isinstance(publication, dict)
        or publication.get("policy") != PRIVATE_POLICY
        or publication.get("protocol") != PUBLICATION_PROTOCOL
        or publication.get("owner") != owner_id
        or publication.get("path") != record["path"]
        or publication.get("state") not in ("inode-journalled", "published")
    ):
        raise RunError("Unknown or incomplete private publication provenance")
    if (
        type(record.get("device")) is not int or type(record.get("inode")) is not int
        or record["inode"] <= 0
        or publication.get("device") != record["device"] or publication.get("inode") != record["inode"]
        or not isinstance(record.get("name"), str)
        or not re.fullmatch(r"[a-z][a-z0-9_-]{0,15}", record["name"])
        or record.get("serial") != "itr-" + record["name"]
        or str(local_path(record["path"])) != record["path"]
    ):
        raise RunError("Private publication path/inode/serial mismatch")
    storage = Storage(storage_root)
    storage.basename(record)
    with storage.directory() as directory_fd:
        if storage.verify(record, directory_fd) is None:
            raise RunError("Publication intent has no matching named object")
    if "image_chain" in record:
        chain = validated_chain(record["image_chain"])
        if chain[0] != {
            "path": record["path"], "device": record["device"], "inode": record["inode"], "format": "qcow2",
        }:
            raise RunError("Private publication differs from its pre-start capture")
    return True


def assert_owned_domain_unused(live, persistent, disk: dict, store, context: dict,
                               owner_id: str, guest_id: str, storage_root: Path = STORAGE) -> None:
    """Check every observable reference under the private-resource trust boundary.

    New private disks cannot be exported to unmanaged consumers. Therefore
    OMITTED foreign backing metadata is outside this contract, not evidence of
    a complete/empty graph. All explicit references, source-resolution errors,
    unsupported forms and registered managed dependencies still block removal.
    Generic/legacy targets use the original strict graph resolver.
    """
    if not eligible_private_disk(store, context, owner_id, guest_id, disk, storage_root):
        return assert_domain_unused(live, persistent, disk, store, context, storage_root)
    active = xml_evidence(live, True) if live is not None else []
    defined = xml_evidence(persistent, False) if persistent is not None else []
    for entry in active + defined:
        reject_reference(entry["refs"], disk)
        if any(member["format"] not in ("raw", "qcow2") for member in entry["chain"]):
            raise RunError("Unknown foreign format is not merely omitted backing metadata")
    # Deliberately do not mark incomplete entries complete or probe unreadable
    # unrelated image headers. Eligibility is a supported-lifecycle boundary,
    # not a universal claim that invisible out-of-band consumers cannot exist.


def assert_pending_unused(store, context: dict, own_run_id: str, disk: dict) -> None:
    """Pending managed source claims are durable before preparation/start.

    Used under the short global graph lock. These records can only DENY
    deletion; they never authorize skipping a backend or permission check.
    """
    for data in store.runs():
        if data["id"] == own_run_id or data["backend"] != "kvm" or data["status"] == "cleaned":
            continue
        if data["context"] != context:
            raise RunError("Outstanding KVM run context differs")
        for guest in data["guests"]:
            source = guest.get("source_chain")
            if source:
                reject_reference([Path(item["path"]) for item in validated_chain(source)], disk)


def assert_disk_unused(root, disk: dict) -> None:
    """Legacy single-definition interface: do not assume this is live evidence."""
    assert_domain_unused(None, root, disk)
