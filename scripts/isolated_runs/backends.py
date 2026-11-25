"""Owned backend lifecycle. Never use legacy Molecule plugin destruction."""

import contextlib
import ipaddress
import json
from pathlib import Path
import re
import shlex
import time
import uuid
import xml.etree.ElementTree as ET

from .discovery import PODMAN, VIRSH, command, libvirt_networks, podman_context, podman_networks
from .state import RunError, lock
from .storage import Storage
from .storage_references import assert_owned_domain_unused, assert_pending_unused, image_chain
from .network_references import assert_network_unused

LABEL = "io.idarsi.test-run"
REPO = Path(__file__).resolve().parents[2]


def kvm_instance(platform: dict, subnet: str, index: int, key: Path) -> dict:
    """One authoritative allocation-to-SSH mapping for creation and validation."""
    network = ipaddress.ip_network(subnet)
    if network.version != 4 or network.prefixlen != 24 or not 0 <= index < 200:
        raise RunError("Invalid managed KVM allocation")
    return {
        "instance": platform["name"], "address": str(network[index + 10]),
        "user": platform["ssh_user"], "port": "22", "identity_file": str(key),
    }


def validate_platforms(backend: str, platforms: list, scenario: Path) -> list:
    """Validate the entire platform list before allocating backend resources."""
    common = {"name"}
    podman = {"image", "pre_build_image", "command", "environment", "user", "groups"}
    kvm = {
        "image_path", "install_source", "kickstart", "ssh_user", "memory_mb",
        "vcpus", "disk_size_gb", "install_timeout", "groups", "data_disks",
    }
    if not isinstance(platforms, list) or not 1 <= len(platforms) <= 200:
        raise RunError("Expected between 1 and 200 platforms")
    names = set()
    normalized = []
    for original in platforms:
        if not isinstance(original, dict):
            raise RunError("Each platform must be a mapping")
        item = dict(original)
        if set(item) - common - (podman if backend == "podman" else kvm):
            raise RunError("Unsupported platform options: " + str(sorted(
                set(item) - common - (podman if backend == "podman" else kvm),
            )))
        name = item.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,62}", name):
            raise RunError("Platform name must be a safe logical inventory name of 1-63 ASCII characters")
        if name in names:
            raise RunError("Duplicate platform name")
        names.add(name)
        if "groups" in item and (
            not isinstance(item["groups"], list)
            or not all(isinstance(group, str) and re.fullmatch(r"\w+", group) for group in item["groups"])
        ):
            raise RunError("groups must be a list of inventory group names")
        if backend == "podman":
            if item.get("pre_build_image") is not True:
                raise RunError("Managed Podman requires pre_build_image: true")
            image = item.get("image")
            if not isinstance(image, str) or not image or image.startswith("-"):
                raise RunError("A prebuilt Podman image is required")
            cmd = item.get("command", ["/bin/sleep", "infinity"])
            if isinstance(cmd, str):
                cmd = shlex.split(cmd)
            if not isinstance(cmd, list) or not cmd or not all(isinstance(arg, str) for arg in cmd):
                raise RunError("command must be an argv list or shell-word string")
            item["command"] = cmd
            environment = item.get("environment", {})
            if not isinstance(environment, dict) or not all(
                isinstance(key, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                and isinstance(value, str) for key, value in environment.items()
            ):
                raise RunError("environment must map variable names to strings")
            if "user" in item and (
                not isinstance(item["user"], str)
                or not re.fullmatch(r"[a-zA-Z0-9_:.-]+", item["user"])
            ):
                raise RunError("Invalid container user")
        else:
            disks = item.get("data_disks", [])
            if not isinstance(disks, list) or len(disks) > 25:
                raise RunError("data_disks must be a list with at most 25 entries")
            disk_names = {"root"}
            for disk in disks:
                if not isinstance(disk, dict) or set(disk) != {"name", "size_gb"}:
                    raise RunError("Data disks accept only name and size_gb")
                name = disk["name"]
                if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,15}", name):
                    raise RunError("Data disk names must be safe names of at most 16 characters")
                if name in disk_names or type(disk["size_gb"]) is not int or disk["size_gb"] <= 0:
                    raise RunError("Data disk names must be unique and sizes positive integers")
                disk_names.add(name)
            user = item.setdefault("ssh_user", "molecule")
            if not isinstance(user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", user):
                raise RunError("Invalid SSH user")
            for key, default, minimum in (
                ("memory_mb", 4096, 1024), ("vcpus", 2, 1),
                ("disk_size_gb", 30, 10), ("install_timeout", 3600, 60),
            ):
                value = item.setdefault(key, default)
                if type(value) is not int or value < minimum:
                    raise RunError("Invalid " + key)
            if bool(item.get("image_path")) == bool(item.get("install_source")):
                raise RunError("KVM needs exactly one of image_path or install_source")
            for key in ("image_path", "kickstart"):
                if key in item:
                    path = Path(item[key])
                    if not path.is_absolute():
                        path = scenario / path
                    path = path.resolve(strict=True)
                    if not path.is_file():
                        raise RunError("Not a regular file: " + str(path))
                    item[key] = str(path)
            if "install_source" in item:
                source = item["install_source"]
                if not isinstance(source, str) or not source:
                    raise RunError("Invalid install_source")
                if not source.startswith(("http://", "https://")):
                    path = Path(source)
                    item["install_source"] = str(
                        (path if path.is_absolute() else scenario / path).resolve(strict=True),
                    )
                if "kickstart" not in item:
                    raise RunError("ISO guests require a kickstart template")
                text = Path(item["kickstart"]).read_text()
                if disks and re.search(r"(?m)^\s*ignoredisk\b", text):
                    raise RunError("Managed data disks require the adapter-owned ignoredisk directive")
                if "@@NETWORK_CONFIGURATION@@" not in text:
                    raise RunError("Kickstart must use @@NETWORK_CONFIGURATION@@")
                for placeholder in ("@@NETWORK_CONFIGURATION@@", "@@SSH_USER@@", "@@SSH_PUBLIC_KEY@@"):
                    text = text.replace(placeholder, "")
                if "@@" in text:
                    raise RunError("Unknown kickstart placeholder")
        normalized.append(item)
    return normalized


class Backend:
    """Resources are journalled before creation and verified before removal."""

    def __init__(self, store, data: dict):
        self.store = store
        self.data = data
        self.directory = store.directory(data["id"])
        self.storage = Storage()

    def save(self):
        self.store.save(self.data)

    def check_context(self):
        if podman_context() != self.data["context"]["podman"]:
            raise RunError("Podman context differs from the recorded run context")
        if self.data["context"]["libvirt"] != "qemu:///system":
            raise RunError("Unsupported libvirt context")

    def network(self):
        self.check_context()
        if self.data["network"] or self.data.get("storage_probe"):
            raise RunError("Network/probe already journalled; explicit cleanup required before retry")
        if self.data["backend"] == "kvm":
            def journal_probe(record):
                self.data["storage_probe"] = record
                self.save()

            self.storage.probe(journal_probe)
            self.data.pop("storage_probe", None)
            self.save()
        network = self.data["network"]
        if network:
            raise RunError("Network already journalled; explicit cleanup required before retry")
        identity = str(uuid.uuid4())
        name = "itr-" + identity.replace("-", "")[:24]
        network = {"name": name, "id": identity if self.data["backend"] == "kvm" else None}
        if self.data["backend"] == "kvm":
            # Published with network intent, before any guest can be defined.
            # Never synthesize this evidence from a possibly cleared journal.
            network["domain_ownership"] = {
                "version": 1, "protocol": "create-intent-v1",
                "generation": self.data["id"], "domains": [],
            }
        self.data["network"] = network
        self.save()
        subnet = ipaddress.ip_network(self.data["subnet"])
        if self.data["backend"] == "kvm":
            existing = libvirt_networks()
            if any(root.findtext("name") == name or root.findtext("uuid") == identity for root in existing):
                raise RunError("Libvirt network identity is already in use")
            root = ET.Element("network")
            ET.SubElement(root, "name").text = name
            ET.SubElement(root, "uuid").text = identity
            ET.SubElement(root, "bridge", name="it" + identity.replace("-", "")[:12])
            ET.SubElement(root, "forward", mode="nat")
            ET.SubElement(root, "domain", name=name + ".test", localOnly="yes")
            address = ET.SubElement(root, "ip", address=str(subnet[1]), netmask="255.255.255.0")
            dhcp = ET.SubElement(address, "dhcp")
            ET.SubElement(dhcp, "range", start=str(subnet[210]), end=str(subnet[250]))
            path = self.directory / "network.xml"
            path.write_text(ET.tostring(root, encoding="unicode"))
            command(VIRSH + ["net-create", str(path)])
        else:
            if any(net["name"] == name for net in podman_networks()):
                raise RunError("Podman network name is already in use")
            command(PODMAN + [
                "network", "create", "--label", LABEL + "=" + self.data["id"],
                "--subnet", str(subnet), "--gateway", str(subnet[1]), name,
            ])
            self.owned_podman_network()

    def owned_podman_network(self):
        intent = self.data["network"]
        matches = [net for net in podman_networks() if (
            net["name"] == intent["name"] or net["id"] == intent["id"]
        )]
        if not matches:
            return None
        if len(matches) != 1:
            raise RunError("Ambiguous Podman network identity")
        actual = matches[0]
        if actual.get("labels", {}).get(LABEL) != self.data["id"]:
            raise RunError("Podman network ownership label mismatch")
        if actual["name"] != intent["name"] or (intent["id"] and actual["id"] != intent["id"]):
            raise RunError("Podman network was replaced")
        if intent["id"] is None:
            intent["id"] = actual["id"]
            self.save()
        return actual

    def owned_container(self, guest: dict):
        identities = command(PODMAN + ["ps", "--all", "--no-trunc", "--format", "{{.ID}}"]).splitlines()
        if not identities:
            return None
        containers = json.loads(command(PODMAN + ["inspect"] + identities))
        matches = [obj for obj in containers if (
            obj["Id"] == guest["id"] or obj["Name"].lstrip("/") == guest["name"]
        )]
        if not matches:
            return None
        if len(matches) != 1:
            raise RunError("Ambiguous container identity")
        actual = matches[0]
        if actual["Config"].get("Labels", {}).get(LABEL) != self.data["id"]:
            raise RunError("Container ownership label mismatch")
        if actual["Name"].lstrip("/") != guest["name"] or (
            guest["id"] and actual["Id"] != guest["id"]
        ):
            raise RunError("Container was replaced")
        if guest["id"] is None:
            guest["id"] = actual["Id"]
            self.save()
        return actual

    def owned_domain(self, guest: dict):
        identities = command(VIRSH + ["list", "--all", "--uuid"]).splitlines()
        names = command(VIRSH + ["list", "--all", "--name"]).splitlines()
        if guest["id"] not in identities:
            if guest["name"] in names:
                raise RunError("Domain name has been replaced")
            return None
        root = ET.fromstring(command(VIRSH + ["dumpxml", guest["id"]]))
        if root.findtext("name") != guest["name"] or root.findtext("description") != (
            "idarsi-run:" + self.data["id"]
        ):
            raise RunError("Domain ownership metadata mismatch")
        self.verify_attachments(guest, root)
        persistent = command(VIRSH + ["list", "--all", "--persistent", "--uuid"]).splitlines()
        if guest["id"] in persistent:
            self.verify_attachments(guest, ET.fromstring(command(VIRSH + ["dumpxml", guest["id"], "--inactive"])))
        return root

    @staticmethod
    def disks(guest: dict) -> list:
        """Normalize version-1 root-only manifests without changing their ownership."""
        if "disks" in guest:
            return guest["disks"]
        return [guest["disk"]] if guest.get("disk") else []

    def verify_attachments(self, guest: dict, root):
        expected = {disk["path"]: disk for disk in self.disks(guest)}
        attached = root.findall("./devices/disk[@device='disk']")
        sources = [disk.find("source").get("file") if disk.find("source") is not None else None for disk in attached]
        if len(sources) != len(expected) or set(sources) != set(expected):
            raise RunError("Domain disk attachment set changed")
        for node, source in zip(attached, sources):
            record = expected[source]
            if "serial" in record and (
                node.findtext("serial") != record["serial"]
                or node.find("target") is None or node.find("target").get("bus") != "virtio"
                or node.find("driver") is None or node.find("driver").get("type") != "qcow2"
            ):
                raise RunError("Domain disk serial, format or bus changed")

    def create(self, platforms: list) -> list:
        from .cooperative_stop import check_create_stop

        check_create_stop(self.store, self.data, "before-network")
        self.network()
        result = []
        for index, platform in enumerate(platforms):
            check_create_stop(self.store, self.data, "before-guest")
            guest = {
                "logical": platform["name"], "name": "itr-" + uuid.uuid4().hex,
                "id": str(uuid.uuid4()) if self.data["backend"] == "kvm" else None,
                "disk": None,
            }
            self.data["guests"].append(guest)
            if self.data["backend"] == "kvm":
                self.data["network"]["domain_ownership"]["domains"].append({
                    "id": guest["id"], "name": guest["name"],
                })
            self.save()
            if self.data["backend"] == "podman":
                result.append(self.create_container(guest, platform))
            else:
                result.append(self.create_domain(guest, platform, index))
        return result

    def create_container(self, guest: dict, platform: dict) -> dict:
        if self.owned_container(guest):
            raise RunError("Container name already exists")
        args = PODMAN + [
            "create", "--name", guest["name"], "--label", LABEL + "=" + self.data["id"],
            "--network", self.data["network"]["name"], "--hostname", guest["logical"],
            "--image-volume", "ignore",
        ]
        if "user" in platform:
            args += ["--user", platform["user"]]
        for key, value in platform.get("environment", {}).items():
            args += ["--env", key + "=" + value]
        identity = command(args + [platform["image"]] + platform["command"], timeout=600)
        if not identity:
            raise RunError("Podman did not return a container ID")
        guest["id"] = identity
        self.save()
        self.owned_container(guest)
        command(PODMAN + ["start", identity])
        return {
            "instance": guest["logical"], "address": guest["name"],
            "user": platform.get("user", "root"), "port": "22", "identity_file": "",
            "connection": "containers.podman.podman",
        }

    def create_domain(self, guest: dict, platform: dict, index: int) -> dict:
        """Import a cached image or install directly; no shared cache mutation."""
        if self.owned_domain(guest):
            raise RunError("Domain already exists")
        if "image_path" in platform:
            # Lock order is always this run's resource lock, then graph lock.
            # Publish backing dependencies before any overlay preparation;
            # another run must not unlink a source while this guest is pending.
            with lock(self.store.root / ".storage-graph.lock"):
                guest["source_chain"] = image_chain(Path(platform["image_path"]), before_start=True)
                self.save()
        guest["disks"] = []
        with contextlib.ExitStack() as stack:
            for spec in [{"name": "root"}] + platform.get("data_disks", []):
                record = {
                    "path": str(self.storage.root / ("itr-" + uuid.uuid4().hex + ".qcow2")),
                    "name": spec["name"], "serial": "itr-" + spec["name"],
                    "device": None, "inode": None,
                }
                guest["disks"].append(record)
                self.save()
                stack.enter_context(self.storage.publish(record, self.save, owner_id=self.data["id"]))
                if spec["name"] != "root":
                    self.disk_command(record, [
                        "qemu-img", "create", "-f", "qcow2", record["path"], str(spec["size_gb"]) + "G",
                    ])
            return self.provision_domain(guest, platform, index)

    def disk_command(self, record: dict, argv: list, **kwargs):
        with self.storage.directory() as directory_fd:
            if self.storage.verify(record, directory_fd) is None:
                raise RunError("Disk disappeared before provisioning")
            try:
                return command(argv, **kwargs)
            finally:
                if self.storage.verify(record, directory_fd) is None:
                    raise RunError("Disk disappeared during provisioning")

    def provision_domain(self, guest: dict, platform: dict, index: int) -> dict:
        from .cooperative_stop import check_create_stop

        key = self.directory / "kvm_ed25519"
        if not key.exists():
            command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
        record = guest["disks"][0]
        path = Path(record["path"])
        subnet = ipaddress.ip_network(self.data["subnet"])
        instance = kvm_instance(platform, self.data["subnet"], index, key)
        address = instance["address"]
        gateway = str(subnet[1])
        disk = ["qemu-img", "create", "-f", "qcow2"]
        if "image_path" in platform:
            image = platform["image_path"]
            if json.loads(command(["qemu-img", "info", "--output=json", image]))["format"] != "qcow2":
                raise RunError("Image must be qcow2")
            self.disk_command(record, disk + ["-F", "qcow2", "-b", image, str(path)])
            network_file = self.directory / (guest["name"] + ".nmconnection")
            network_file.write_text(
                "[connection]\nid=idarsi-test\ntype=ethernet\nautoconnect=true\n"
                "autoconnect-priority=999\nmatch-device=type:ethernet\n"
                "[ipv4]\nmethod=manual\naddress1=" + address + "/24," + gateway
                + "\ndns=" + gateway + ";\n[ipv6]\nmethod=disabled\n",
            )
            self.disk_command(record, [
                "virt-customize", "--format", "qcow2", "-a", str(path), "--hostname", guest["logical"],
                "--ssh-inject", platform["ssh_user"] + ":file:" + str(key) + ".pub",
                "--upload", str(network_file) + ":/etc/NetworkManager/system-connections/99-idarsi-test.nmconnection",
                "--chown", "0:0:/etc/NetworkManager/system-connections/99-idarsi-test.nmconnection",
                "--chmod", "0600:/etc/NetworkManager/system-connections/99-idarsi-test.nmconnection",
                "--selinux-relabel",
            ], timeout=platform["install_timeout"])
            install = ["--import"]
        else:
            self.disk_command(record, disk + [str(path), str(platform["disk_size_gb"]) + "G"])
            rendered = self.directory / (guest["name"] + ".ks.cfg")
            text = Path(platform["kickstart"]).read_text()
            if platform.get("data_disks"):
                # Data disks stay blank even when the template uses autopart.
                text = "ignoredisk --only-use=disk/by-id/virtio-itr-root\n" + text
            text = text.replace("@@SSH_USER@@", platform["ssh_user"]).replace(
                "@@SSH_PUBLIC_KEY@@", Path(str(key) + ".pub").read_text().strip(),
            ).replace(
                "@@NETWORK_CONFIGURATION@@",
                "network --bootproto=static --ip=" + address + " --netmask=255.255.255.0"
                " --gateway=" + gateway + " --nameserver=" + gateway + " --device=link --activate",
            )
            rendered.write_text(text)
            install = [
                "--location", platform["install_source"], "--initrd-inject", str(rendered),
                "--extra-args", "inst.ks=file:/" + rendered.name + " console=ttyS0,115200n8",
            ]
        disk_arguments = []
        for owned in guest["disks"]:
            self.verify_disk(owned)
            disk_arguments += ["--disk", "path=" + owned["path"] + ",format=qcow2,bus=virtio,serial=" + owned["serial"]]
        start_arguments = [
            "virt-install", "--connect", "qemu:///system", "--name", guest["name"],
            "--uuid", guest["id"], "--metadata", "description=idarsi-run:" + self.data["id"],
            "--memory", str(platform["memory_mb"]), "--vcpus", str(platform["vcpus"]),
            "--network", "network=" + self.data["network"]["name"] + ",model=virtio",
            "--os-variant", "generic", "--graphics", "none", "--noautoconsole",
        ] + disk_arguments + install
        # Do not hold the shared lock during guest installation or SSH polling.
        # --noautoconsole without --wait returns after initial definition/start.
        with lock(self.store.root / ".storage-graph.lock"):
            for owned in guest["disks"]:
                owned["image_chain"] = image_chain(Path(owned["path"]), before_start=True)
            self.save()
            command(start_arguments, timeout=60)
        deadline = time.monotonic() + platform["install_timeout"]
        install_restarted = False
        while time.monotonic() < deadline:
            # virsh/virt-install and journal writes above have returned. Stop
            # here, not by killing their client during an uncertain daemon RPC.
            # Guest installation/SSH readiness need not finish before cleanup.
            check_create_stop(self.store, self.data, "guest-readiness")
            if (
                "install_source" in platform and not install_restarted
                and command(VIRSH + ["domstate", guest["id"]]) in ("shut off", "shutoff")
            ):
                # virt-install's install-phase XML destroys on reboot; its
                # persistent final XML is already defined. Boot it once after
                # installation, outside any long-lived shared lock.
                with lock(self.store.root / ".storage-graph.lock"):
                    if self.owned_domain(guest) is None:
                        raise RunError("Install-phase domain disappeared before final boot")
                    if command(VIRSH + ["domstate", guest["id"]]) in ("shut off", "shutoff"):
                        command(VIRSH + ["start", guest["id"]])
                        install_restarted = True
            try:
                command([
                    "ssh", "-F", "/dev/null", "-i", str(key), "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=4", "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null", platform["ssh_user"] + "@" + address, "true",
                ], timeout=10)
                return instance
            except RunError:
                time.sleep(2)
        raise RunError("Guest did not become SSH-ready")

    @staticmethod
    def verify_disk(disk: dict):
        storage = Storage()
        storage.basename(disk)
        with storage.directory() as directory_fd:
            return storage.verify(disk, directory_fd)

    def destroy_guests(self):
        self.check_context()
        for guest in reversed(self.data["guests"]):
            if self.data["backend"] == "podman":
                if self.owned_container(guest):
                    command(PODMAN + ["rm", "--force", guest["id"]])
                    if self.owned_container(guest):
                        raise RunError("Container removal was not confirmed")
            else:
                with lock(self.store.root / ".storage-graph.lock"):
                    with self.storage.directory() as directory_fd:
                        for disk in self.disks(guest):
                            self.storage.verify(disk, directory_fd)
                    root = self.owned_domain(guest)
                    if root is not None:
                        state = command(VIRSH + ["domstate", guest["id"]])
                        if state not in ("shut off", "shutoff"):
                            command(VIRSH + ["destroy", guest["id"]])
                        command(VIRSH + ["undefine", guest["id"]])
                        if self.owned_domain(guest) is not None:
                            raise RunError("Domain removal was not confirmed")
                for disk in self.disks(guest):
                    with lock(self.store.root / ".storage-graph.lock"):
                        with self.storage.directory() as directory_fd:
                            missing = self.storage.verify(disk, directory_fd) is None
                        if missing:
                            # Retry after a successful unlink but interrupted
                            # journal update: fsync absence, never adopt a path.
                            self.storage.remove(disk)
                            continue
                        # Atomic metadata reads only: never acquire another
                        # run's resource/supervisor lock and deadlock its lifetime.
                        assert_pending_unused(self.store, self.data["context"], self.data["id"], disk)
                        active = command(VIRSH + ["list", "--uuid"]).splitlines()
                        persistent = command(VIRSH + ["list", "--all", "--persistent", "--uuid"]).splitlines()
                        for identity in command(VIRSH + ["list", "--all", "--uuid"]).splitlines():
                            live = ET.fromstring(command(VIRSH + ["dumpxml", identity])) if identity in active else None
                            defined = ET.fromstring(command(VIRSH + ["dumpxml", identity, "--inactive"])) if identity in persistent else None
                            if live is None and defined is None:
                                raise RunError("Foreign domain changed during storage discovery")
                            assert_owned_domain_unused(
                                live, defined, disk, self.store, self.data["context"],
                                self.data["id"], guest.get("id"), self.storage.root,
                            )
                        self.storage.remove(disk)
        if self.data.get("storage_probe"):
            self.storage.remove(self.data["storage_probe"])
            self.data.pop("storage_probe")
        self.data["guests"] = []
        self.save()

    def destroy_network(self):
        intent = self.data["network"]
        if intent is None:
            return
        if self.data["backend"] == "podman":
            if self.owned_podman_network():
                command(PODMAN + ["network", "rm", intent["id"]])
                if self.owned_podman_network():
                    raise RunError("Network removal was not confirmed")
        else:
            with lock(self.store.root / ".storage-graph.lock"):
                ownership = intent.get("domain_ownership")
                owned_ids, owned_names = set(), set()
                if ownership is not None:
                    if (
                        not isinstance(ownership, dict) or ownership.get("version") != 1
                        or ownership.get("protocol") != "create-intent-v1"
                        or ownership.get("generation") != self.data["id"]
                        or not isinstance(ownership.get("domains"), list)
                    ):
                        raise RunError("Invalid original network domain ownership")
                    for domain in ownership["domains"]:
                        if (
                            not isinstance(domain, dict) or set(domain) != {"id", "name"}
                            or str(uuid.UUID(domain["id"])) != domain["id"]
                            or not re.fullmatch(r"itr-[a-f0-9]{32}", domain["name"])
                            or domain["id"] in owned_ids or domain["name"] in owned_names
                        ):
                            raise RunError("Ambiguous original network domain ownership")
                        owned_ids.add(domain["id"])
                        owned_names.add(domain["name"])
                    if any(
                        guest["id"] not in owned_ids or guest["name"] not in owned_names
                        for guest in self.data.get("guests", [])
                    ):
                        raise RunError("Original network ownership does not cover the guest journal")
                # Historical records without creation-time evidence keep the
                # strict resolver: absence cannot retroactively prove ownership.
                allow_dangling = ownership is not None
                networks = libvirt_networks()
                matches = [root for root in networks if (
                    root.findtext("uuid") == intent["id"] or root.findtext("name") == intent["name"]
                )]
                if matches:
                    if len(matches) != 1 or matches[0].findtext("uuid") != intent["id"] or (
                        matches[0].findtext("name") != intent["name"]
                    ):
                        raise RunError("Libvirt network was replaced")
                    first = assert_network_unused(
                        matches[0], intent, self.data["subnet"], networks,
                        allow_inactive_dangling=allow_dangling,
                        owned_domain_ids=owned_ids, owned_domain_names=owned_names,
                        owned_generation_id=self.data["id"],
                    )
                    fresh = libvirt_networks()
                    targets = [root for root in fresh if (
                        root.findtext("uuid") == intent["id"] or root.findtext("name") == intent["name"]
                    )]
                    if len(targets) != 1:
                        raise RunError("Owned network changed between dependency snapshots")
                    second = assert_network_unused(
                        targets[0], intent, self.data["subnet"], fresh,
                        allow_inactive_dangling=allow_dangling,
                        owned_domain_ids=owned_ids, owned_domain_names=owned_names,
                        owned_generation_id=self.data["id"],
                    )
                    if first != second:
                        raise RunError("Network dependencies changed between snapshots")
                    command(VIRSH + ["net-destroy", intent["id"]])
                    if any(root.findtext("uuid") == intent["id"] for root in libvirt_networks()):
                        raise RunError("Network remains defined; not removing a persistent definition")
        self.data["network"] = None
        self.save()
