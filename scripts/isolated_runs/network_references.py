"""Read-only network ownership and foreign interface dependency checks."""

import ipaddress
import json
import re
import uuid
import xml.etree.ElementTree as ET

from .discovery import VIRSH, command
from .state import RunError


def owned_bridge(root, intent: dict, subnet: str) -> str:
    """Validate the generated network contract before trusting its actual bridge."""
    identity = str(uuid.UUID(intent["id"]))
    expected_bridge = "it" + identity.replace("-", "")[:12]
    expected_name = "itr-" + identity.replace("-", "")[:24]
    if (
        root.tag != "network" or intent["id"] != identity or intent["name"] != expected_name
        or len(root.findall("name")) != 1 or root.findtext("name") != expected_name
        or len(root.findall("uuid")) != 1 or root.findtext("uuid") != identity
    ):
        raise RunError("Owned network identity/configuration mismatch")
    bridges = root.findall("bridge")
    forwards = root.findall("forward")
    domains = root.findall("domain")
    ips = root.findall("ip")
    if (
        len(bridges) != 1 or bridges[0].get("name") != expected_bridge
        or len(forwards) != 1 or forwards[0].get("mode") != "nat"
        or forwards[0].get("dev") or forwards[0].find("interface") is not None
        or len(domains) != 1 or domains[0].get("name") != expected_name + ".test"
        or domains[0].get("localOnly") != "yes" or len(ips) != 1
    ):
        raise RunError("Owned network bridge/NAT configuration changed")
    network = ipaddress.ip_network(subnet)
    address = ips[0]
    masks = [address.get(key) for key in ("prefix", "netmask") if address.get(key)]
    ranges = address.findall("./dhcp/range")
    if (
        network.version != 4 or network.prefixlen != 24
        or address.get("family", "ipv4") != "ipv4" or address.get("address") != str(network[1])
        or not masks or any(ipaddress.ip_network("0.0.0.0/" + mask).prefixlen != 24 for mask in masks)
        or len(address.findall("dhcp")) != 1 or len(ranges) != 1
        or ranges[0].get("start") != str(network[210]) or ranges[0].get("end") != str(network[250])
    ):
        raise RunError("Owned network address/DHCP configuration changed")
    return bridges[0].get("name")


class InterfaceReferences:
    """Resolve network names/UUIDs and kernel interface alternative names."""

    def __init__(self, bridge: str, intent: dict, networks: list):
        self.bridge = bridge
        self.intent = intent
        self.networks = networks
        self.links = None

    def bridge_reference(self, name: str) -> None:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,127}", name):
            raise RunError("Malformed interface source device")
        if name == self.bridge:
            raise RunError("Owned bridge is referenced by a foreign domain")
        if self.links is None:
            result = json.loads(command(["ip", "-j", "link", "show"]))
            if not isinstance(result, list):
                raise RunError("Incomplete kernel interface discovery")
            links = {}
            for item in result:
                if (
                    not isinstance(item, dict) or type(item.get("ifindex")) is not int or item["ifindex"] <= 0
                    or not isinstance(item.get("ifname"), str)
                    or not isinstance(item.get("altnames", []), list)
                ):
                    raise RunError("Malformed kernel interface discovery")
                for alias in [item["ifname"]] + item.get("altnames", []):
                    if not isinstance(alias, str) or alias in links:
                        raise RunError("Ambiguous kernel interface alias")
                    links[alias] = item
            if self.bridge not in links:
                raise RunError("Owned bridge disappeared during dependency discovery")
            self.links = links
        owned_index = self.links[self.bridge]["ifindex"]
        source = self.links.get(name)
        # A complete kernel listing proves an absent different name is not a
        # current alias. Persistent XML is still inspected separately.
        if source is None:
            return
        master = source.get("master")
        if isinstance(master, str):
            if master not in self.links:
                raise RunError("Cannot resolve interface master")
            master = self.links[master]["ifindex"]
        elif master is not None and type(master) is not int:
            raise RunError("Malformed interface master")
        if source["ifindex"] == owned_index or master == owned_index:
            raise RunError("Owned bridge is referenced through an interface alias/master")

    def network_reference(self, reference: str) -> None:
        if reference == self.intent["name"] or reference.lower() == self.intent["id"].lower():
            raise RunError("Owned network is referenced by a foreign domain")
        matches = [
            root for root in self.networks
            if root.findtext("name") == reference or root.findtext("uuid", "").lower() == reference.lower()
        ]
        if len(matches) != 1 or any(
            len(matches[0].findall(tag)) != 1 for tag in ("name", "uuid", "bridge")
        ):
            raise RunError("Cannot resolve foreign network reference unambiguously")
        self.bridge_reference(matches[0].find("bridge").get("name"))

    def check_interface(self, interface) -> None:
        kind = interface.get("type")
        sources = interface.findall("source")
        if kind == "user" and not sources:
            return  # Ordinary user-mode networking does not attach a host bridge.
        allowed = {
            "network": {"network", "bridge", "portgroup", "portid"},
            "bridge": {"bridge"},
            "direct": {"dev", "mode"},
        }
        required = {"network": "network", "bridge": "bridge", "direct": "dev"}
        if kind not in allowed or len(sources) != 1:
            raise RunError("Unsupported or incomplete foreign interface source")
        source = sources[0]
        if (
            not source.get(required[kind]) or set(source.attrib) - allowed[kind]
            or any(child.tag != "seclabel" for child in source)
            or (kind == "direct" and source.get("mode", "vepa") not in ("vepa", "bridge", "private", "passthrough"))
        ):
            raise RunError("Unexpected foreign interface source form")
        if source.get("network"):
            self.network_reference(source.get("network"))
        for key in ("bridge", "dev"):
            if source.get(key):
                self.bridge_reference(source.get(key))

    def check_domain(self, root, identity: str) -> None:
        if (
            root.tag != "domain" or len(root.findall("uuid")) != 1
            or root.findtext("uuid") != identity or len(root.findall("devices")) != 1
        ):
            raise RunError("Foreign domain identity changed during network discovery")
        for interface in root.findall("./devices/interface"):
            self.check_interface(interface)
            actual = interface.findall("actual")
            if len(actual) > 1:
                raise RunError("Ambiguous resolved interface source")
            for resolved in actual:
                self.check_interface(resolved)


def assert_network_unused(root, intent: dict, subnet: str, networks: list) -> None:
    bridge = owned_bridge(root, intent, subnet)
    references = InterfaceReferences(bridge, intent, networks)
    all_domains = set(command(VIRSH + ["list", "--all", "--uuid"]).splitlines())
    active = set(command(VIRSH + ["list", "--uuid"]).splitlines())
    persistent = set(command(VIRSH + ["list", "--all", "--persistent", "--uuid"]).splitlines())
    if active | persistent != all_domains:
        raise RunError("Domain inventory changed during network dependency discovery")
    for identity in sorted(all_domains):
        try:
            if identity in active:
                references.check_domain(ET.fromstring(command(VIRSH + ["dumpxml", identity])), identity)
            if identity in persistent:
                references.check_domain(ET.fromstring(command(VIRSH + ["dumpxml", identity, "--inactive"])), identity)
        except ET.ParseError as exc:
            raise RunError("Malformed foreign domain XML during network discovery") from exc
