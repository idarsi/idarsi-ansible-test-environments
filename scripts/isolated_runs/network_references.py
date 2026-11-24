"""Read-only network ownership and foreign interface dependency checks."""

from dataclasses import dataclass
import ipaddress
import json
import os
import re
from typing import Optional
import uuid
import xml.etree.ElementTree as ET

from .discovery import VIRSH, command
from .state import RunError


@dataclass(frozen=True)
class DomainObservation:
    """Explicit read-only domain state and XML-origin context; never persisted."""

    identity: str
    state: Optional[str]
    xml_origin: Optional[str]
    persistent: bool
    active: bool


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

    def __init__(
        self, bridge: str, intent: dict, networks: list, bridge_absent: bool = False,
        runner=None, owned_domain_ids=(), owned_domain_names=(), owned_generation_id=None,
    ):
        self.bridge = bridge
        self.intent = intent
        self.networks = networks
        self.links = None
        self.bridge_absent = bridge_absent
        self.command = command if runner is None else runner
        self.owned_domain_ids = set(owned_domain_ids)
        self.owned_domain_names = set(owned_domain_names)
        self.owned_generation_id = owned_generation_id
        self.complete_inventory = False
        self.persistent_networks = {}

    def bridge_reference(self, name: str) -> None:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,127}", name):
            raise RunError("Malformed interface source device")
        if name == self.bridge:
            raise RunError("Owned bridge is referenced by a foreign domain")
        self.load_links()
        if self.bridge not in self.links and self.bridge_absent:
            return
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

    def load_links(self) -> None:
        """Load one complete kernel view; each snapshot owns a fresh resolver."""
        if self.links is None:
            result = json.loads(self.command(["ip", "-j", "link", "show"]))
            if not isinstance(result, list):
                raise RunError("Incomplete kernel interface discovery")
            links = {}
            indexes = set()
            for item in result:
                if (
                    not isinstance(item, dict) or type(item.get("ifindex")) is not int or item["ifindex"] <= 0
                    or not isinstance(item.get("ifname"), str)
                    or not isinstance(item.get("altnames", []), list)
                    or item["ifindex"] in indexes
                ):
                    raise RunError("Malformed kernel interface discovery")
                indexes.add(item["ifindex"])
                for alias in [item["ifname"]] + item.get("altnames", []):
                    if (
                        not isinstance(alias, str) or alias in links
                        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,127}", alias)
                    ):
                        raise RunError("Ambiguous kernel interface alias")
                    links[alias] = item
            if self.bridge not in links:
                if self.bridge_absent:
                    self.links = links
                    return
                raise RunError("Owned bridge disappeared during dependency discovery")
            self.links = links

    def network_reference(self, reference: str, *, observation=None) -> None:
        if not isinstance(reference, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,127}", reference):
            raise RunError("Malformed foreign network name")
        if reference == self.intent["name"] or reference.lower() == self.intent["id"].lower():
            raise RunError("Owned network is referenced by a foreign domain")
        matches = [
            root for root in self.networks
            if root.findtext("name") == reference or root.findtext("uuid", "").lower() == reference.lower()
        ]
        if (
            not matches and self.complete_inventory
            and isinstance(observation, DomainObservation)
            and observation.xml_origin == "inactive" and observation.persistent is True
            and observation.active is False and observation.state == "shut off"
            and observation.identity not in self.owned_domain_ids
            and str(uuid.UUID(observation.identity)) == observation.identity
        ):
            return
        if len(matches) != 1 or matches[0].findtext("name") != reference or any(
            len(matches[0].findall(tag)) != 1 for tag in ("name", "uuid", "bridge")
        ):
            raise RunError("Cannot resolve foreign network reference unambiguously")
        self.bridge_reference(matches[0].find("bridge").get("name"))
        defined = self.persistent_networks.get(matches[0].findtext("uuid"))
        if defined is not None:
            if len(defined.findall("bridge")) != 1:
                raise RunError("Cannot resolve persistent foreign network bridge")
            self.bridge_reference(defined.find("bridge").get("name"))

    def check_interface(self, interface, *, observation=None) -> None:
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
            self.network_reference(
                source.get("network"),
                observation=observation if (
                    kind == "network"
                    and set(source.attrib) == {"network"} and not list(source)
                    and not (source.text or "").strip()
                    and interface.find(".//actual") is None
                ) else None,
            )
        for key in ("bridge", "dev"):
            if source.get(key):
                self.bridge_reference(source.get(key))

    def check_domain(
        self, root, identity: str, *, state=None, xml_origin=None,
        persistent: bool = False, active: bool = True,
    ) -> None:
        if (
            root.tag != "domain" or len(root.findall("uuid")) != 1
            or root.findtext("uuid") != identity or len(root.findall("devices")) != 1
        ):
            raise RunError("Foreign domain identity changed during network discovery")
        for interface in root.findall("./devices/interface"):
            self.check_interface(
                interface,
                observation=DomainObservation(
                    identity, state, xml_origin, persistent, active,
                ) if (
                    root.find(".//actual") is None
                    and len(root.findall("name")) == 1
                    and bool(root.findtext("name"))
                    and not any(node.text in self.owned_domain_names for node in root.findall("name"))
                    and (
                        self.owned_generation_id is None
                        or not any(
                            node.text == "idarsi-run:" + self.owned_generation_id
                            for node in root.findall("description")
                        )
                    )
                ) else None,
            )
            actual = interface.findall("actual")
            if len(actual) > 1:
                raise RunError("Ambiguous resolved interface source")
            for resolved in actual:
                self.check_interface(resolved)


def assert_network_unused(
    root, intent: dict, subnet: str, networks: list, *, bridge_absent: bool = False, runner=None,
    allow_inactive_dangling: bool = False, owned_domain_ids=(), owned_domain_names=(),
    owned_generation_id=None,
):
    query = command if runner is None else runner
    bridge = owned_bridge(root, intent, subnet)
    references = InterfaceReferences(
        bridge, intent, networks, bridge_absent=bridge_absent, runner=query,
        owned_domain_ids=owned_domain_ids, owned_domain_names=owned_domain_names,
        owned_generation_id=owned_generation_id,
    )

    def identities(arguments):
        values = query(VIRSH + arguments).splitlines()
        if len(values) != len(set(values)) or any(str(uuid.UUID(value)) != value for value in values):
            raise RunError("Malformed or duplicate UUID inventory")
        return set(values)

    network_observations = None
    if allow_inactive_dangling:
        names, identities_seen, network_names = set(), set(), {}
        for network in networks:
            name, identity = network.findtext("name"), network.findtext("uuid")
            if (
                network.tag != "network" or len(network.findall("name")) != 1
                or len(network.findall("uuid")) != 1 or not name
                or not identity or str(uuid.UUID(identity)) != identity
                or name in names or identity in identities_seen
            ):
                raise RunError("Malformed or duplicate network inventory")
            names.add(name)
            identities_seen.add(identity)
            network_names[identity] = name
        # Force a fresh full kernel query even when no interface needs resolution.
        references.load_links()
        net_all = identities(["net-list", "--all", "--uuid"])
        net_active = identities(["net-list", "--uuid"])
        net_persistent = identities(["net-list", "--all", "--persistent", "--uuid"])
        if net_all != identities_seen or net_active | net_persistent != net_all:
            raise RunError("Network inventory changed during dependency discovery")
        definitions = []
        for identity in sorted(net_persistent):
            xml = query(VIRSH + ["net-dumpxml", identity, "--inactive"])
            try:
                defined = ET.fromstring(xml)
            except ET.ParseError as exc:
                raise RunError("Malformed persistent network XML") from exc
            if (
                defined.tag != "network" or len(defined.findall("uuid")) != 1
                or defined.findtext("uuid") != identity or len(defined.findall("name")) != 1
                or defined.findtext("name") != network_names[identity]
            ):
                raise RunError("Persistent network identity changed during discovery")
            definitions.append((identity, xml))
            references.persistent_networks[identity] = defined
        network_observations = (sorted(net_all), sorted(net_active), sorted(net_persistent), definitions)
        references.complete_inventory = True
    all_domains = identities(["list", "--all", "--uuid"])
    active = identities(["list", "--uuid"])
    persistent = identities(["list", "--all", "--persistent", "--uuid"])
    if active | persistent != all_domains:
        raise RunError("Domain inventory changed during network dependency discovery")
    observations = []
    for identity in sorted(all_domains):
        try:
            state = query(
                VIRSH + ["domstate", identity], env={**os.environ, "LC_ALL": "C"},
            ) if allow_inactive_dangling else None
            observations.append((identity, state))
            if identity in active:
                xml = query(VIRSH + ["dumpxml", identity])
                observations.append((identity, "live", xml))
                references.check_domain(ET.fromstring(xml), identity)
            if identity in persistent:
                xml = query(VIRSH + ["dumpxml", identity, "--inactive"])
                observations.append((identity, "inactive", xml))
                references.check_domain(
                    ET.fromstring(xml), identity, state=state,
                    xml_origin="inactive" if allow_inactive_dangling else None,
                    persistent=True, active=identity in active,
                )
        except ET.ParseError as exc:
            raise RunError("Malformed foreign domain XML during network discovery") from exc
    return (
        sorted(all_domains), sorted(active), sorted(persistent), observations,
        sorted(ET.tostring(network, encoding="unicode") for network in networks),
        references.links, network_observations,
    )
