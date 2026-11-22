"""Read-only boot-fenced network-tail reconciliation, never ad hoc teardown.

There is deliberately no approved mutation-driver profile in this release.
Present resources require independently reviewed driver/vendor/helper tracking.
"""

import ipaddress
import json
import fnmatch
from pathlib import Path
import re
import shlex
import uuid
import xml.etree.ElementTree as ET

from . import recovery_routes, recovery_system
from .discovery import libvirt_networks
from .recovery_commands import command
from .network_references import assert_network_unused, owned_bridge
from .state import RunError, existing_lock


def expected_network(data: dict):
    """Reconstruct only the exact generated legacy network configuration."""
    intent = data["network"]
    subnet = ipaddress.ip_network(data["subnet"])
    root = ET.Element("network")
    ET.SubElement(root, "name").text = intent["name"]
    ET.SubElement(root, "uuid").text = intent["id"]
    ET.SubElement(root, "bridge", name="it" + intent["id"].replace("-", "")[:12])
    ET.SubElement(root, "forward", mode="nat")
    ET.SubElement(root, "domain", name=intent["name"] + ".test", localOnly="yes")
    address = ET.SubElement(root, "ip", address=str(subnet[1]), netmask="255.255.255.0")
    dhcp = ET.SubElement(address, "dhcp")
    ET.SubElement(dhcp, "range", start=str(subnet[210]), end=str(subnet[250]))
    owned_bridge(root, intent, data["subnet"])
    return root


def strings(value):
    """Visit every JSON key/value; unknown expression shapes cannot hide strings."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def overlaps(value: str, subnet) -> bool:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return network.version == 4 and network.overlaps(subnet)


def range_overlaps(first, last, subnet) -> bool:
    try:
        lower, upper = ipaddress.ip_address(first), ipaddress.ip_address(last)
    except ValueError:
        return False
    return lower.version == upper.version == 4 and lower <= subnet.broadcast_address and upper >= subnet.network_address


def iptables_rule(tokens: list, subnet, bridge: str, version: int) -> None:
    """Small explicit selector whitelist, not an iptables extension interpreter."""
    modules, seen = set(), set()
    protocol, target = None, None
    index = 2
    while index < len(tokens):
        option = tokens[index]
        index += 1
        if option == "!" or option not in {
            "-s", "--source", "-d", "--destination", "-i", "--in-interface",
            "-o", "--out-interface", "-p", "--protocol", "-m", "--match",
            "-j", "--jump", "--ctstate", "--state", "--comment",
            "--sport", "--source-port", "--dport", "--destination-port",
        }:
            raise RunError("firewall_expression_unproven")
        if index >= len(tokens):
            raise RunError("firewall_query_incomplete")
        value = tokens[index]
        index += 1
        if option in ("-m", "--match"):
            if value not in ("conntrack", "state", "comment", "tcp", "udp") or value in modules:
                raise RunError("firewall_expression_unproven")
            modules.add(value)
            continue
        canonical = {
            "--source": "-s", "--destination": "-d", "--in-interface": "-i",
            "--out-interface": "-o", "--protocol": "-p", "--jump": "-j",
            "--source-port": "--sport", "--destination-port": "--dport",
        }.get(option, option)
        if canonical in seen:
            raise RunError("firewall_expression_unproven")
        seen.add(canonical)
        if canonical in ("-s", "-d"):
            try:
                address = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise RunError("firewall_expression_unproven") from exc
            if address.version != version:
                raise RunError("firewall_query_incomplete")
            if address.version == subnet.version and address.overlaps(subnet):
                raise RunError("firewall_footprint_remains")
        elif canonical in ("-i", "-o"):
            if not re.fullmatch(r"(?:[A-Za-z0-9_.:-]{1,15}|[A-Za-z0-9_.:-]{0,15}\+)", value):
                raise RunError("firewall_expression_unproven")
            if bridge == value or value.endswith("+") and bridge.startswith(value[:-1]):
                raise RunError("firewall_footprint_remains")
        elif canonical == "-p":
            if value not in ("tcp", "udp", "icmp", "ipv6-icmp", "icmpv6", "all", "6", "17", "1", "58", "0"):
                raise RunError("firewall_expression_unproven")
            protocol = value
        elif canonical == "-j":
            if value not in ("ACCEPT", "DROP", "RETURN", "REJECT"):
                # Includes NAT targets and arbitrary chain/extension dispatch.
                raise RunError("firewall_expression_unproven")
            target = value
        elif canonical in ("--ctstate", "--state"):
            required = "conntrack" if canonical == "--ctstate" else "state"
            states = value.split(",")
            if required not in modules or not states or any(
                state not in ("NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED")
                for state in states
            ):
                raise RunError("firewall_expression_unproven")
        elif canonical == "--comment":
            if "comment" not in modules:
                raise RunError("firewall_expression_unproven")
        else:  # Supported numeric TCP/UDP ports, never opaque extension options.
            if protocol not in ("tcp", "udp", "6", "17") or not re.fullmatch(r"\d+(?::\d+)?", value):
                raise RunError("firewall_expression_unproven")
            ports = [int(port) for port in value.split(":")]
            if any(port > 65535 for port in ports) or ports != sorted(ports):
                raise RunError("firewall_expression_unproven")
    if target is None:
        raise RunError("firewall_expression_unproven")
    if (
        ("tcp" in modules and protocol not in ("tcp", "6"))
        or ("udp" in modules and protocol not in ("udp", "17"))
    ):
        raise RunError("firewall_expression_unproven")
    # A declared extension with omitted required options is not supported proof.
    for module, required in (("conntrack", "--ctstate"), ("state", "--state"), ("comment", "--comment")):
        if module in modules and required not in seen:
            raise RunError("firewall_expression_unproven")


def validate_iptables(text: str, subnet, bridge: str, version: int) -> None:
    """Validate complete save framing and semantics; unknown selectors block."""
    table = None
    tables, chains = set(), set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("*") and table is None:
            table = line[1:]
            if table not in ("filter", "nat", "mangle", "raw", "security") or table in tables:
                raise RunError("firewall_query_incomplete")
            tables.add(table)
            chains = set()
        elif line == "COMMIT" and table is not None:
            table = None
        elif table is not None and line.startswith(":"):
            declaration = re.fullmatch(r":([A-Za-z0-9_.:+-]{1,127}) (?:ACCEPT|DROP|-) \[[0-9]+:[0-9]+\]", line)
            if declaration is None or declaration[1] in chains:
                raise RunError("firewall_query_incomplete")
            chains.add(declaration[1])
        elif table is not None and line.startswith("-A "):
            try:
                tokens = shlex.split(line, comments=False, posix=True)
            except ValueError as exc:
                raise RunError("firewall_query_incomplete") from exc
            if len(tokens) < 2 or tokens[0] != "-A" or tokens[1] not in chains:
                raise RunError("firewall_query_incomplete")
            iptables_rule(tokens, subnet, bridge, version)
        else:
            raise RunError("firewall_query_incomplete")
    if table is not None:
        raise RunError("firewall_query_incomplete")


def nft_address(value, subnet) -> bool:
    """Interpret only explicit IPv4 literal/prefix/range/set selectors."""
    if isinstance(value, str):
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise RunError("firewall_expression_unproven") from exc
        return network.version == 4 and network.overlaps(subnet)
    if isinstance(value, dict) and len(value) == 1:
        if "prefix" in value and isinstance(value["prefix"], dict) and set(value["prefix"]) == {"addr", "len"}:
            prefix = value["prefix"]
            return nft_address(str(prefix["addr"]) + "/" + str(prefix["len"]), subnet)
        if "range" in value and isinstance(value["range"], list) and len(value["range"]) == 2:
            try:
                first, last = map(ipaddress.ip_address, value["range"])
            except ValueError as exc:
                raise RunError("firewall_expression_unproven") from exc
            if first.version != 4 or last.version != 4 or first > last:
                raise RunError("firewall_expression_unproven")
            return first <= subnet.broadcast_address and last >= subnet.network_address
        if "set" in value and isinstance(value["set"], list):
            # Evaluate all elements, even after an overlapping one.
            return any([nft_address(item, subnet) for item in value["set"]])
    raise RunError("firewall_expression_unproven")


def nft_expressions(expressions: list, subnet, bridge: str) -> None:
    """Small whitelist, not a claim to implement nft's expression language.

    Arithmetic/bitmask, named sets, maps, concatenation, inverted comparisons
    and any unknown expression are uncertainty blockers. String traversal below
    is an additional conservative check, never the completeness proof.
    """
    for expression in expressions:
        if not isinstance(expression, dict) or len(expression) != 1:
            raise RunError("firewall_expression_unproven")
        kind, body = next(iter(expression.items()))
        if kind in ("accept", "drop", "continue", "return") and body is None:
            continue
        if kind == "counter" and (
            body is None or isinstance(body, dict) and set(body) <= {"packets", "bytes"}
            and all(type(value) is int and value >= 0 for value in body.values())
        ):
            continue
        if kind != "match" or not isinstance(body, dict) or set(body) != {"op", "left", "right"} or body["op"] != "==":
            raise RunError("firewall_expression_unproven")
        left = body["left"]
        if left in (
            {"payload": {"protocol": "ip", "field": "saddr"}},
            {"payload": {"protocol": "ip", "field": "daddr"}},
        ):
            if nft_address(body["right"], subnet):
                raise RunError("firewall_footprint_remains")
        elif left in ({"meta": {"key": "iifname"}}, {"meta": {"key": "oifname"}}):
            if not isinstance(body["right"], str) or not re.fullmatch(r"[A-Za-z0-9_.:*?-]+", body["right"]):
                raise RunError("firewall_expression_unproven")
            if fnmatch.fnmatchcase(bridge, body["right"]):
                raise RunError("firewall_footprint_remains")
        else:
            raise RunError("firewall_expression_unproven")


def kernel_absent(data: dict, bridge: str) -> None:
    """Require complete interface/address/route and nftables/iptables absence."""
    subnet = ipaddress.ip_network(data["subnet"])
    addresses = json.loads(command(["ip", "-j", "address", "show"]))
    if not isinstance(addresses, list):
        raise RunError("kernel_query_incomplete")
    seen = set()
    for interface in addresses:
        if (
            not isinstance(interface, dict) or type(interface.get("ifindex")) is not int
            or not isinstance(interface.get("ifname"), str)
            or not isinstance(interface.get("addr_info"), list)
            or not isinstance(interface.get("altnames", []), list)
        ):
            raise RunError("kernel_query_incomplete")
        names = [interface["ifname"], *interface.get("altnames", [])]
        if any(not isinstance(name, str) or name in seen for name in names):
            raise RunError("kernel_query_incomplete")
        seen.update(names)
        if bridge in names or interface.get("master") == bridge:
            raise RunError("bridge_or_interface_remains")
        for address in interface["addr_info"]:
            if address.get("family") == "inet":
                network = ipaddress.ip_network(
                    str(address["local"]) + "/" + str(address["prefixlen"]), strict=False,
                )
                if network.overlaps(subnet):
                    raise RunError("subnet_address_remains")
    for version in (4, 6):
        routes = json.loads(command(["ip", "-j", "-" + str(version), "route", "show", "table", "all"]))
        recovery_routes.verify(routes, subnet, bridge, version)
    rules = json.loads(command(["nft", "-j", "list", "ruleset"]))
    if not isinstance(rules, dict) or set(rules) != {"nftables"} or not isinstance(rules["nftables"], list):
        raise RunError("firewall_query_incomplete")
    for item in rules["nftables"]:
        if not isinstance(item, dict) or len(item) != 1:
            raise RunError("firewall_query_incomplete")
        kind, body = next(iter(item.items()))
        if kind not in ("metainfo", "table", "chain", "rule", "set", "map", "element", "flowtable") or not isinstance(body, dict):
            raise RunError("firewall_query_incomplete")
        if kind == "metainfo":
            if body.get("json_schema_version") != 1:
                raise RunError("firewall_query_incomplete")
        elif (
            body.get("family") not in ("ip", "ip6", "inet", "arp", "bridge", "netdev")
            or not isinstance(body.get("name" if kind in ("table", "chain", "set", "map", "flowtable") else "table"), str)
            or (kind == "rule" and (
                not isinstance(body.get("chain"), str) or not isinstance(body.get("expr"), list)
            ))
        ):
            raise RunError("firewall_query_incomplete")
        if kind == "rule":
            nft_expressions(body["expr"], subnet, bridge)
        elif kind == "set":
            if (
                body.get("type") != "ipv4_addr" or not isinstance(body.get("elem", []), list)
                or set(body) - {
                    "family", "table", "name", "type", "handle", "flags", "elem",
                    "size", "policy", "timeout", "gc-interval", "auto-merge", "comment",
                }
                or not isinstance(body.get("flags", []), list)
                or set(body.get("flags", [])) - {"constant", "interval"}
            ):
                raise RunError("firewall_expression_unproven")
            if nft_address({"set": body.get("elem", [])}, subnet):
                raise RunError("firewall_footprint_remains")
        elif kind in ("map", "element", "flowtable"):
            raise RunError("firewall_expression_unproven")
    # Inspect legacy and nft iptables views too; neither permission failure nor a
    # missing tool can mean clean. No sudo escalation or firewall modification.
    legacy = [
        command(["iptables-save"]), command(["ip6tables-save"]),
    ]
    for version, text in zip((4, 6), legacy):
        validate_iptables(text, subnet, bridge, version)
    for text in [*strings(rules), *legacy]:
        if bridge in text or data["network"]["name"] in text:
            raise RunError("firewall_footprint_remains")
        for token in re.findall(r"[0-9]+(?:\.[0-9]+){3}(?:/[0-9]+)?", text):
            if overlaps(token, subnet):
                raise RunError("firewall_footprint_remains")
        for first, last in re.findall(r"(\d+(?:\.\d+){3})-(\d+(?:\.\d+){3})", text):
            if range_overlaps(first, last, subnet):
                raise RunError("firewall_footprint_remains")
        # Firewall interface wildcard rules can still retain this footprint.
        for token in re.findall(r"[A-Za-z0-9_.:*?+-]+", text):
            if any(character in token for character in "*?+") and fnmatch.fnmatchcase(
                bridge, token.replace("+", "*"),
            ):
                raise RunError("firewall_footprint_remains")
    # nft prefix objects split addr/len; any address in the subnet is caught
    # above, and broader subnets are conservatively checked as addresses too.
    # Catch network prefixes expressed as {"addr": ..., "len": ...} explicitly.
    def prefixes(value):
        if isinstance(value, dict):
            if "range" in value:
                interval = value["range"]
                if (
                    isinstance(interval, list) and len(interval) == 2
                    and all(isinstance(item, str) for item in interval)
                    and range_overlaps(*interval, subnet)
                ):
                    raise RunError("firewall_footprint_remains")
            if set(value) == {"addr", "len"}:
                if overlaps(str(value["addr"]) + "/" + str(value["len"]), subnet):
                    raise RunError("firewall_footprint_remains")
            for item in value.values():
                prefixes(item)
        elif isinstance(value, list):
            for item in value:
                prefixes(item)
    prefixes(rules)


def process_identity(entry: Path) -> tuple:
    """Parse stable procfs birth/UID/state/flags, rejecting incomplete metadata."""
    text = (entry / "stat").read_text()
    fields = text.rsplit(")", 1)[1].split()
    if (
        text.split(" ", 1)[0] != entry.name or len(fields) < 20
        or fields[0] not in ("R", "S", "D", "Z", "T", "t", "X", "x", "K", "W", "P", "I")
        or not fields[19].isdigit()
    ):
        raise RunError("network_helper_identity_unknown")
    return fields[0] in ("Z", "X", "x"), fields[19], entry.stat().st_uid, int(fields[6])


def helpers_absent(data: dict, bridge: str) -> None:
    """Reject any current dnsmasq/helper association; never signal by name.

    Historical process termination is supplied separately by the boot proof.
    This is not a same-boot substitute for pinned helper ownership.
    """
    recovery_system.complete_proc_view()
    proc = Path("/proc")
    entries = {entry.name: entry for entry in proc.iterdir() if entry.name.isdigit()}
    identities = {}
    executable_snapshots = {}
    for entry in entries.values():
        try:
            name = (entry / "comm").read_text().strip()
            identity = process_identity(entry)
            identities[entry.name] = identity
            arguments = (entry / "cmdline").read_bytes()
            if identity[0]:
                continue
            if identity[3] & 0x00200000:  # PF_KTHREAD; no userspace executable.
                if arguments:
                    raise RunError("network_helper_identity_unknown")
                continue
            executable = (entry / "exe").readlink()
            executable_snapshots[entry.name] = (name, executable, arguments)
            if identity != process_identity(entry):
                raise RunError("network_helper_identity_changed")
        except (FileNotFoundError, ProcessLookupError) as exc:
            # Missing executable/config is not exit proof for a surviving PID.
            if entry.exists():
                raise RunError("network_helper_identity_unknown") from exc
            continue
        except (OSError, UnicodeError, IndexError, ValueError) as exc:
            raise RunError("network_helper_identity_unknown") from exc
        if not arguments or str(executable).endswith(" (deleted)"):
            raise RunError("network_helper_identity_unknown")
        if name in ("dnsmasq", "radvd") or executable.name in ("dnsmasq", "radvd"):
            # No approved configuration/include parser exists in this MVP.
            # ANY such helper may refer indirectly to this network: retain the
            # lease even when its argv looks unrelated. Never open arbitrary
            # configuration paths or signal by executable/name/UID.
            raise RunError("network_helper_association_unproven")
    if {entry.name for entry in proc.iterdir() if entry.name.isdigit()} != set(entries):
        raise RunError("process_inventory_changed")
    try:
        if any(process_identity(entries[pid]) != identity for pid, identity in identities.items()):
            raise RunError("process_inventory_changed")
        for pid, snapshot in executable_snapshots.items():
            entry = entries[pid]
            if (
                (entry / "comm").read_text().strip(), (entry / "exe").readlink(),
                (entry / "cmdline").read_bytes(),
            ) != snapshot:
                raise RunError("process_inventory_changed")
    except (OSError, IndexError, ValueError) as exc:
        raise RunError("process_inventory_changed") from exc


def network_inventory() -> list:
    """Bound XML parsing errors in both inventory passes."""
    try:
        networks = libvirt_networks(runner=command)
    except ET.ParseError as exc:
        raise RunError("network_inventory_xml_invalid") from exc
    names, identities = set(), set()
    for network in networks:
        name, identity = network.findtext("name"), network.findtext("uuid")
        if (
            network.tag != "network" or len(network.findall("name")) != 1
            or len(network.findall("uuid")) != 1 or not name or not identity
            or name in names or identity in identities
        ):
            raise RunError("network_inventory_incomplete")
        try:
            if str(uuid.UUID(identity)) != identity:
                raise ValueError
        except ValueError as exc:
            raise RunError("network_inventory_incomplete") from exc
        names.add(name)
        identities.add(identity)
    return networks


def verify_absent(store, data: dict) -> dict:
    """No mutation: guarded exact network and OS footprint absence on this boot."""
    root = expected_network(data)
    bridge = owned_bridge(root, data["network"], data["subnet"])
    with existing_lock(store.root / ".storage-graph.lock"):
        networks = network_inventory()
        matches = [network for network in networks if (
            network.findtext("uuid") == data["network"]["id"]
            or network.findtext("name") == data["network"]["name"]
        )]
        if matches:
            if (
                len(matches) != 1
                or matches[0].findtext("uuid") != data["network"]["id"]
                or matches[0].findtext("name") != data["network"]["name"]
            ):
                raise RunError("network_replaced")
            owned_bridge(matches[0], data["network"], data["subnet"])
            raise RunError("current_mutation_profile_unavailable")
        for network in networks:
            if any(item.get("name") == bridge for item in network.findall("bridge")):
                raise RunError("bridge_identity_collision")
            for address in network.findall("ip"):
                if address.get("family", "ipv4") == "ipv4":
                    mask = address.get("prefix") or address.get("netmask")
                    if not mask:
                        raise RunError("network_inventory_incomplete")
                    try:
                        foreign_subnet = ipaddress.ip_network(address.attrib["address"] + "/" + mask, strict=False)
                    except (ValueError, KeyError) as exc:
                        raise RunError("network_inventory_incomplete") from exc
                    if foreign_subnet.version != 4:
                        raise RunError("network_inventory_incomplete")
                    if foreign_subnet.overlaps(ipaddress.ip_network(data["subnet"])):
                        raise RunError("network_subnet_collision")
            for route in network.findall("route"):
                if route.get("family", "ipv4") == "ipv4":
                    mask = route.get("prefix") or route.get("netmask")
                    if mask is None:
                        raise RunError("network_inventory_incomplete")
                    destination = ipaddress.ip_network(route.attrib["address"] + "/" + mask, strict=False)
                    if destination.prefixlen and destination.overlaps(ipaddress.ip_network(data["subnet"])):
                        raise RunError("network_subnet_collision")
        kernel_absent(data, bridge)
        assert_network_unused(root, data["network"], data["subnet"], networks, bridge_absent=True, runner=command)
        helpers_absent(data, bridge)
        # Repeat after dependency/process discovery; absence must be stable.
        if any(
            network.findtext("uuid") == data["network"]["id"]
            or network.findtext("name") == data["network"]["name"]
            for network in network_inventory()
        ):
            raise RunError("network_changed_during_verification")
        kernel_absent(data, bridge)
    return {"network": "absent", "kernel": "absent", "helpers": "absent", "mutation": False}
