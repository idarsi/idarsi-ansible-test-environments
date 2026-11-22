"""Strict, read-only host and backend discovery; errors never mean absence."""

import ipaddress
import json
import os
import subprocess
import xml.etree.ElementTree as ET

from .state import RunError

VIRSH = ["virsh", "--connect", "qemu:///system"]
PODMAN = ["podman", "--remote=false"]


def command(argv: list, timeout: int = 60, **kwargs) -> str:
    """Execute without a shell and with bounded backend command duration."""
    try:
        result = subprocess.run(
            argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout, **kwargs,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunError("Command unavailable or timed out: " + argv[0]) from exc
    if result.returncode:
        raise RunError("Command failed: " + " ".join(argv[:3]) + "\n" + result.stderr)
    return result.stdout.strip()


def podman_context() -> dict:
    """Reject rootful/remote contexts; record storage/runtime identity."""
    if os.getuid() == 0 or any(os.environ.get(key) for key in (
        "CONTAINER_HOST", "CONTAINER_CONNECTION", "DOCKER_HOST",
    )):
        raise RunError("Only local rootless Podman with no remote override is supported")
    info = json.loads(command(PODMAN + ["info", "--format", "json"]))
    if info["host"]["security"]["rootless"] is not True:
        raise RunError("Podman context is not rootless")
    return {
        "uid": os.getuid(), "graph_root": info["store"]["graphRoot"],
        "run_root": info["store"]["runRoot"],
        "network_backend": info["host"]["networkBackend"],
    }


def libvirt_networks(runner=None) -> list:
    query = command if runner is None else runner
    networks = []
    for identity in query(VIRSH + ["net-list", "--all", "--uuid"]).splitlines():
        root = ET.fromstring(query(VIRSH + ["net-dumpxml", identity]))
        networks.append(root)
    return networks


def podman_networks() -> list:
    names = command(PODMAN + ["network", "ls", "--format", "{{.Name}}"]).splitlines()
    if not names:
        return []
    result = json.loads(command(PODMAN + ["network", "inspect"] + names))
    if not isinstance(result, list) or len(result) != len(names):
        raise RunError("Incomplete Podman network discovery")
    return result


def discover() -> list:
    """Scan both backends, all interfaces and all routing tables."""
    podman_context()
    networks = []
    addresses = json.loads(command(["ip", "-j", "address", "show"]))
    for interface in addresses:
        for address in interface["addr_info"]:
            if address["family"] == "inet":
                networks.append(ipaddress.ip_network(
                    "{}/{}".format(address["local"], address["prefixlen"]), strict=False,
                ))
    routes = json.loads(command(["ip", "-j", "-4", "route", "show", "table", "all"]))
    for route in routes:
        destination = route.get("dst")
        if destination in ("default", "0.0.0.0/0"):
            continue
        if not destination:
            raise RunError("Route has no destination; cannot prove subnet availability")
        networks.append(ipaddress.ip_network(destination, strict=False))
    for root in libvirt_networks():
        for address in root.findall("ip"):
            if address.get("family", "ipv4") == "ipv4":
                prefix = address.get("prefix") or address.get("netmask")
                if not prefix:
                    raise RunError("Libvirt IPv4 network has no prefix or netmask")
                networks.append(ipaddress.ip_network(
                    address.attrib["address"] + "/" + prefix, strict=False,
                ))
        for route in root.findall("route"):
            if route.get("family", "ipv4") == "ipv4":
                prefix = route.get("prefix") or route.get("netmask")
                if prefix is None:
                    raise RunError("Libvirt route has no prefix")
                network = ipaddress.ip_network(route.attrib["address"] + "/" + prefix, strict=False)
                if network.prefixlen:
                    networks.append(network)
    for network in podman_networks():
        for subnet in network["subnets"]:
            networks.append(ipaddress.ip_network(subnet["subnet"], strict=False))
    return networks
