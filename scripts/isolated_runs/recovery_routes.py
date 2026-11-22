"""Strict route-address semantics for recovery absence, not a routing engine."""

import ipaddress
import re

from .state import RunError


def address(value, subnet, version: int, *, prefix: bool = False) -> None:
    """Validate an address field before testing association; invalid is not absent."""
    if not isinstance(value, str):
        raise RunError("route_query_incomplete")
    try:
        parsed = ipaddress.ip_network(value, strict=False) if prefix else ipaddress.ip_address(value)
    except ValueError as exc:
        raise RunError("route_query_incomplete") from exc
    if parsed.version != version:
        raise RunError("route_query_incomplete")
    associated = parsed.overlaps(subnet) if prefix and version == subnet.version else (
        parsed in subnet if not prefix and version == subnet.version else False
    )
    if associated:
        raise RunError("subnet_route_remains")


def path_fields(route: dict, subnet, bridge: str, version: int) -> None:
    for key in ("gateway", "prefsrc", "src", "from"):
        if key in route:
            if key == "from" and route[key] == "all":
                continue
            address(route[key], subnet, version, prefix=key in ("src", "from"))
    if "via" in route:
        via = route["via"]
        if (
            not isinstance(via, dict)
            or set(via) not in ({"family", "host"}, {"family", "addr"})
            or via["family"] not in ("inet", "inet6")
        ):
            raise RunError("route_query_incomplete")
        address(via.get("host", via.get("addr")), subnet, 4 if via["family"] == "inet" else 6)
    if "dev" in route:
        device = route["dev"]
        if not isinstance(device, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", device):
            raise RunError("route_query_incomplete")
        if device == bridge:
            raise RunError("bridge_or_interface_remains")
    if "flags" in route:
        flags = route["flags"]
        if not isinstance(flags, list) or any(flag not in (
            "onlink", "linkdown", "dead", "pervasive", "offload", "trap",
            "notify", "cloned", "equalize", "prefix", "rt_offload_failed",
        ) for flag in flags):
            raise RunError("route_query_incomplete")


def verify(routes, subnet, bridge: str, version: int) -> None:
    """Check destinations, all source/gateway forms and supported explicit nexthops."""
    if not isinstance(routes, list):
        raise RunError("route_query_incomplete")
    allowed = {
        "dst", "gateway", "prefsrc", "src", "from", "via", "dev", "flags",
        "protocol", "scope", "type", "table", "metric", "mtu", "advmss",
        "hoplimit", "pref", "preference", "expires", "cache", "nexthops", "multipath",
    }
    for route in routes:
        if not isinstance(route, dict) or set(route) - allowed or "dst" not in route:
            # Includes unresolved nhid and encapsulation/reference objects.
            raise RunError("route_query_incomplete")
        if route["dst"] != "default":
            address(route["dst"], subnet, version, prefix=True)
        path_fields(route, subnet, bridge, version)
        for key in ("nexthops", "multipath"):
            if key not in route:
                continue
            hops = route[key]
            if not isinstance(hops, list) or not hops or "nexthops" in route and "multipath" in route:
                raise RunError("route_query_incomplete")
            for hop in hops:
                if (
                    not isinstance(hop, dict) or not hop or set(hop) - {"gateway", "via", "dev", "weight", "flags"}
                    or not any(field in hop for field in ("gateway", "via", "dev"))
                    or "weight" in hop and (type(hop["weight"]) is not int or not 1 <= hop["weight"] <= 256)
                ):
                    raise RunError("route_query_incomplete")
                path_fields(hop, subnet, bridge, version)
        for key in ("metric", "mtu", "advmss", "hoplimit", "expires"):
            if key in route and (type(route[key]) is not int or route[key] < 0):
                raise RunError("route_query_incomplete")
        for key in ("protocol", "scope", "table"):
            if key in route and not (
                type(route[key]) is int and route[key] >= 0
                or isinstance(route[key], str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", route[key])
            ):
                raise RunError("route_query_incomplete")
        if "type" in route and route["type"] not in (
            "unicast", "local", "broadcast", "multicast", "unreachable", "prohibit", "blackhole", "throw",
        ):
            raise RunError("route_query_incomplete")
        if any(key in route and route[key] not in ("low", "medium", "high") for key in ("pref", "preference")):
            raise RunError("route_query_incomplete")
        if "cache" in route and route["cache"] != []:
            raise RunError("route_query_incomplete")
