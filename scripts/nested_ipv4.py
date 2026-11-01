"""Validation for static networking on the nested KVM guest."""

import ipaddress


TEST_NETWORK = ipaddress.IPv4Network("192.168.250.0/24")
DHCP_RANGE = (ipaddress.IPv4Address("192.168.250.100"), ipaddress.IPv4Address("192.168.250.199"))


def validate(address: str, netmask: str, gateway: str, nameserver: str) -> None:
    """Reject static settings not usable on the idarsi-test network."""
    if "/" in netmask:
        raise ValueError("netmask must be dotted IPv4, not a CIDR prefix")
    interface = ipaddress.IPv4Interface(f"{address}/{netmask}")
    network = interface.network
    if network != TEST_NETWORK:
        raise ValueError(f"static address/netmask must match {TEST_NETWORK}")
    if interface.ip in (network.network_address, network.broadcast_address):
        raise ValueError("static address must be a usable host address")
    if DHCP_RANGE[0] <= interface.ip <= DHCP_RANGE[1]:
        raise ValueError("static address must be outside the DHCP range .100-.199")
    for label, value in (("gateway", gateway), ("nameserver", nameserver)):
        host = ipaddress.IPv4Address(value)
        if host not in network or host in (network.network_address, network.broadcast_address):
            raise ValueError(f"{label} must be a usable member of {TEST_NETWORK}")
