#!/usr/bin/env python3
"""Check virsh domain info and block info against blueprint resource values."""

import re
import sys


def field(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}:\s*(.+?)\s*$", text, re.MULTILINE)
    if not match:
        raise ValueError(f"missing {name} field")
    return match.group(1)


def check(dominfo: str, domblkinfo: str, memory_mb: int, vcpus: int, disk_gb: int) -> None:
    memory_kib = int(field(dominfo, "Max memory").split()[0])
    actual_vcpus = int(field(dominfo, "CPU(s)"))
    capacity = int(field(domblkinfo, "Capacity").split()[0])
    expected = (memory_mb * 1024, vcpus, disk_gb * 1024**3)
    actual = (memory_kib, actual_vcpus, capacity)
    if actual != expected:
        raise ValueError(f"resource mismatch: expected memory/vCPU/disk {expected}, got {actual}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("Usage: check-nested-kvm-resources MEMORY_MB VCPUS DISK_GB < VIRSH_OUTPUT")
    try:
        dominfo, domblkinfo = sys.stdin.read().split("\n--- DOMBLKINFO ---\n", maxsplit=1)
        check(dominfo, domblkinfo, *(int(value) for value in sys.argv[1:]))
    except (ValueError, TypeError) as error:
        raise SystemExit(f"FAIL: {error}") from error
