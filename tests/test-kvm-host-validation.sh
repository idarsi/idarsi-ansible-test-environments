#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
setup="$root/scripts/setup-host"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Invalid paths must fail before OS discovery, sudo, or any other host operation.
for path in / /var/lib/libvirt/images /tmp /var/lib/libvirt/images/idarsi-test-bases/../other; do
  if IDARSI_TEST_KVM_BASE_DIR="$path" "$setup" check kvm >"$tmp/out" 2>&1; then
    printf 'Unsafe path was accepted: %s\n' "$path" >&2
    exit 1
  fi
  grep -q 'IDARSI_TEST_KVM_BASE_DIR' "$tmp/out"
done

# Verify the same XML contract enforced against a defined network: full NAT,
# bridge/address/netmask and exact single DHCP range, not just its identity.
python3 - "$root/config/idarsi-test-network.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
f, b, ip = root.find('forward'), root.find('bridge'), root.find('ip')
assert root.findtext('name') == 'idarsi-test'
assert f is not None and f.get('mode') == 'nat'
assert b is not None and b.get('name') == 'virbr-idarsi'
assert ip is not None and ip.get('address') == '192.168.250.1' and ip.get('netmask') == '255.255.255.0'
ranges = ip.findall('dhcp/range')
assert len(ranges) == 1 and ranges[0].get('start') == '192.168.250.100' and ranges[0].get('end') == '192.168.250.199'
PY

printf 'KVM host validation checks passed.\n'
