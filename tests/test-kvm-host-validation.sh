#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
setup="$root/scripts/setup-host"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Production accepts exactly the fixed canonical path. Exercise filesystem
# checks through the same validator with a temporary expected root.
base_dir="$root/scripts/kvm-base-dir"
[[ $(env -u IDARSI_TEST_KVM_BASE_DIR "$base_dir") == /var/lib/libvirt/images/idarsi-test-bases ]]
source "$base_dir"
mkdir -p "$tmp/root/parent/base" "$tmp/real"
ln -s "$tmp/real" "$tmp/root/parent/base/in-root-link"
validate_base_path "$tmp/root/parent/base" "$tmp/root/parent/base"
if validate_base_path "$tmp/root/parent/base/in-root-link" "$tmp/root/parent/base/in-root-link" 2>/dev/null; then
  printf 'In-root symlink was accepted\n' >&2
  exit 1
fi
ln -s "$tmp/real" "$tmp/root/parent-link"
if validate_base_path "$tmp/root/parent-link/base" "$tmp/root/parent-link/base" 2>/dev/null; then
  printf 'Symlinked ancestor was accepted\n' >&2
  exit 1
fi
for path in "$tmp/canonical" "$tmp/link" / /var/lib/libvirt/images /tmp \
  /var/lib/libvirt/images/idarsi-test-bases/../other \
  /var/lib/libvirt/images/idarsi-test-bases/child\ name; do
  if [[ "$path" == "$tmp/link" ]]; then ln -s "$tmp/canonical" "$path"; fi
  if IDARSI_TEST_KVM_BASE_DIR="$path" "$base_dir" >"$tmp/out" 2>&1; then
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

# Exercise setup-host's read-only KVM check with an isolated virsh executable.
# No libvirt command or host state is touched by these scenarios.
mock_bin="$tmp/mock-bin"
mkdir -p "$mock_bin"
cat >"$mock_bin/rpm" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat >"$mock_bin/systemctl" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat >"$mock_bin/id" <<'SH'
#!/usr/bin/env bash
printf 'users libvirt\n'
SH
cat >"$mock_bin/virsh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$VIRSH_LOG"
[[ $1 == --connect ]] && shift 2
case "$1:$2:${KVM_CASE:-ready}" in
  net-info:default:*) printf 'Active: yes\nAutostart: yes\n' ;;
  net-info:idarsi-test:missing-network) exit 1 ;;
  net-info:idarsi-test:*) printf 'Active: yes\nAutostart: yes\n' ;;
  net-dumpxml:idarsi-test:conflicting-network-nat) printf '<network><name>idarsi-test</name><forward mode="route"/><bridge name="virbr-idarsi"/><ip address="192.168.250.1" netmask="255.255.255.0"><dhcp><range start="192.168.250.100" end="192.168.250.199"/></dhcp></ip></network>\n' ;;
  net-dumpxml:idarsi-test:conflicting-network-dhcp) printf '<network><name>idarsi-test</name><forward mode="nat"/><bridge name="virbr-idarsi"/><ip address="192.168.250.1" netmask="255.255.255.0"><dhcp><range start="192.168.250.20" end="192.168.250.30"/></dhcp></ip></network>\n' ;;
  net-dumpxml:idarsi-test:*) cat "$EXPECTED_NETWORK" ;;
  pool-info:idarsi-test-bases:missing-pool) exit 1 ;;
  pool-info:idarsi-test-bases:*) printf 'State: running\nAutostart: yes\n' ;;
  pool-dumpxml:idarsi-test-bases:conflicting-pool-type) printf '<pool type="logical"><name>idarsi-test-bases</name><target><path>%s</path></target></pool>\n' "$EXPECTED_TARGET" ;;
  pool-dumpxml:idarsi-test-bases:conflicting-pool-target) printf '<pool type="dir"><name>idarsi-test-bases</name><target><path>/wrong</path></target></pool>\n' ;;
  pool-dumpxml:idarsi-test-bases:*) printf '<pool type="dir"><name>idarsi-test-bases</name><target><path>%s</path></target></pool>\n' "$EXPECTED_TARGET" ;;
  *) printf 'Unexpected virsh command: %s\n' "$*" >&2; exit 99 ;;
esac
SH
chmod +x "$mock_bin"/*
export VIRSH_LOG="$tmp/virsh.log" EXPECTED_NETWORK="$root/config/idarsi-test-network.xml"
mkdir -p "$tmp/kvm-base-dir"
export EXPECTED_TARGET="$tmp/kvm-base-dir"
export PATH="$mock_bin:$PATH"

cat >"$tmp/rocky-10-os-release" <<'EOF'
ID=rocky
VERSION_ID="10"
EOF
cat >"$tmp/ubuntu-os-release" <<'EOF'
ID=ubuntu
VERSION_ID="24.04"
EOF

run_host_check() {
  local scenario=$1 expected_status=$2
  : >"$VIRSH_LOG"
  if KVM_CASE="$scenario" IDARSI_TEST_KVM_CHECK_BASE_DIR="$EXPECTED_TARGET" \
    IDARSI_TEST_KVM_DEVICE="${kvm_device:-/dev/kvm}" \
    IDARSI_TEST_OS_RELEASE_FILE="$tmp/rocky-10-os-release" "$setup" check kvm >"$tmp/check.out" 2>&1; then
    status=0
  else
    status=$?
  fi
  if [[ $status -ne $expected_status ]]; then
    cat "$tmp/check.out" >&2
    printf 'Scenario %s returned %s (expected %s)\n' "$scenario" "$status" "$expected_status" >&2
    exit 1
  fi
  if grep -Eq '(^| )(net-define|net-start|net-autostart|pool-define|pool-start|pool-autostart)( |$)' "$VIRSH_LOG"; then
    printf 'Check mode invoked a mutating virsh command in scenario %s\n' "$scenario" >&2
    cat "$VIRSH_LOG" >&2
    exit 1
  fi
}

kvm_device=/dev/null
run_host_check ready 0
: >"$VIRSH_LOG"
if IDARSI_TEST_OS_RELEASE_FILE="$tmp/ubuntu-os-release" "$setup" check kvm >"$tmp/check.out" 2>&1; then
  printf 'Unsupported Ubuntu OS-release fixture was accepted\n' >&2
  exit 1
fi
grep -q 'detected ubuntu 24.04' "$tmp/check.out"
[[ ! -s "$VIRSH_LOG" ]]
kvm_device="$tmp/not-a-char-device"
touch "$kvm_device"
run_host_check ready 1
kvm_device=/dev/null
run_host_check missing-network 1
run_host_check missing-pool 1
for conflict in conflicting-network-nat conflicting-network-dhcp; do
  run_host_check "$conflict" 1
  grep -q 'Conflicting libvirt idarsi-test network' "$tmp/check.out"
done
for conflict in conflicting-pool-type conflicting-pool-target; do
  run_host_check "$conflict" 1
  grep -q 'Conflicting idarsi-test-bases pool target' "$tmp/check.out"
done

printf 'KVM host validation checks passed.\n'
