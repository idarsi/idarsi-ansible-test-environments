#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
test_timeout=${TEST_TIMEOUT_SECONDS:-120}
test_pid=$BASHPID
(
  /usr/bin/sleep "$test_timeout"
  printf 'Explicit-disk test exceeded %s seconds.\n' "$test_timeout" >&2
  kill -TERM "$test_pid"
) &
watchdog_pid=$!
trap 'kill "$watchdog_pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
bin="$tmp/bin"
scenario="$tmp/scenario"
mkdir -p "$bin" "$scenario"
: >"$tmp/installer.iso"
cat >"$bin/qemu-img" <<'SH'
#!/usr/bin/env bash
[[ $1 == create && $2 == -f && $3 == qcow2 ]] || exit 90
printf 'qemu-img %s\n' "$*" >>"$CALL_LOG"
: >"${@: -2:1}"
if [[ ${DISK_COLLISION:-0} == 1 ]]; then printf 'foreign disk\n' >"$DISK_PATH"; fi
if [[ ${QEMU_FAIL_AFTER_CREATE:-0} == 1 ]]; then exit 1; fi
SH
cat >"$bin/virt-install" <<'SH'
#!/usr/bin/env bash
printf 'virt-install %s\n' "$*" >>"$CALL_LOG"
rm -f "$DOMAIN_UUID_FILE.stopped" "$DOMAIN_UUID_FILE.absent"
while (($#)); do
  if [[ $1 == --uuid ]]; then printf '%s\n' "$2" >"$DOMAIN_UUID_FILE"; break; fi
  shift
done
if [[ ${BLOCK_VIRT_INSTALL:-0} == 1 ]]; then
  : >"$VIRT_INSTALL_STARTED"
  trap ' : >"$VIRT_INSTALL_TERM_RECEIVED"' TERM
  while [[ ! -e $VIRT_INSTALL_RELEASE ]]; do sleep 0.05; done
  : >"$VIRT_INSTALL_TERMINATED"
  exit 143
fi
if [[ ${MOCK_INSTALL_SUCCESS:-0} == 1 ]]; then exit 0; fi
if [[ ${EXPECT_EXPLICIT:-1} == 1 ]]; then
  [[ $(stat -c '%a' "$DISK_PATH") == 600 && -f $DISK_PATH && ! -L $DISK_PATH ]] || exit 91
else
  [[ " $* " == *'--disk size=12,format=qcow2,bus=virtio '* ]] || exit 92
fi
exit 1
SH
cat >"$bin/ln" <<'SH'
#!/usr/bin/env bash
/usr/bin/ln "$@" || exit
if [[ ${SIGNAL_AFTER_DISK_LINK:-0} == 1 && ${*: -1} == "$KVM_DISK_PATH" ]]; then
  kill -TERM "$PPID"
fi
SH
cat >"$bin/virsh" <<'SH'
#!/usr/bin/env bash
printf 'virsh %s\n' "$*" >>"$CALL_LOG"
case "$*" in
  *dominfo*)
    count=$(cat "$DOMINFO_COUNT" 2>/dev/null || printf 0)
    count=$((count + 1)); printf '%s' "$count" >"$DOMINFO_COUNT"
    if ((count == 1)); then exit 1; else exit 0; fi
    ;;
  *domuuid*) [[ ${QUERY_FAIL:-0} == 0 ]] || exit 1; printf '%s\n' "${MOCK_DOMAIN_UUID:-$(cat "$DOMAIN_UUID_FILE" 2>/dev/null || printf 00000000-0000-0000-0000-000000000001)}";;
  *net-info*) printf 'Active: yes\n';;
  *domstate*)
    if [[ -e $DOMAIN_UUID_FILE.absent ]]; then echo 'error: Domain not found' >&2; exit 1; fi
    if [[ -e $DOMAIN_UUID_FILE.stopped ]]; then echo 'shut off'; else echo "${DOMAIN_STATE:-running}"; fi ;;
  *destroy*) [[ ${DESTROY_FAIL:-0} == 0 ]] || exit 1; touch "$DOMAIN_UUID_FILE.stopped" ;;
  *undefine*) [[ ${UNDEFINE_FAIL:-0} == 0 ]] || exit 1; touch "$DOMAIN_UUID_FILE.absent" ;;
  *domifaddr*) printf 'vnet0 52:54  ipv4 192.0.2.2/24\n';;
  *) exit 0 ;;
esac
SH
cat >"$bin/ssh-keygen" <<'SH'
#!/usr/bin/env bash
while (($#)); do if [[ $1 == -f ]]; then key=$2; shift 2; else shift; fi; done
printf 'private\n' >"$key"; printf 'public\n' >"$key.pub"
SH
cat >"$bin/ssh" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat >"$bin/sleep" <<'SH'
#!/usr/bin/env bash
# Let child processes and the SECONDS-based deadline advance without making
# polling loops spin or imposing their production five-second delay.
/usr/bin/sleep 0.05
SH
cat >"$bin/sudo" <<'SH'
#!/usr/bin/env bash
printf 'Unexpected sudo invocation\n' >&2
exit 99
SH
chmod +x "$bin"/*
export PATH="$bin:$PATH" CALL_LOG="$tmp/calls" DOMINFO_COUNT="$tmp/dominfo-count" DOMAIN_UUID_FILE="$tmp/domain-uuid" MOLECULE_EPHEMERAL_DIRECTORY="$scenario"
export KVM_BASE_IMAGE_MODE=off KVM_DISK_SIZE_GB=12 KVM_INSTALL_TIMEOUT=60
export KVM_IPV4_ADDRESS=192.0.2.2
export KVM_DISK_PATH="$tmp/explicit.qcow2" KVM_LOG_DIR="$tmp/logs"
export DISK_PATH="$KVM_DISK_PATH"
: >"$CALL_LOG"
if "$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1; then
  printf 'Expected mocked virt-install failure.\n' >&2
  exit 1
fi
grep -q '^qemu-img ' "$CALL_LOG"
grep -q 'qemu-img create -f qcow2 .* 12G' "$CALL_LOG"
grep -q -- "--disk path=$KVM_DISK_PATH,format=qcow2,bus=virtio" "$CALL_LOG"
grep -q -- '--uuid ' "$CALL_LOG"
grep -q '^virt-install ' "$CALL_LOG"
[[ ! -e "$KVM_DISK_PATH" ]]
explicit_uuid=$(cat "$DOMAIN_UUID_FILE")
grep -q "^virsh --connect qemu:///system destroy $explicit_uuid$" "$CALL_LOG"
grep -q "^virsh --connect qemu:///system undefine $explicit_uuid$" "$CALL_LOG"
! grep -q -- '--remove-all-storage' "$CALL_LOG"
! grep -Eq '^virsh .* (destroy|undefine) molecule-' "$CALL_LOG"

# Failed cleanup must leave the explicit disk intact, including query errors
# and foreign UUIDs. A paused owned guest must be stopped before unlinking.
for failure in DESTROY_FAIL QUERY_FAIL UNDEFINE_FAIL MOCK_DOMAIN_UUID; do
  export "$failure=1"
  rm -f "$DOMINFO_COUNT"
  if "$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1; then exit 1; fi
  [[ -e $KVM_DISK_PATH ]]
  rm "$KVM_DISK_PATH"
  unset "$failure"
done
export DOMAIN_STATE=paused
rm -f "$DOMINFO_COUNT"
if "$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1; then exit 1; fi
[[ ! -e $KVM_DISK_PATH ]]
unset DOMAIN_STATE

export EXPECT_EXPLICIT=0
unset KVM_DISK_PATH
: >"$CALL_LOG"
rm -f "$DOMINFO_COUNT"
if "$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1; then
  printf 'Expected mocked virt-install failure for generic disk allocation.\n' >&2
  exit 1
fi
! grep -q '^qemu-img ' "$CALL_LOG"
grep -q -- '--disk size=12,format=qcow2,bus=virtio' "$CALL_LOG"
generic_uuid=$(sed -n 's/^virt-install .*--uuid \([^ ]*\).*/\1/p' "$CALL_LOG")
[[ -n "$generic_uuid" ]]
grep -q "^virsh --connect qemu:///system destroy $generic_uuid$" "$CALL_LOG"
grep -q "^virsh --connect qemu:///system undefine $generic_uuid$" "$CALL_LOG"
! grep -q -- '--remove-all-storage' "$CALL_LOG"

# A same-name domain with another UUID is never touched.
export MOCK_DOMAIN_UUID=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
: >"$CALL_LOG"
rm -f "$DOMINFO_COUNT"
if "$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1; then
  printf 'Expected mocked virt-install failure for foreign-domain check.\n' >&2
  exit 1
fi
! grep -Eq '^virsh .* (destroy|undefine) ' "$CALL_LOG"
unset MOCK_DOMAIN_UUID

# A successful create publishes the matching UUID marker with private mode.
export MOCK_INSTALL_SUCCESS=1
: >"$CALL_LOG"
rm -f "$DOMINFO_COUNT"
"$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1
successful_uuid=$(cat "$DOMAIN_UUID_FILE")
[[ $(cat "$MOLECULE_EPHEMERAL_DIRECTORY/kvm-vm.uuid") == "$successful_uuid" ]]
[[ $(stat -c '%a' "$MOLECULE_EPHEMERAL_DIRECTORY/kvm-vm.uuid") == 600 ]]
rm "$MOLECULE_EPHEMERAL_DIRECTORY/kvm-vm.uuid"

# SSH readiness is not sufficient to claim a same-name domain: the UUID must
# equal the invocation UUID passed to virt-install. A foreign UUID is preserved.
export MOCK_DOMAIN_UUID=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
: >"$CALL_LOG"
rm -f "$DOMINFO_COUNT"
if "$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1; then
  printf 'Expected create to reject a mismatching domain UUID.\n' >&2
  exit 1
fi
grep -q 'does not match this create invocation' "$tmp/out"
[[ ! -e "$MOLECULE_EPHEMERAL_DIRECTORY/kvm-vm.uuid" ]]
grep -Eq '^virsh .* domuuid molecule-vm-' "$CALL_LOG"
! grep -Eq '^virsh .* (destroy|undefine) ' "$CALL_LOG"
[[ $(cat "${KVM_DISK_PATH:-/nonexistent}" 2>/dev/null || true) != 'foreign disk' ]]
unset MOCK_INSTALL_SUCCESS MOCK_DOMAIN_UUID

printf 'untouched\n' >"$tmp/existing.qcow2"
export KVM_DISK_PATH="$tmp/existing.qcow2"
rm -f "$DOMINFO_COUNT"
if "$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1; then
  printf 'Expected existing explicit disk rejection.\n' >&2
  exit 1
fi
grep -q 'already exists or is a symlink' "$tmp/out"
[[ $(cat "$tmp/existing.qcow2") == untouched ]]
ln -s "$tmp/existing.qcow2" "$tmp/existing-link.qcow2"
export KVM_DISK_PATH="$tmp/existing-link.qcow2"
rm -f "$DOMINFO_COUNT"
if "$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1; then
  printf 'Expected explicit disk symlink rejection.\n' >&2
  exit 1
fi
grep -q 'already exists or is a symlink' "$tmp/out"
[[ $(cat "$tmp/existing.qcow2") == untouched ]]
export KVM_DISK_PATH="$tmp/partial.qcow2" QEMU_FAIL_AFTER_CREATE=1
: >"$CALL_LOG"
rm -f "$DOMINFO_COUNT"
if "$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1; then
  printf 'Expected partial qemu-img failure.\n' >&2
  exit 1
fi
grep -q 'qemu-img failed to create explicit KVM disk' "$tmp/out"
[[ ! -e "$KVM_DISK_PATH" ]]
! grep -q '^virt-install ' "$CALL_LOG"
unset QEMU_FAIL_AFTER_CREATE
export KVM_DISK_PATH="$tmp/collision.qcow2" DISK_PATH="$tmp/collision.qcow2" DISK_COLLISION=1
rm -f "$DOMINFO_COUNT"
if "$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1; then
  printf 'Expected atomic explicit disk publication collision.\n' >&2
  exit 1
fi
[[ $(cat "$KVM_DISK_PATH") == 'foreign disk' ]]
unset DISK_COLLISION
rm -f "$KVM_DISK_PATH"

# Signal after explicit-disk publication but before explicit_disk_owned is
# assigned. Cleanup may remove it only because staging and final are one inode.
export KVM_DISK_PATH="$tmp/signalled-publication.qcow2" DISK_PATH="$tmp/signalled-publication.qcow2" SIGNAL_AFTER_DISK_LINK=1
rm -f "$DOMINFO_COUNT"
if "$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1; then
  printf 'Expected signal during explicit disk publication.\n' >&2
  exit 1
fi
[[ ! -e "$KVM_DISK_PATH" ]]
[[ -z $(find "$tmp" -maxdepth 2 -name disk.qcow2 -print -quit) ]]
unset SIGNAL_AFTER_DISK_LINK

export KVM_DISK_PATH="$tmp/unsafe,disk.qcow2"
rm -f "$DOMINFO_COUNT"
if "$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1; then
  printf 'Expected comma-containing explicit disk path rejection.\n' >&2
  exit 1
fi
grep -q 'must not contain commas' "$tmp/out"
[[ ! -e "$KVM_DISK_PATH" ]]

# Signal the VM-free mocked install and ensure cleanup waits for its child
# before removing the invocation-owned disk.
export KVM_DISK_PATH="$tmp/signalled.qcow2" BLOCK_VIRT_INSTALL=1
export VIRT_INSTALL_STARTED="$tmp/virt-install-started"
export VIRT_INSTALL_TERM_RECEIVED="$tmp/virt-install-term-received"
export VIRT_INSTALL_TERMINATED="$tmp/virt-install-terminated"
export VIRT_INSTALL_RELEASE="$tmp/virt-install-release"
unset EXPECT_EXPLICIT
rm -f "$VIRT_INSTALL_STARTED" "$VIRT_INSTALL_TERM_RECEIVED" "$VIRT_INSTALL_TERMINATED" "$VIRT_INSTALL_RELEASE"
rm -f "$DOMINFO_COUNT"
"$repo_root/scripts/kvm-vm" create vm "$tmp/installer.iso" "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" >"$tmp/out" 2>&1 &
vm_pid=$!
for _ in {1..100}; do
  [[ -e "$VIRT_INSTALL_STARTED" ]] && break
  sleep 0.05
done
[[ -e "$VIRT_INSTALL_STARTED" ]] || { printf 'Mock virt-install did not start.\n' >&2; kill "$vm_pid" 2>/dev/null || true; exit 1; }
kill -TERM "$vm_pid"
for _ in {1..100}; do
  [[ -e "$VIRT_INSTALL_TERM_RECEIVED" ]] && break
  sleep 0.05
done
[[ -e "$VIRT_INSTALL_TERM_RECEIVED" ]] || { printf 'Mock child did not receive TERM.\n' >&2; kill -KILL "$vm_pid" 2>/dev/null || true; exit 1; }
[[ -e "$KVM_DISK_PATH" ]] || { printf 'Disk was removed before child termination/reap.\n' >&2; exit 1; }
[[ ! -e "$VIRT_INSTALL_TERMINATED" ]] || { printf 'Mock child exited before release.\n' >&2; exit 1; }
: >"$VIRT_INSTALL_RELEASE"
if wait "$vm_pid"; then
  printf 'Expected signalled VM creation to fail.\n' >&2
  exit 1
fi
[[ -e "$VIRT_INSTALL_TERMINATED" ]]
[[ ! -e "$KVM_DISK_PATH" ]]
printf 'KVM explicit-disk checks passed.\n'
