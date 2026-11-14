#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mock_repo="$tmp/repo"
bin="$tmp/bin"
base_dir="$tmp/bases"
mkdir -p "$mock_repo/scripts" "$bin" "$base_dir"
cp "$repo_root/scripts/kvm-base-image" "$mock_repo/scripts/"
cat >"$mock_repo/scripts/kvm-base-dir" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$TEST_BASE_DIR"
SH
cat >"$mock_repo/scripts/kvm-base-image-os-key" <<'SH'
#!/usr/bin/env bash
printf 'fedora44\n'
SH
cat >"$mock_repo/scripts/kvm-vm" <<'SH'
#!/usr/bin/env bash
printf 'guest disk\n' >"$KVM_DISK_PATH"
printf '{"address":"192.0.2.2","user":"molecule","identity_file":"/tmp/key","uuid":"11111111-1111-4111-8111-111111111111"}\n'
SH
cat >"$bin/virsh" <<'SH'
#!/usr/bin/env bash
printf 'virsh %s\n' "$*" >>"$CALL_LOG"
case "$*" in
  *domblklist*) printf ' Type Device Target Source\n------------------------------------------------\n file disk vda %s\n' "${ATTACHED_DISK:-/unrelated/disk.qcow2}";;
  *domuuid*) printf '%s\n' "${DOMAIN_UUID:-22222222-2222-4222-8222-222222222222}";;
  *domstate*) printf 'shut off\n';;
  *undefine*) printf "Domain '%s' has been undefined\n" "${*: -1}";;
  *) exit 0;;
esac
SH
for tool in qemu-img ssh-keygen ssh; do
  printf '#!/usr/bin/env bash\nexit 0\n' >"$bin/$tool"
done
cat >"$bin/qemu-img" <<'SH'
#!/usr/bin/env bash
if [[ $1 == create ]]; then : >"${@: -1}"; fi
exit 0
SH
cat >"$bin/virt-sysprep" <<'SH'
#!/usr/bin/env bash
[[ ${SYSPREP_FAIL:-0} != 1 ]]
SH
chmod +x "$mock_repo/scripts"/* "$bin"/*
printf 'source\n' >"$tmp/source.iso"
printf 'kickstart\n' >"$tmp/kickstart.ks"
export PATH="$bin:$PATH" TEST_BASE_DIR="$base_dir" CALL_LOG="$tmp/calls"
export TMPDIR="$tmp" XDG_CACHE_HOME="$tmp/cache" KVM_LOG_DIR="$tmp/logs"
: >"$CALL_LOG"
if "$mock_repo/scripts/kvm-base-image" ensure "$tmp/source.iso" "$tmp/kickstart.ks" molecule 10 default qemu:///system >"$tmp/out" 2>&1; then
  printf 'Expected the deliberately mismatched attached-disk check to fail.\n' >&2
  exit 1
fi
if grep -Eq '^virsh .* (destroy|undefine) ' "$CALL_LOG"; then
  printf 'Wrapper attempted destructive cleanup of a domain with a different UUID.\n' >&2
  cat "$CALL_LOG" >&2
  exit 1
fi
grep -q '^virsh .* domuuid ' "$CALL_LOG"

# A sealing failure must clean the still-owned temporary disk. Destructive
# libvirt operations use the UUID, not the reusable domain name.
export DOMAIN_UUID=11111111-1111-4111-8111-111111111111
export SYSPREP_FAIL=1
export ATTACHED_DISK_MARKER="$base_dir"
: >"$CALL_LOG"
# The mock kvm-vm returns the same UUID and creates the exact disk argument.
cat >"$mock_repo/scripts/kvm-vm" <<'SH'
#!/usr/bin/env bash
printf 'guest disk\n' >"$KVM_DISK_PATH"
printf '{"address":"192.0.2.2","user":"molecule","identity_file":"/tmp/key","uuid":"11111111-1111-4111-8111-111111111111"}\n'
SH
# Have virsh report the temporary disk created by the mocked guest installer.
cat >"$bin/virsh" <<'SH'
#!/usr/bin/env bash
printf 'virsh %s\n' "$*" >>"$CALL_LOG"
case "$*" in
  *domblklist*) disk=$(find "$TEST_BASE_DIR" -name '*.building.qcow2' -print -quit); printf ' Type Device Target Source\n------------------------------------------------\n file disk vda %s\n' "$disk";;
  *domuuid*) printf '%s\n' "$DOMAIN_UUID";;
  *domstate*) printf 'shut off\n';;
  *undefine*) printf "Domain '%s' has been undefined\n" "${*: -1}";;
  *) exit 0;;
esac
SH
chmod +x "$mock_repo/scripts/kvm-vm" "$bin/virsh"
if "$mock_repo/scripts/kvm-base-image" ensure "$tmp/source.iso" "$tmp/kickstart.ks" molecule 10 default qemu:///system >"$tmp/out" 2>&1; then
  printf 'Expected mocked virt-sysprep failure.\n' >&2
  exit 1
fi
grep -q 'virsh --connect qemu:///system undefine 11111111-1111-4111-8111-111111111111' "$CALL_LOG"
! grep -Eq '^virsh .* (destroy|undefine) molecule-base-' "$CALL_LOG"
[[ -z $(find "$base_dir" -name '*.building.qcow2' -print -quit) ]]

# Successful publication retains the cache; a second ensure reuses it.
unset SYSPREP_FAIL
: >"$CALL_LOG"
"$mock_repo/scripts/kvm-base-image" ensure "$tmp/source.iso" "$tmp/kickstart.ks" molecule 10 default qemu:///system >"$tmp/published.stdout" 2>"$tmp/published.stderr"
[[ $(wc -l <"$tmp/published.stdout") -eq 1 ]]
published_image=$(cat "$tmp/published.stdout")
[[ -s "$published_image" ]]
grep -q 'Created sealed OS base image' "$tmp/published.stderr"
! grep -q 'has been undefined' "$tmp/published.stdout"
: >"$CALL_LOG"
"$mock_repo/scripts/kvm-base-image" ensure "$tmp/source.iso" "$tmp/kickstart.ks" molecule 10 default qemu:///system >"$tmp/reused" 2>&1
[[ $(tail -n 1 "$tmp/reused") == "$published_image" && -s "$published_image" ]]
grep -q 'Using cached OS base image' "$tmp/reused"
rm -f -- "$published_image"

# If the guest ignores poweroff, wrapper fallback destroy addresses only the
# UUID returned by kvm-vm, never the reusable domain name.
cat >"$mock_repo/scripts/kvm-vm" <<'SH'
#!/usr/bin/env bash
: >"$KVM_DISK_PATH"
printf '{"address":"192.0.2.2","user":"molecule","identity_file":"/tmp/key","uuid":"11111111-1111-4111-8111-111111111111"}\n'
SH
cat >"$bin/virsh" <<'SH'
#!/usr/bin/env bash
printf 'virsh %s\n' "$*" >>"$CALL_LOG"
case "$*" in
  *domblklist*) disk=$(find "$TEST_BASE_DIR" -name '*.building.qcow2' -print -quit); printf ' Type Device Target Source\n------------------------------------------------\n file disk vda %s\n' "$disk";;
  *domuuid*) printf '%s\n' "$DOMAIN_UUID";;
  *domstate*) printf 'running\n';;
  *) exit 0;;
esac
SH
printf '#!/usr/bin/env bash\nexit 0\n' >"$bin/sleep"
chmod +x "$mock_repo/scripts/kvm-vm" "$bin/virsh" "$bin/sleep"
# Keep this VM-free test immediate while exercising the wrapper's timeout
# fallback branch.
sed -i 's/deadline=$((SECONDS + 180))/deadline=$SECONDS/' "$mock_repo/scripts/kvm-base-image"
export DOMAIN_UUID=11111111-1111-4111-8111-111111111111
: >"$CALL_LOG"
"$mock_repo/scripts/kvm-base-image" ensure "$tmp/source.iso" "$tmp/kickstart.ks" molecule 10 default qemu:///system >"$tmp/forced" 2>&1
grep -qi 'forcing shutdown' "$tmp/forced"
grep -q '^virsh --connect qemu:///system destroy 11111111-1111-4111-8111-111111111111$' "$CALL_LOG"
! grep -Eq '^virsh .* destroy molecule-base-' "$CALL_LOG"
printf 'KVM base-image ownership checks passed.\n'
