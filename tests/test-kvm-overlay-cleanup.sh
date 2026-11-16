#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/scenario/scripts" "$tmp/ephemeral" "$tmp/bases"
cp "$root/scripts/kvm-vm" "$tmp/scenario/scripts/kvm-vm"
cat >"$tmp/scenario/scripts/kvm-base-dir" <<EOF
#!/usr/bin/env bash
printf '%s\\n' '$tmp/bases'
EOF
chmod +x "$tmp/scenario/scripts/kvm-base-dir"
cat >"$tmp/scenario/scripts/kvm-base-image" <<EOF
#!/usr/bin/env bash
printf '%s\\n' '$tmp/source.qcow2'
EOF
chmod +x "$tmp/scenario/scripts/kvm-base-image"
cat >"$tmp/bin/virsh" <<'SH'
#!/usr/bin/env bash
case "$*" in *dominfo*) exit 1;; *net-info*) echo 'Active: yes';; esac
SH
cat >"$tmp/bin/qemu-img" <<'SH'
#!/usr/bin/env bash
if [[ $1 == info ]]; then echo '{"format":"qcow2"}'; exit 0; fi
printf 'create\n' >>"$CALL_LOG"
: >"${@: -1}"
if [[ ${OVERLAY_COLLISION:-0} == 1 ]]; then printf 'foreign overlay\n' >"$OVERLAY_PATH"; fi
[[ ${QEMU_FAIL:-0} != 1 ]]
SH
cat >"$tmp/bin/ssh-keygen" <<'SH'
#!/usr/bin/env bash
while (($#)); do if [[ $1 == -f ]]; then key=$2; shift 2; else shift; fi; done
echo private >"$key"; echo public >"$key.pub"
SH
cat >"$tmp/bin/virt-customize" <<'SH'
#!/usr/bin/env bash
exit 1
SH
for tool in virt-install; do printf '#!/usr/bin/env bash\nexit 90\n' >"$tmp/bin/$tool"; done
chmod +x "$tmp/bin"/*
cat >"$tmp/bin/ln" <<'SH'
#!/usr/bin/env bash
/usr/bin/ln "$@" || exit
if [[ ${SIGNAL_AFTER_LINK:-0} == 1 && ${*: -1} == "$OVERLAY_PATH" ]]; then
  kill -TERM "$PPID"
fi
SH
chmod +x "$tmp/bin/ln"
export PATH="$tmp/bin:$PATH" CALL_LOG="$tmp/calls" MOLECULE_EPHEMERAL_DIRECTORY="$tmp/ephemeral"
export KVM_LIBVIRT_URI=qemu:///session KVM_NETWORK=default KVM_INSTALL_TIMEOUT=60
source="$tmp/source.qcow2"; : >"$source"
iso="$tmp/installer.iso"; : >"$iso"
kickstart="$tmp/test.ks"; printf '@@SSH_USER@@ @@SSH_PUBLIC_KEY@@ @@NETWORK_CONFIGURATION@@\n' >"$kickstart"
run_image() {
  "$tmp/scenario/scripts/kvm-vm" create-image image-test "$source" >"$tmp/out" 2>&1
}

# A partial qemu-img output is owned and removed on command failure.
export QEMU_FAIL=1
if run_image; then echo 'Expected qemu-img failure' >&2; exit 1; fi
overlay="$tmp/bases/molecule-image-test-$(printf '%s' "$tmp/ephemeral" | sha256sum | cut -c1-8).qcow2"
[[ ! -e $overlay ]]
unset QEMU_FAIL

# A file appearing after preflight but before publication must remain untouched.
export OVERLAY_COLLISION=1 OVERLAY_PATH="$overlay"
if run_image; then echo 'Expected atomic overlay publication collision' >&2; exit 1; fi
[[ $(cat "$overlay") == 'foreign overlay' ]]
[[ -z $(find "$tmp/bases" -maxdepth 2 -name overlay.qcow2 -print -quit) ]]
rm -f "$overlay"
unset OVERLAY_COLLISION OVERLAY_PATH

# Customization failure occurs before virt-install but must still clean overlay.
if run_image; then echo 'Expected virt-customize failure' >&2; exit 1; fi
[[ ! -e $overlay ]]
! grep -q '^virt-install' "$tmp/calls" 2>/dev/null

# A dangling overlay symlink is rejected before qemu-img and left untouched.
ln -s "$tmp/nonexistent-target" "$overlay"
: >"$tmp/calls"
if run_image; then echo 'Expected dangling overlay rejection' >&2; exit 1; fi
grep -q 'overlay already exists' "$tmp/out"
[[ -L $overlay && $(readlink "$overlay") == "$tmp/nonexistent-target" ]]
[[ ! -s $tmp/calls ]]
rm -f "$overlay"

# The regular create (base-image) route also cleans a failed partial overlay.
export KVM_BASE_IMAGE_MODE=auto OVERLAY_COLLISION=1 OVERLAY_PATH="$overlay"
if "$tmp/scenario/scripts/kvm-vm" create image-test "$iso" "$kickstart" >"$tmp/out" 2>&1; then
  echo 'Expected auto-mode atomic overlay publication collision' >&2; exit 1
fi
[[ $(cat "$overlay") == 'foreign overlay' ]]
rm -f "$overlay"
unset OVERLAY_COLLISION OVERLAY_PATH

# Deliver TERM after link(2) publishes the overlay but before its ownership
# flag is set. The still-present staging hard link lets cleanup prove identity.
export SIGNAL_AFTER_LINK=1 OVERLAY_PATH="$overlay"
if run_image; then echo 'Expected signal during overlay publication' >&2; exit 1; fi
[[ ! -e $overlay ]]
[[ -z $(find "$tmp/bases" -maxdepth 2 -name overlay.qcow2 -print -quit) ]]
unset SIGNAL_AFTER_LINK OVERLAY_PATH
export QEMU_FAIL=1
if "$tmp/scenario/scripts/kvm-vm" create image-test "$iso" "$kickstart" >"$tmp/out" 2>&1; then
  echo 'Expected create-path qemu-img failure' >&2; exit 1
fi
[[ ! -e $overlay ]]
echo 'KVM overlay cleanup checks passed.'
