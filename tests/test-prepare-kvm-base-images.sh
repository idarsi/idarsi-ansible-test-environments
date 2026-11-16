#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/repo/scripts" "$tmp/bin" "$tmp/bases"
cp "$root/scripts/prepare-kvm-base-images" "$tmp/repo/scripts/"
export TEST_BASE_DIR="$tmp/bases" TEST_CALL_LOG="$tmp/calls"
cat >"$tmp/repo/scripts/kvm-base-dir" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$TEST_BASE_DIR"
SH
cat >"$tmp/repo/scripts/kvm-base-image" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$TEST_CALL_LOG"
SH
# Never perform host permission or privilege operations, even when run as root.
for command in sudo chown chmod restorecon find; do
  printf '#!/usr/bin/env bash\nexit 0\n' >"$tmp/bin/$command"
done
chmod +x "$tmp/bin/"* "$tmp/repo/scripts/"*
for entry in '.kvm-install-source rocky9' '.kvm-install-source-rocky10 rocky10' \
  '.kvm-install-source-rhel9 rhel9' '.kvm-install-source-rhel10 rhel10' \
  '.kvm-install-source-fedora44 fedora44'; do
  read -r state key <<<"$entry"
  printf '/fixture/%s.iso\n' "$key" >"$tmp/repo/$state"
done
PATH="$tmp/bin:$PATH" KVM_BASE_DISK_SIZE_GB=30 KVM_NETWORK=idarsi-test \
  KVM_LIBVIRT_URI=qemu:///system bash "$tmp/repo/scripts/prepare-kvm-base-images" >"$tmp/output"
[[ $(wc -l <"$TEST_CALL_LOG") == 5 ]]
for key in rocky9 rocky10 rhel9 rhel10 fedora44; do
  template=rocky9-10.ks.tmpl
  [[ $key != fedora44 ]] || template=fedora-44.ks.tmpl
  grep -Fxq "ensure /fixture/$key.iso $tmp/repo/examples/molecule-kvm/$template molecule 30 idarsi-test qemu:///system" "$TEST_CALL_LOG"
  grep -Fq "Preparing reusable $key KVM base image." "$tmp/output"
done
printf 'KVM base preparation mappings passed (mocked, no host changes).\n'
