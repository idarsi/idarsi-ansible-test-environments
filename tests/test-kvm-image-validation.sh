#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/ephemeral"
for tool in virt-install ssh-keygen timeout; do printf '#!/bin/sh\nexit 99\n' >"$tmp/bin/$tool"; chmod +x "$tmp/bin/$tool"; done
cat >"$tmp/bin/qemu-img" <<'SH'
#!/bin/sh
if [[ ${1:-} == info ]]; then printf '{"format":"raw"}\n'; exit 0; fi
exit 99
SH
chmod +x "$tmp/bin/qemu-img"
source="$tmp/source.qcow2"
printf 'source bytes' >"$source"
before=$(sha256sum "$source")
if PATH="$tmp/bin:$PATH" MOLECULE_EPHEMERAL_DIRECTORY="$tmp/ephemeral" \
  "$root/scripts/kvm-vm" create-image image-test "$source" >"$tmp/out" 2>&1; then
  echo "Expected raw image rejection" >&2; exit 1
fi
grep -q 'Image source must be qcow2' "$tmp/out"
[[ $(sha256sum "$source") == "$before" ]]
[[ ! -e "$tmp/ephemeral/kvm_ed25519" ]]
if command -v ansible-playbook >/dev/null; then
  cat >"$tmp/molecule.yml" <<EOF
driver: {name: default}
platforms:
  - name: bad-input
    image_path: "$source"
    install_source: "$source"
    kickstart: fake.ks
EOF
  if MOLECULE_FILE="$tmp/molecule.yml" IDARSI_TEST_ENVIRONMENT="$root" \
    MOLECULE_EPHEMERAL_DIRECTORY="$tmp/ephemeral" MOLECULE_SCENARIO_DIRECTORY="$tmp" \
    MOLECULE_INSTANCE_CONFIG="$tmp/instance.json" ansible-playbook \
    "$root/molecule/kvm/create.yml" >"$tmp/playbook.out" 2>&1; then
    echo "Expected conflicting image/ISO input rejection" >&2; exit 1
  fi
  grep -q 'must use either image_path or install_source' "$tmp/playbook.out"
  [[ ! -e "$tmp/instance.json" && $(sha256sum "$source") == "$before" ]]
  echo "PASS: launcher and create playbook reject bad inputs before mutation; source unchanged"
else
  echo "PASS: launcher rejects invalid image before mutation; source unchanged (ansible-playbook unavailable; create-playbook test skipped)"
fi
