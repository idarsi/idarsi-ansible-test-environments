#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/environment/molecule/kvm" "$tmp/environment/scripts" "$tmp/ephemeral" "$tmp/scenario"
cp "$root/molecule/kvm/create.yml" "$tmp/environment/molecule/kvm/create.yml"
cat >"$tmp/environment/scripts/kvm-vm" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${KVM_SSH_USER:-molecule}" >"$MOLECULE_SCENARIO_DIRECTORY/captured-user"
printf '%s\n' '{"instance":"image-user-test","address":"192.0.2.10","user":"rocky"}'
SH
chmod +x "$tmp/environment/scripts/kvm-vm"
touch "$tmp/image.qcow2"
cat >"$tmp/scenario/molecule.yml" <<EOF
driver: {name: default}
platforms:
  - name: image-user-test
    image_path: "$tmp/image.qcow2"
    ssh_user: rocky
EOF

MOLECULE_FILE="$tmp/scenario/molecule.yml" \
MOLECULE_EPHEMERAL_DIRECTORY="$tmp/ephemeral" \
MOLECULE_SCENARIO_DIRECTORY="$tmp/scenario" \
MOLECULE_INSTANCE_CONFIG="$tmp/instance.yml" \
IDARSI_TEST_ENVIRONMENT="$tmp/environment" \
  ansible-playbook "$tmp/environment/molecule/kvm/create.yml" -i localhost, >/dev/null

[[ $(cat "$tmp/scenario/captured-user") == rocky ]]
echo "PASS: image platform ssh_user is forwarded to the KVM launcher"
