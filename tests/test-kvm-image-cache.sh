#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/environment/scripts" "$tmp/scenario" "$tmp/ephemeral"
export IDARSI_TEST_ENVIRONMENT="$tmp/environment"
export MOLECULE_FILE="$tmp/scenario/molecule.yml"
export MOLECULE_SCENARIO_DIRECTORY="$tmp/scenario"
export MOLECULE_EPHEMERAL_DIRECTORY="$tmp/ephemeral"
export MOLECULE_INSTANCE_CONFIG="$tmp/instance.yml"
export FIXTURE_ROOT="$tmp"
printf 'cached fixture\n' >"$tmp/cached.qcow2"
printf 'explicit fixture\n' >"$tmp/explicit.qcow2"
cat >"$tmp/environment/scripts/kvm-base-image" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >"$FIXTURE_ROOT/find-argv"
[[ $# == 5 && $1 == find && $2 == rocky9 && $3 == "$MOLECULE_SCENARIO_DIRECTORY/cache.ks" && $4 == molecule && $5 == 30 ]]
[[ ! -e "$FIXTURE_ROOT/cache-missing" ]] || exit 1
printf '%s\n' "$FIXTURE_ROOT/cached.qcow2"
SH
cat >"$tmp/environment/scripts/kvm-vm" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >"$FIXTURE_ROOT/vm-argv"
printf '%s\n' "$KVM_SSH_USER" >"$FIXTURE_ROOT/vm-user"
printf '{"instance":"fixture","address":"192.0.2.10","user":"%s"}\n' "$KVM_SSH_USER"
SH
chmod +x "$tmp/environment/scripts/"*

configure() {
  rm -f "$tmp/find-argv" "$tmp/vm-argv" "$tmp/vm-user" "$tmp/instance.yml"
  printf 'driver: {name: default}\nplatforms:\n  - name: fixture\n' >"$MOLECULE_FILE"
  cat >>"$MOLECULE_FILE"
}
run_create() {
  ansible-playbook "$root/molecule/kvm/create.yml" -i localhost, >"$tmp/output" 2>&1
}
reject() {
  if run_create; then cat "$tmp/output"; echo 'FAIL: accepted invalid input'; exit 1; fi
  grep -q "$1" "$tmp/output"
  [[ ! -e "$tmp/vm-argv" ]] # No create or rescue/destroy before all records resolve.
}
cache='    image_cache: {os_key: rocky9, kickstart: cache.ks, ssh_user: molecule, disk_size_gb: 30}'

# Empty image override selects cache identity, not the platform login.
configure <<EOF
    image_path: ""
    ssh_user: rocky
$cache
EOF
run_create || { cat "$tmp/output"; exit 1; }
[[ $(cat "$tmp/vm-user") == molecule ]]
grep -q 'user: molecule' "$tmp/instance.yml"
grep -qx 'create-image' "$tmp/vm-argv"
grep -qx "$tmp/cached.qcow2" "$tmp/vm-argv"
[[ -e "$tmp/find-argv" ]]

# Explicit nonempty path wins, preserving the explicit account; no cache query.
configure <<EOF
    image_path: "$tmp/explicit.qcow2"
    ssh_user: rocky
$cache
EOF
run_create || { cat "$tmp/output"; exit 1; }
[[ $(cat "$tmp/vm-user") == rocky && ! -e "$tmp/find-argv" ]]
grep -qx "$tmp/explicit.qcow2" "$tmp/vm-argv"

configure <<EOF
    image_path: "$tmp/missing.qcow2"
$cache
EOF
reject 'Explicit paths never fall back'
[[ ! -e "$tmp/find-argv" ]]

touch "$tmp/cache-missing"
configure <<EOF
$cache
EOF
reject 'no readable compatible cached image'
rm "$tmp/cache-missing"

configure <<EOF
    image_path: ""
EOF
reject 'empty image_path'

configure <<EOF
$cache
    install_source: installer.iso
EOF
reject 'no nonempty install_source'
[[ ! -e "$tmp/find-argv" ]]

configure <<EOF
    image_cache: {os_key: rocky9}
EOF
reject 'image_cache requires'

# Even a valid first platform must not provision when a later record fails.
configure <<EOF
    image_path: "$tmp/explicit.qcow2"
  - name: invalid-second
    image_path: ""
EOF
reject 'empty image_path'

# Existing ISO selection and account are unchanged.
configure <<EOF
    install_source: installer.iso
    kickstart: install.ks
    ssh_user: installer
EOF
run_create || { cat "$tmp/output"; exit 1; }
grep -qx create "$tmp/vm-argv"
[[ $(cat "$tmp/vm-user") == installer && ! -e "$tmp/find-argv" ]]

# Exercise the real find function against isolated, non-VM cache fixtures.
(
  source "$root/scripts/kvm-base-image"
  base_dir="$tmp/bases"
  mkdir "$base_dir"
  printf 'kickstart\n' >"$tmp/cache.ks"
  hash=$(sha256sum "$tmp/cache.ks" | cut -c1-16)
  prefix="$base_dir/rocky9-30-molecule-$hash"
  printf z >"$prefix-z-r1.qcow2"
  printf a >"$prefix-a-r1.qcow2"
  touch "$prefix-0-r1.qcow2"
  mkdir "$prefix-1-r1.qcow2"
  revision=1
  [[ $(find_base rocky9 "$tmp/cache.ks" molecule 30) == "$prefix-a-r1.qcow2" ]]
  if find_base rocky9 "$tmp/nonexistent.ks" molecule 30; then exit 1; fi
  if find_base rocky10 "$tmp/cache.ks" molecule 30; then exit 1; fi
)
echo 'PASS: read-only cache selection, precedence, account propagation, validation, and ISO compatibility'
