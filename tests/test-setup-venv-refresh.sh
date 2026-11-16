#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fixture="$tmp/shared environment"
mkdir -p "$fixture/scripts"
cp "$repo_root/scripts/setup-venv" "$fixture/scripts/"
begin='# BEGIN IDARSI FEDORA44 INSTALL SOURCE'
end='# END IDARSI FEDORA44 INSTALL SOURCE'

# No versions.yml, Python, pip, or Galaxy exists in this fixture. Only the
# refresh path may run; it must leave all other environment files alone.
for profile in ansible-min ansible-current ansible-next; do
  mkdir -p "$fixture/environments/$profile" "$fixture/.venv/$profile/bin"
  activate="$fixture/.venv/$profile/bin/activate"
  printf '%s\n' '# Existing activation' \
    'export IDARSI_ANSIBLE_ENVIRONMENT=keep-profile' \
    'export IDARSI_MOLECULE_COLLECTIONS_FILE="keep collections"' >"$tmp/original"
  printf '# No final newline' >>"$tmp/original"
  cp "$tmp/original" "$activate"
  chmod 0640 "$activate"
  printf 'untouched\n' >"$fixture/.venv/$profile/sentinel"
  bash "$fixture/scripts/setup-venv" --refresh-activation "$profile"
  head -c "$(wc -c <"$tmp/original")" "$activate" >"$tmp/prefix"
  cmp "$tmp/original" "$tmp/prefix"
  cp "$activate" "$tmp/once"
  bash "$fixture/scripts/setup-venv" --refresh-activation "$profile"
  cmp "$tmp/once" "$activate"
  [[ $(stat -c '%a' "$activate") == 640 ]]
  [[ $(cat "$fixture/.venv/$profile/sentinel") == untouched ]]
done

# Sourcing under strict mode handles missing/empty source data, literal shell
# syntax, whitespace and EOF without newline; nonempty overrides always win.
check_source() (
  unset IDARSI_TEST_KVM_INSTALL_SOURCE_FEDORA44
  source "$activate"
  [[ ${IDARSI_TEST_KVM_INSTALL_SOURCE_FEDORA44:-} == "$1" ]]
  [[ $IDARSI_ANSIBLE_ENVIRONMENT == keep-profile ]]
  [[ $IDARSI_MOLECULE_COLLECTIONS_FILE == 'keep collections' ]]
)
check_source ''
: >"$fixture/.kvm-install-source-fedora44"
check_source ''
value='  /ISO directory/Fedora 44.iso $(false) `false` \\  '
printf '%s' "$value" >"$fixture/.kvm-install-source-fedora44"
check_source "$value"
(
  export IDARSI_TEST_KVM_INSTALL_SOURCE_FEDORA44='explicit override'
  source "$activate"
  [[ $IDARSI_TEST_KVM_INSTALL_SOURCE_FEDORA44 == 'explicit override' ]]
)
(
  export IDARSI_TEST_KVM_INSTALL_SOURCE_FEDORA44=''
  source "$activate"
  [[ $IDARSI_TEST_KVM_INSTALL_SOURCE_FEDORA44 == "$value" ]]
  export -p | grep -q 'declare -x IDARSI_TEST_KVM_INSTALL_SOURCE_FEDORA44='
)

# Replacement preserves both sides byte-for-byte, including trailing newlines
# or their absence. The old block is replaced, not retained or duplicated.
for suffix in $'\n# suffix\n\n' $'\n# suffix without newline' ''; do
  printf '# prefix\n%s\nstale block\n%s%s' "$begin" "$end" "$suffix" >"$activate"
  bash "$fixture/scripts/setup-venv" --refresh-activation ansible-next
  content=''
  IFS= read -r -d '' content <"$activate" || :
  [[ ${content%%"$begin"*} == $'# prefix\n' ]]
  [[ ${content#*"$end"} == "$suffix" ]]
  [[ $content != *'stale block'* ]]
  cp "$activate" "$tmp/once"
  bash "$fixture/scripts/setup-venv" --refresh-activation ansible-next
  cmp "$tmp/once" "$activate"
done

expect_rejection() {
  if bash "$fixture/scripts/setup-venv" --refresh-activation ansible-next >"$tmp/error" 2>&1; then
    printf 'Expected refresh rejection\n' >&2
    exit 1
  fi
}
for malformed in "$begin" "$end" "$end"$'\n'"$begin" \
  "$begin"$'\n'"$begin"$'\n'"$end" \
  "$begin"$'\n'"$end"$'\n'"$begin"$'\n'"$end" \
  "prefix $begin" "$begin"$'\n'"$end suffix"; do
  printf '%s' "$malformed" >"$activate"
  cp "$activate" "$tmp/before"
  expect_rejection
  cmp "$tmp/before" "$activate"
done
rm "$activate"
expect_rejection
ln -s "$tmp/original" "$activate"
cp "$tmp/original" "$tmp/before"
expect_rejection
cmp "$tmp/before" "$tmp/original"
rm "$activate"
mkdir "$activate"
expect_rejection
for invalid in '' current ../ansible-current ansible-invalid; do
  if bash "$fixture/scripts/setup-venv" --refresh-activation "$invalid" >"$tmp/error" 2>&1; then
    printf 'Expected invalid profile rejection: %s\n' "$invalid" >&2
    exit 1
  fi
done
printf 'Activation refresh fixture tests passed.\n'
