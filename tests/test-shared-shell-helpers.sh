#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

# Sourcing only defines functions: no stdout, state initialization, or writes.
state_dir=untouched
kvm_domain_name=untouched
source "$root/scripts/installer-state.sh" >"$tmp/source-output"
source "$root/scripts/kvm-domain.sh" >>"$tmp/source-output"
[[ ! -s "$tmp/source-output" && $state_dir == untouched && $kvm_domain_name == untouched ]]

# Fixed legacy SHA-256 prefixes catch newline addition, path normalization,
# word splitting and glob expansion. These paths need not exist.
paths=(
  '/repo'
  '/repo with spaces/[literal]*?$'
  '/repo/../repo//'
  $'/repo/line\nbreak'
  "/$(printf 'long-segment-%.0s' {1..30})"
)
hashes=(816fc349d3faebf8 dbdf332f77262131 e148ed074de740b0 76e77e2c03ea86e2 6138383956d19196)

# Only account lookups are mocked; neither real accounts nor host state change.
getent() {
  [[ $# == 2 && $1 == passwd ]]
  case "$2" in
    sudo-selected) printf 'sudo-selected:x:1001:1001::/home/Sudo User:/bin/bash\n' ;;
    user-selected) printf 'user-selected:x:1002:1002::/home/user-selected:/bin/bash\n' ;;
    id-selected) printf 'id-selected:x:1003:1003::/home/id-selected:/bin/bash\n' ;;
    no-home) printf 'no-home:x:1004:1004:::/bin/bash\n' ;;
    missing) : ;; # A successful empty lookup retains the legacy HOME fallback.
    *) return 1 ;;
  esac
}
id() {
  [[ $# == 1 && $1 == -un ]]
  printf 'id-selected\n'
}

check_state() {
  local expected_user=$1 expected_home=$2 expected_state_home=$3 index
  for index in "${!paths[@]}"; do
    idarsi_installer_state "${paths[index]}" >"$tmp/output"
    [[ ! -s "$tmp/output" ]]
    [[ $state_user == "$expected_user" && $state_user_home == "$expected_home" ]]
    [[ $state_home == "$expected_state_home" && $repo_id == "${hashes[index]}" ]]
    [[ $state_dir == "$expected_state_home/idarsi-ansible-test-environments/${hashes[index]}" ]]
    [[ ! -e $state_dir ]]
  done
}

(
  HOME="$tmp/fallback home"
  unset XDG_STATE_HOME
  SUDO_USER=sudo-selected USER=user-selected
  check_state sudo-selected '/home/Sudo User' '/home/Sudo User/.local/state'
  SUDO_USER=
  check_state user-selected /home/user-selected /home/user-selected/.local/state
  unset SUDO_USER USER
  check_state id-selected /home/id-selected /home/id-selected/.local/state
  SUDO_USER= USER=
  check_state id-selected /home/id-selected /home/id-selected/.local/state
  USER=no-home
  check_state no-home "$HOME" "$HOME/.local/state"
  USER=missing
  check_state missing "$HOME" "$HOME/.local/state"
  XDG_STATE_HOME=
  check_state missing "$HOME" "$HOME/.local/state"
  XDG_STATE_HOME="$tmp/xdg state/[literal]*?"
  check_state missing "$HOME" "$XDG_STATE_HOME"
  USER=user-selected XDG_STATE_HOME='relative state//'
  check_state user-selected /home/user-selected "$XDG_STATE_HOME"
)

for index in "${!paths[@]}"; do
  for instance in vm base-rocky10-12345678 "$(printf 'x%.0s' {1..40})" "$(printf 'x%.0s' {1..80})"; do
    idarsi_kvm_domain "$instance" "${paths[index]}" >"$tmp/output"
    expected_hash=${hashes[index]:0:8}
    expected_name="molecule-${instance}-${expected_hash}"
    expected_name=${expected_name:0:63}
    [[ ! -s "$tmp/output" && $kvm_domain_hash == "$expected_hash" ]]
    [[ $kvm_domain_name == "$expected_name" ]]
    # The base-image caller and launcher must compute exactly the same name.
    if [[ $instance == base-rocky10-12345678 ]]; then
      [[ $kvm_domain_name == "molecule-base-rocky10-12345678-${expected_hash}" ]]
    fi
  done
done

# No helper created anything besides the test's own redirected output files.
[[ $(find "$tmp" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort) == $'output\nsource-output' ]]
printf 'Shared shell helper checks passed.\n'
