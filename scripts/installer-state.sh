#!/usr/bin/env bash

# Sourced helper: compute the legacy installer state variables without writing
# state or creating directories. The caller supplies its already-resolved root.
idarsi_installer_state() {
  local repo_root=$1
  state_user=${SUDO_USER:-${USER:-$(id -un)}}
  state_user_home=$(getent passwd "$state_user" | cut -d: -f6)
  state_user_home=${state_user_home:-$HOME}
  state_home=${XDG_STATE_HOME:-$state_user_home/.local/state}
  repo_id=$(printf '%s' "$repo_root" | sha256sum | cut -c1-16)
  state_dir="$state_home/idarsi-ansible-test-environments/$repo_id"
}
