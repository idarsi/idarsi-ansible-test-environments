#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
state_user=${SUDO_USER:-${USER:-$(id -un)}}
state_user_home=$(getent passwd "$state_user" | cut -d: -f6)
state_user_home=${state_user_home:-$HOME}
state_home=${XDG_STATE_HOME:-$state_user_home/.local/state}
repo_id=$(printf '%s' "$repo_root" | sha256sum | cut -c1-16)
state_dir="$state_home/idarsi-ansible-test-environments/$repo_id"
remove_host_packages=false

if [[ $# -gt 1 || ( $# -eq 1 && $1 != --remove-host-packages ) ]]; then
  printf 'Usage: %s [--remove-host-packages]\n' "$0" >&2
  exit 2
fi
if [[ ${1:-} == --remove-host-packages ]]; then
  remove_host_packages=true
fi

if [[ -d "$repo_root/.venv" ]]; then
  rm -rf -- "$repo_root/.venv"
  printf 'Removed local Ansible virtual environments.\n'
else
  printf 'No local Ansible virtual environments found.\n'
fi

if [[ -f "$state_dir/libvirt-group-user" ]]; then
  read -r group_user <"$state_dir/libvirt-group-user"
  if [[ -n "$group_user" ]] && id -nG "$group_user" 2>/dev/null | tr ' ' '\n' | grep -qx libvirt; then
    if [[ $EUID -eq 0 ]]; then
      gpasswd -d "$group_user" libvirt
    else
      sudo gpasswd -d "$group_user" libvirt
    fi
    printf 'Removed %s from the libvirt group; log out and back in.\n' "$group_user"
  fi
  rm -f -- "$state_dir/libvirt-group-user"
fi

if [[ $remove_host_packages == true && -s "$state_dir/installed-packages" ]]; then
  mapfile -t packages <"$state_dir/installed-packages"
  installed_packages=()
  for package in "${packages[@]}"; do
    [[ $package =~ ^[A-Za-z0-9.+_-]+$ ]] || {
      printf 'Invalid package name in install state: %s\n' "$package" >&2
      exit 1
    }
    rpm -q "$package" >/dev/null 2>&1 && installed_packages+=("$package")
  done
  if [[ ${#installed_packages[@]} -gt 0 ]]; then
    if [[ $EUID -eq 0 ]]; then
      dnf remove -y "${installed_packages[@]}"
    else
      sudo dnf remove -y "${installed_packages[@]}"
    fi
    printf 'Removed host packages installed by this repository.\n'
  fi
  rm -f -- "$state_dir/installed-packages"
fi

if [[ -d "$state_dir" && -z "$(find "$state_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  rmdir "$state_dir"
  parent_state_dir=$(dirname "$state_dir")
  [[ ! -d "$parent_state_dir" || -n "$(find "$parent_state_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || rmdir "$parent_state_dir"
fi

if [[ $remove_host_packages == false && -f "$state_dir/installed-packages" ]]; then
  printf 'Host RPM packages remain installed. Remove only packages installed by this repository with:\n'
  printf '  %q --remove-host-packages\n' "$0"
fi
