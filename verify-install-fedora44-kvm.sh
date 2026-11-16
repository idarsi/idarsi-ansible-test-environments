#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if [[ $# -ne 1 ]]; then
  printf 'Usage: %s /path/Fedora-44.iso\n' "$0" >&2
  printf 'Starts Fedora 44 KVM installation with Molecule and its serial console in tmux.\n' >&2
  exit 2
fi

exec "$repo_root/scripts/kvm-smoke-tmux" ansible-current "$1" fedora44
