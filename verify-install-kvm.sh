#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if [[ $# -ne 1 ]]; then
  printf 'Käyttö: %s /polku/Rocky-10-tai-Fedora-44.iso\n' "$0" >&2
  printf 'Avaa tmux-näkymän, jossa KVM-asennustesti ja virtuaalikoneen konsoli näkyvät rinnakkain.\n' >&2
  exit 2
fi

exec "$repo_root/scripts/kvm-smoke-tmux" ansible-current "$1"
