#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
profile=${1:-all}
environment=${2:-ansible-current}

if [[ $# -gt 2 ]]; then
  printf 'Usage: %s [podman|kvm|all] [ansible-min|ansible-current|ansible-next]\n' "$0" >&2
  exit 2
fi

"$repo_root/scripts/setup-host" install "$profile"
"$repo_root/scripts/setup-venv" "$environment"

printf '\nHost and Ansible tooling are ready. Start using them with:\n'
printf '  source %q\n' "$repo_root/.venv/$environment/bin/activate"
printf '  cd /path/to/ansible-role\n'
printf '  molecule test -s <scenario>\n'
