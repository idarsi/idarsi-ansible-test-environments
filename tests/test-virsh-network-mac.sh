#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
helper=$repo_root/scripts/virsh-network-mac
fixture=$(cat <<'EOF'
 Interface   Type      Source       Model    MAC
-------------------------------------------------------
 vnet7       network   default      virtio   52:54:00:ab:cd:ef
EOF
)
[[ $(printf '%s\n' "$fixture" | "$helper") == 52:54:00:ab:cd:ef ]]

result=$(printf '%s\n' \
  ' Interface   Type      Source       Model    MAC' \
  '-------------------------------------------------------' \
  ' vnet0       network   default      virtio   not-a-mac' | "$helper")
[[ -z $result ]]
result=$(printf '%s\n' \
  ' Interface   Type      Source       Model    MAC' \
  '-------------------------------------------------------' | "$helper")
[[ -z $result ]]
printf 'virsh network MAC parser checks passed.\n'
