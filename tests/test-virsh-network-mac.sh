#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
helper=$repo_root/scripts/virsh-network-mac

valid=$(printf '%s\n' \
  ' Interface   Type      Source       Model    MAC' \
  '-------------------------------------------------------' \
  ' vnet1       network   idarsi-test  virtio   52:54:00:ab:cd:ef' | "$helper")
[[ $valid == 52:54:00:ab:cd:ef ]]

normalized=$(printf '%s\n' \
  ' Interface   Type      Source       Model    MAC' \
  ' vnet1       network   idarsi-test  virtio   52:54:00:AB:CD:EF' | "$helper")
[[ $normalized == 52:54:00:ab:cd:ef ]]

invalid=$(printf '%s\n' \
  ' Interface   Type      Source       Model    MAC' \
  ' vnet1       network   idarsi-test  virtio   not-a-mac' | "$helper")
[[ -z $invalid ]]

no_match=$(printf '%s\n' \
  ' Interface   Type      Source       Model    MAC' \
  ' vnet1       bridge    br0          virtio   52:54:00:ab:cd:ef' | "$helper")
[[ -z $no_match ]]

printf 'virsh network MAC parser checks passed.\n'
