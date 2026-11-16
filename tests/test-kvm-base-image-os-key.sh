#!/usr/bin/env bash
set -euo pipefail
script=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/kvm-base-image
check() {
  local expected=$1 source=$2 actual
  actual=$("$script" source-os-key "$source")
  [[ $actual == "$expected" ]] || { printf 'Expected %s for %s, got %s\n' "$expected" "$source" "$actual" >&2; exit 1; }
}
check fedora44 /images/Fedora-Server-dvd-x86_64-44-1.7.iso
check fedora43 Fedora-43.iso
check rocky10 rocky-10.iso
check rhel9 RHEL-9.iso
check fedora44 base-only:fedora44
printf 'KVM base-image OS key tests passed.\n'
