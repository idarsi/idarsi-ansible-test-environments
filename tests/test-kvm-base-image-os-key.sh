#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key_script="$repo_root/scripts/kvm-base-image-os-key"

assert_key() {
  local source=$1 expected=$2 actual
  actual=$(bash "$key_script" "$source")
  [[ "$actual" == "$expected" ]] || {
    printf 'Expected OS key %s for %s, got %s\n' "$expected" "$source" "$actual" >&2
    return 1
  }
  local instance="base-${actual}-12345678"
  (( ${#instance} <= 40 )) || {
    printf 'Generated base guest name exceeds 40 characters: %s\n' "$instance" >&2
    return 1
  }
}

assert_key '/isos/Fedora-Server-dvd-x86_64-44-1.7.iso' fedora44
assert_key '/isos/Fedora-44-x86_64-dvd.iso' fedora44
assert_key '/isos/RHEL-9.4-x86_64-dvd.iso' rhel9
assert_key '/isos/Rocky-10.0-x86_64-dvd.iso' rocky10
assert_key 'base-only:fedora44' fedora44
assert_key '/isos/a-very-long-unrecognized-operating-system-install-image-name.iso' a-very-long-unrecognized-o

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for source in 'base-only:' 'base-only:../outside' 'base-only:fedora/44' 'base-only:fedora44/../../outside'; do
  if bash "$key_script" "$source" >"$tmp/parser.out" 2>"$tmp/parser.err"; then
    printf 'Expected invalid base-only key to fail: %s\n' "$source" >&2
    exit 1
  fi
  grep -q 'Invalid base-only OS key' "$tmp/parser.err"
done

# Invalid base-only input must fail before cache lookup/permission handling.
outside_image="$tmp/outside.qcow2"
: >"$outside_image"
chmod 0600 "$outside_image"
if "$repo_root/scripts/kvm-base-image" ensure 'base-only:../outside' "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" testuser 20 default qemu:///system >"$tmp/ensure.out" 2>&1; then
  printf 'Expected ensure to reject a traversal base-only key.\n' >&2
  exit 1
fi
grep -q 'Invalid base-only OS key' "$tmp/ensure.out"
[[ $(stat -c '%a' "$outside_image") == 600 ]]

# Cache lookup accepts safe keys, treats the cache directory literally, and
# rejects traversal before any glob can be expanded.
source "$repo_root/scripts/kvm-base-image"
base_dir="$tmp/cache[glob]"
mkdir -p "$base_dir"
kickstart_hash=$(sha256sum "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" | awk '{print $1}')
cached_image="$base_dir/fedora44-20-testuser-${kickstart_hash:0:16}-sourcehash-r1.qcow2"
printf 'cached image\n' >"$cached_image"
[[ $(find_base fedora44 "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" testuser 20) == "$cached_image" ]]
if find_base '../outside' "$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl" testuser 20 >"$tmp/find.out" 2>&1; then
  printf 'Expected cache lookup to reject a traversal OS key.\n' >&2
  exit 1
fi
grep -q 'Invalid OS key for KVM base-image lookup' "$tmp/find.out"
printf 'KVM base-image OS-key tests passed.\n'
