#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

write_collection() {
  local root=$1 namespace=$2 name=$3 version=$4
  mkdir -p "$root/ansible_collections/$namespace/$name"
  printf '{"collection_info":{"version":"%s"}}\n' "$version" > \
    "$root/ansible_collections/$namespace/$name/MANIFEST.json"
}
check_fails() {
  if VIRTUAL_ENV="$tmp/venv" ANSIBLE_COLLECTIONS_PATH="$1" "$repo_root/scripts/check-dependencies" >"$tmp/out" 2>&1; then
    printf 'Expected dependency check failure\n' >&2; exit 1
  fi
}

check_fails "$tmp/empty"
grep -q 'found: missing' "$tmp/out"
write_collection "$tmp/path-a" ansible posix 2.2.2
write_collection "$tmp/path-a" containers podman 1.20.2
VIRTUAL_ENV="$tmp/venv" ANSIBLE_COLLECTIONS_PATH="$tmp/path-a" "$repo_root/scripts/check-dependencies" >/dev/null

write_collection "$tmp/path-a" ansible posix 0.0.1
check_fails "$tmp/path-a"
grep -q 'found: 0.0.1' "$tmp/out"

# The first effective search path wins; a shadowed duplicate is rejected.
write_collection "$tmp/path-b" ansible posix 2.2.2
write_collection "$tmp/path-a" ansible posix 2.2.2
check_fails "$tmp/path-a:$tmp/path-b"
grep -q 'installed more than once' "$tmp/out"

mkdir -p "$tmp/repo/scripts" "$tmp/repo/environments"
cp "$repo_root/scripts/check-dependencies" "$tmp/repo/scripts/"
cp "$repo_root/versions.yml" "$tmp/repo/versions.yml"
cp -R "$repo_root/environments/ansible-"* "$tmp/repo/environments/"
printf '  - name: "ansible.posix"\n    version: "2.2.2"\n' >> "$tmp/repo/environments/ansible-current/requirements.yml"
if VIRTUAL_ENV= ANSIBLE_COLLECTIONS_PATH= "$tmp/repo/scripts/check-dependencies" >"$tmp/out" 2>&1; then
  printf 'Expected duplicate manifest to fail\n' >&2; exit 1
fi
grep -q 'exactly one declaration' "$tmp/out"
sed -i '/  ansible_posix:/a\  ansible_posix: "2.2.2"' "$tmp/repo/versions.yml"
cp "$repo_root/environments/ansible-current/requirements.yml" "$tmp/repo/environments/ansible-current/requirements.yml"
if VIRTUAL_ENV= ANSIBLE_COLLECTIONS_PATH= "$tmp/repo/scripts/check-dependencies" >"$tmp/out" 2>&1; then
  printf 'Expected duplicate version pin to fail\n' >&2; exit 1
fi
grep -q 'exactly one declared pin' "$tmp/out"
printf 'Dependency checker tests passed.\n'
