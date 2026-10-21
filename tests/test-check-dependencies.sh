#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if VIRTUAL_ENV="$tmp/venv" "$repo_root/scripts/check-dependencies" >"$tmp/missing.out" 2>&1; then
  printf 'Expected missing installed collections to fail\n' >&2
  exit 1
fi
grep -q 'Rerun: install.sh <profile> venv' "$tmp/missing.out"

for item in 'ansible posix 2.2.2' 'containers podman 1.20.2'; do
  read -r namespace name version <<<"$item"
  mkdir -p "$tmp/venv/collections/ansible_collections/$namespace/$name"
  printf '{"collection_info":{"version":"%s"}}\n' "$version" > \
    "$tmp/venv/collections/ansible_collections/$namespace/$name/MANIFEST.json"
done
VIRTUAL_ENV="$tmp/venv" "$repo_root/scripts/check-dependencies" >/dev/null
