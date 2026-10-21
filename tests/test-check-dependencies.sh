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
mkdir -p "$tmp/bin"
cat > "$tmp/bin/ansible-config" <<'EOF'
#!/usr/bin/env bash
if [[ -n "${CONFIG_JSON:-}" ]]; then printf '%s\n' "$CONFIG_JSON"; else
  python - "$ANSIBLE_COLLECTIONS_PATH" <<'PYCONFIG'
import json, sys
print(json.dumps([{"name":"COLLECTIONS_PATHS", "value":sys.argv[1]}]))
PYCONFIG
fi
EOF
chmod +x "$tmp/bin/ansible-config"
export PATH="$tmp/bin:$PATH"
check_fails() {
  if VIRTUAL_ENV="$tmp/venv" ANSIBLE_COLLECTIONS_PATH="$1" "$repo_root/scripts/check-dependencies" >"$tmp/out" 2>&1; then
    printf 'Expected dependency check failure\n' >&2; exit 1
  fi
}

check_fails "$tmp/empty"
grep -q 'version: missing' "$tmp/out"
grep -q "$tmp/empty" "$tmp/out"
write_collection "$tmp/path-a" ansible posix 2.2.2
write_collection "$tmp/path-a" containers podman 1.20.2
VIRTUAL_ENV="$tmp/venv" ANSIBLE_COLLECTIONS_PATH="$tmp/path-a" "$repo_root/scripts/check-dependencies" >/dev/null

# Config JSON is a list of records; path strings and spaces must be preserved.
mkdir -p "$tmp/bin" "$tmp/path with spaces"
write_collection "$tmp/path with spaces" ansible posix 2.2.2
write_collection "$tmp/path with spaces" containers podman 1.20.2
cat > "$tmp/bin/ansible-config" <<'EOF'
#!/usr/bin/env bash
if [[ -n "${CONFIG_JSON:-}" ]]; then printf '%s\n' "$CONFIG_JSON"; else
  python - "$ANSIBLE_COLLECTIONS_PATH" <<'PYCONFIG'
import json, sys
print(json.dumps([{"name":"COLLECTIONS_PATHS", "value":sys.argv[1]}]))
PYCONFIG
fi
EOF
chmod +x "$tmp/bin/ansible-config"
CONFIG_JSON='[{"name":"COLLECTIONS_PATHS","value":"'"$tmp/path with spaces"'"}]' \
  PATH="$tmp/bin:$PATH" VIRTUAL_ENV="$tmp/venv" ANSIBLE_COLLECTIONS_PATH="$tmp/empty" ANSIBLE_COLLECTIONS_PATHS="$tmp/empty" \
  "$repo_root/scripts/check-dependencies" >/dev/null
CONFIG_JSON='[{"name":"COLLECTIONS_PATHS","value":["'"$tmp/path with spaces"'"]}]' \
  PATH="$tmp/bin:$PATH" VIRTUAL_ENV="$tmp/venv" ANSIBLE_COLLECTIONS_PATH="$tmp/empty" ANSIBLE_COLLECTIONS_PATHS="$tmp/empty" \
  "$repo_root/scripts/check-dependencies" >/dev/null
# Duplicate config records are rejected even when environment variables are set.
if CONFIG_JSON='[{"name":"COLLECTIONS_PATHS","value":"'"$tmp/path with spaces"'"},{"name":"COLLECTIONS_PATHS","value":[]}]' \
  VIRTUAL_ENV="$tmp/venv" ANSIBLE_COLLECTIONS_PATH="$tmp/path with spaces" ANSIBLE_COLLECTIONS_PATHS="$tmp/path with spaces" \
  "$repo_root/scripts/check-dependencies" >"$tmp/out" 2>&1; then
  printf 'Expected duplicate configuration records to fail\n' >&2; exit 1
fi
grep -q 'Duplicate COLLECTIONS_PATHS records' "$tmp/out"

# Parser errors must stay fatal rather than being hidden by mapfile or fallback.
mkdir -p "$tmp/venv/collections"
write_collection "$tmp/venv/collections" ansible posix 2.2.2
write_collection "$tmp/venv/collections" containers podman 1.20.2
for invalid_config in 'not-json' '[{"name":"COLLECTIONS_PATHS","value":[]},{"name":"COLLECTIONS_PATHS","value":[]}]'; do
  if CONFIG_JSON="$invalid_config" VIRTUAL_ENV="$tmp/venv" \
    ANSIBLE_COLLECTIONS_PATH="$tmp/path with spaces" \
    "$repo_root/scripts/check-dependencies" >"$tmp/out" 2>&1; then
    printf 'Expected invalid Ansible configuration to fail\n' >&2; exit 1
  fi
  if [[ "$invalid_config" == not-json ]]; then
    grep -q 'Invalid ansible-config JSON' "$tmp/out"
  else
    grep -q 'Duplicate COLLECTIONS_PATHS records' "$tmp/out"
  fi
done

# A failed ansible-config command is fatal even when the venv fallback is valid.
cat > "$tmp/bin/ansible-config" <<'EOF'
#!/usr/bin/env bash
exit 9
EOF
chmod +x "$tmp/bin/ansible-config"
if PATH="$tmp/bin:$PATH" VIRTUAL_ENV="$tmp/venv" \
  "$repo_root/scripts/check-dependencies" >"$tmp/out" 2>&1; then
  printf 'Expected ansible-config failure\n' >&2; exit 1
fi
grep -q 'Failed to read Ansible configuration' "$tmp/out"
cat > "$tmp/bin/ansible-config" <<'EOF'
#!/usr/bin/env bash
if [[ -n "${CONFIG_JSON:-}" ]]; then printf '%s\n' "$CONFIG_JSON"; else
  python - "$ANSIBLE_COLLECTIONS_PATH" <<'PYCONFIG'
import json, sys
print(json.dumps([{"name":"COLLECTIONS_PATHS", "value":sys.argv[1]}]))
PYCONFIG
fi
EOF
chmod +x "$tmp/bin/ansible-config"

# Config is authoritative when both path environment variables are set.
CONFIG_JSON='[{"name":"COLLECTIONS_PATHS","value":["'"$tmp/path with spaces"'"]}]' \
  VIRTUAL_ENV="$tmp/venv" ANSIBLE_COLLECTIONS_PATH="$tmp/empty" ANSIBLE_COLLECTIONS_PATHS="$tmp/empty" \
  "$repo_root/scripts/check-dependencies" >/dev/null

unset CONFIG_JSON
write_collection "$tmp/path-a" ansible posix 0.0.1
check_fails "$tmp/path-a"
grep -q 'mismatched' "$tmp/out"

# The first effective search path wins; a shadowed duplicate is rejected.
write_collection "$tmp/path-b" ansible posix 2.2.2
write_collection "$tmp/path-a" ansible posix 2.2.2
check_fails "$tmp/path-a:$tmp/path-b"
grep -q 'duplicate manifests' "$tmp/out"
grep -q 'Remove the later duplicate manifest(s)' "$tmp/out"

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
