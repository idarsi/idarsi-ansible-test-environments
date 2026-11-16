#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=${TEST_TMPDIR:-$(mktemp -d)}
trap 'rm -rf "$tmp"' EXIT
mock_bin="$tmp/bin"
mkdir -p "$mock_bin"
cat >"$mock_bin/sudo" <<'SH'
#!/usr/bin/env bash
printf 'Unexpected sudo invocation: %s\n' "$*" >&2
exit 99
SH
cat >"$mock_bin/stat" <<'SH'
#!/usr/bin/env bash
if [[ ${*: -1} == "$MOCK_FOREIGN_IMAGE" ]]; then
  printf '%s\n' "$(( $(id -u) + 1 ))"
else
  exec /usr/bin/stat "$@"
fi
SH
chmod +x "$mock_bin/sudo" "$mock_bin/stat"

run_checks() {
  local private_image="$tmp/private.qcow2" foreign_image="$tmp/foreign.qcow2"
  : >"$private_image"
  : >"$foreign_image"
  export PATH="$mock_bin:$PATH" MOCK_FOREIGN_IMAGE="$foreign_image"

  if "$repo_root/scripts/kvm-base-image" prepare-sysprep "$private_image" >"$tmp/out" 2>&1; then
    printf 'Expected arbitrary-path preparation CLI action to be unavailable.\n' >&2
    return 1
  fi
  [[ $(/usr/bin/stat -c '%a' "$private_image") == 644 ]]

  # Sourcing exposes the preparation helpers to VM-free tests without
  # providing a CLI that accepts arbitrary paths.
  source "$repo_root/scripts/kvm-base-image"
  prepare_image_for_sysprep "$private_image"
  [[ $(/usr/bin/stat -c '%a' "$private_image") == 600 ]]
  prepare_image_for_libvirt "$private_image"
  [[ $(/usr/bin/stat -c '%a' "$private_image") == 644 ]]

  if prepare_image_for_sysprep "$foreign_image" >"$tmp/out" 2>&1; then
    printf 'Expected foreign-owned image preparation to fail.\n' >&2
    return 1
  fi
  grep -q 'not owned by the current user' "$tmp/out"
  [[ $(/usr/bin/stat -c '%a' "$foreign_image") == 644 ]]
}

if [[ $EUID -eq 0 ]]; then
  command -v runuser >/dev/null || { printf 'runuser is required for root-run sealing tests.\n' >&2; exit 1; }
  chmod 0777 "$tmp"
  runuser -u nobody -- env TEST_TMPDIR="$tmp" TEST_AS_UNPRIVILEGED=1 bash "$0"
  exit
else
  run_checks
fi

printf 'KVM base-image sealing checks passed.\n'
