#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
setup="$root/scripts/setup-host"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mock_bin="$tmp/bin"
mkdir -p "$mock_bin"

# Keep the install path self-contained: these commands report ready state and
# make any attempted host operation a no-op.
for command in rpm systemctl id virsh dnf usermod sudo; do
  cat >"$mock_bin/$command" <<'SH'
#!/usr/bin/env bash
case "$(basename "$0")" in
  sudo)
    exec "$@"
    ;;
  virsh)
    # setup-host invokes virsh with --connect URI before the subcommand.
    [[ ${1:-} == --connect ]] && shift 2
     case "${1:-}:${2:-}" in
       net-info:default|net-info:idarsi-test) printf 'Active: yes\nAutostart: yes\n' ;;
       net-dumpxml:idarsi-test) cat "$EXPECTED_NETWORK" ;;
       pool-info:idarsi-test-bases) printf 'State: running\nAutostart: yes\n' ;;
       pool-dumpxml:idarsi-test-bases) printf '<pool type="dir"><name>idarsi-test-bases</name><target><path>%s</path></target></pool>\n' "$EXPECTED_TARGET" ;;
      *) printf 'Unexpected virsh command: %s\n' "$*" >&2; exit 1 ;;
    esac ;;
  id) [[ ${1:-} == -nG ]] && printf 'users libvirt\n' ;;
  *) exit 0 ;;
esac
SH
  chmod +x "$mock_bin/$command"
done

export PATH="$mock_bin:$PATH"
export EXPECTED_NETWORK="$root/config/idarsi-test-network.xml"
export EXPECTED_TARGET=$("$root/scripts/kvm-base-dir")
export TMPDIR="$tmp"

# Select the module matching the real CPU vendor; setup-host detects the same
# vendor from /proc/cpuinfo. Unsupported vendors make opt-in a documented skip.
vendor=$(awk -F: '/vendor_id/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' /proc/cpuinfo)
case "$vendor" in
  GenuineIntel) module=kvm_intel ;;
  AuthenticAMD) module=kvm_amd ;;
  *) printf 'Nested KVM install tests skipped: unsupported CPU vendor %s\n' "${vendor:-unknown}"; exit 0 ;;
esac

run_install() {
  local config=$1 enabled=$2
  if ! IDARSI_ENABLE_NESTED_KVM="$enabled" IDARSI_TEST_NESTED_KVM_CONFIG="$config" "$setup" install kvm >"$tmp/out" 2>&1; then
    cat "$tmp/out" >&2
    return 1
  fi
}

config="$tmp/enabled.conf"
run_install "$config" 1
[[ $(cat "$config") == "options $module nested=1" ]]

config="$tmp/conflict.conf"
printf 'options %s nested=0\nkeep-me\n' "$module" >"$config"
before=$(sha256sum "$config")
run_install "$config" 1
[[ $(sha256sum "$config") == "$before" ]]
grep -q 'refusing to replace it' "$tmp/out"

config="$tmp/opt-out.conf"
run_install "$config" 0
[[ ! -e "$config" ]]

printf 'Nested KVM install checks passed.\n'
