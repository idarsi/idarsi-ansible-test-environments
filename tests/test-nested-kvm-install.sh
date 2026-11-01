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
    case "${1:-}:${2:-}" in
       virsh:--connect|systemctl:enable|usermod:-aG|dnf:install|sh:-c) exec "$@" ;;
      tee:*) exec tee "${@:2}" ;;
      mkdir:-p|chown:*|chmod:*|restorecon:*) exit 0 ;;
      *) printf 'Unexpected sudo command: %s\n' "$*" >&2; exit 1 ;;
    esac
    ;;
  virsh)
    # setup-host invokes virsh with --connect URI before the subcommand.
    [[ ${1:-} == --connect ]] && shift 2
     case "${1:-}:${2:-}" in
        net-info:default|net-info:idarsi-test) printf 'Active: yes\nAutostart: yes\n' ;;
        net-dumpxml:idarsi-test) cat "$EXPECTED_NETWORK" ;;
        net-autostart:default|net-autostart:idarsi-test|pool-autostart:idarsi-test-bases) exit 0 ;;
        net-start:default|net-start:idarsi-test|pool-start:idarsi-test-bases) exit 0 ;;
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

# The test path is deliberately unavailable to privileged callers. The
# remaining redirect-path scenarios require an unprivileged test process.
if [[ $EUID -eq 0 ]]; then
  config="$tmp/root-rejected.conf"
  if IDARSI_ENABLE_NESTED_KVM=1 IDARSI_TEST_NESTED_KVM_CONFIG="$config" "$setup" install kvm >"$tmp/out" 2>&1; then
    printf 'Expected root to be rejected from using the nested KVM test path.\n' >&2
    exit 1
  fi
  [[ ! -e $config ]]
  grep -q 'not allowed when running as root' "$tmp/out"
  printf 'Nested KVM root seam rejection check passed.\n'
  exit 0
fi

config="$tmp/enabled.conf"
run_install "$config" 1
[[ $(cat "$config") == "options $module nested=1" ]]

config="$tmp/conflict.conf"
printf 'options %s nested=0\nkeep-me\n' "$module" >"$config"
before=$(sha256sum "$config")
if IDARSI_ENABLE_NESTED_KVM=1 IDARSI_TEST_NESTED_KVM_CONFIG="$config" "$setup" install kvm >"$tmp/out" 2>&1; then
  printf 'Expected conflicting nested KVM config to fail installation.\n' >&2
  exit 1
fi
[[ $(sha256sum "$config") == "$before" ]]
printf 'options %s nested=0\nkeep-me\n' "$module" >"$tmp/expected-conflict.conf"
cmp -s "$config" "$tmp/expected-conflict.conf"
grep -q 'refusing to replace it' "$tmp/out"

config="$tmp/dangling.conf"
sentinel="$tmp/sentinel"
ln -s "$sentinel" "$config"
if IDARSI_ENABLE_NESTED_KVM=1 IDARSI_TEST_NESTED_KVM_CONFIG="$config" "$setup" install kvm >"$tmp/out" 2>&1; then
  printf 'Expected dangling nested KVM config symlink to fail installation.\n' >&2
  exit 1
fi
[[ -L $config ]]
[[ ! -e $sentinel ]]
grep -q 'is a symlink' "$tmp/out"

config="$tmp/opt-out.conf"
run_install "$config" 0
[[ ! -e "$config" ]]

outside_parent="/var/tmp/idarsi-nested-kvm-outside-parent"
config="$outside_parent/child/config.conf"
if IDARSI_ENABLE_NESTED_KVM=1 IDARSI_TEST_NESTED_KVM_CONFIG="$config" "$setup" install kvm >"$tmp/out" 2>&1; then
  printf 'Expected an outside nested KVM config path to fail installation.\n' >&2
  exit 1
fi
[[ ! -e "$outside_parent" ]]
grep -q 'Unsafe nested KVM test config path' "$tmp/out"

printf 'Nested KVM install checks passed.\n'
