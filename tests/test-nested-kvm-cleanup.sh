#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat >"$tmp/bin/virsh" <<'SH'
#!/usr/bin/env bash
[[ ${1:-} == --connect ]] && shift 2
case ${1:-} in
  dominfo)
    case $(cat "$DOMAIN_STATE") in
      present) exit 0 ;;
      absent) printf 'error: Domain not found: no domain with matching name\n' >&2; exit 1 ;;
      error) printf 'error: failed to connect to the hypervisor\n' >&2; exit 1 ;;
      *) exit 2 ;;
    esac
    ;;
  domuuid) printf '11111111-1111-4111-8111-111111111111\n' ;;
  domstate) printf 'running\n' ;;
  destroy) exit 0 ;;
  undefine)
    if [[ ${DESTROY_FAIL:-0} == 1 ]]; then exit 1; fi
    printf absent >"$DOMAIN_STATE"
    ;;
  *) printf 'Unexpected virsh command: %s\n' "$*" >&2; exit 1 ;;
esac
SH
chmod +x "$tmp/bin/virsh"
export PATH="$tmp/bin:$PATH" DOMAIN_STATE="$tmp/domain-state" TMPDIR="$tmp"
work="$tmp/idarsi-nested-kvm.abcdefgh"
mkdir "$work"
hash=$(printf '%s' "$work" | sha256sum | cut -c1-8)
domain="nested-kvm-$hash"
credentials="$work/credentials/molecule"
mkdir -p "$credentials"
disk="$work/$domain.qcow2"

# Invalid destinations must be rejected before destroy or removal.
mkdir -p "$tmp/unrelated/credentials/molecule"
touch "$tmp/unrelated/keep"
ln -s "$tmp/unrelated" "$tmp/link"
for bad_work in "$tmp" "$tmp/unrelated" "$tmp/link" "$tmp/idarsi-nested-kvm.abcdefgh/../unrelated"; do
  if "$root/scripts/cleanup-nested-kvm" "$domain" qemu:///system "$tmp/unrelated/keep" "$bad_work" >"$tmp/out" 2>&1; then
    echo "Expected invalid work path to fail: $bad_work" >&2
    exit 1
  fi
  [[ -f $tmp/unrelated/keep && -d $tmp/unrelated ]]
done
if "$root/scripts/cleanup-nested-kvm" "$domain" qemu:///system "$tmp" "$work" >"$tmp/out" 2>&1; then
  echo 'Expected mismatched disk path to fail.' >&2
  exit 1
fi
if "$root/scripts/cleanup-nested-kvm" nested-kvm-deadbeef qemu:///system "$disk" "$work" >"$tmp/out" 2>&1; then
  echo 'Expected mismatched domain hash to fail.' >&2
  exit 1
fi
[[ -f $tmp/unrelated/keep && -d $tmp/unrelated ]]

printf present >"$DOMAIN_STATE"
touch "$disk"
printf '11111111-1111-4111-8111-111111111111\n' >"$credentials/kvm-$domain.uuid"
if DESTROY_FAIL=1 "$root/scripts/cleanup-nested-kvm" "$domain" qemu:///system "$disk" "$work" >"$tmp/out" 2>&1; then
  echo 'Expected failed destroy to fail cleanup.' >&2
  exit 1
fi
[[ -f $disk && -d $work ]]
grep -q "preserving disk and work directory at $work" "$tmp/out" || { cat "$tmp/out"; exit 1; }

printf present >"$DOMAIN_STATE"
touch "$disk"
printf '11111111-1111-4111-8111-111111111111\n' >"$credentials/kvm-$domain.uuid"
if (printf error >"$DOMAIN_STATE"; "$root/scripts/cleanup-nested-kvm" "$domain" qemu:///system "$disk" "$work" >"$tmp/out" 2>&1); then
  echo 'Expected failed dominfo query to fail cleanup.' >&2
  exit 1
fi
[[ -f $disk && -d $work ]]
grep -Eq 'could not establish whether outer guest|Unable to query VM .* preserving its overlay' "$tmp/out" || { cat "$tmp/out"; exit 1; }

printf present >"$DOMAIN_STATE"
printf '11111111-1111-4111-8111-111111111111\n' >"$credentials/kvm-$domain.uuid"
"$root/scripts/cleanup-nested-kvm" "$domain" qemu:///system "$disk" "$work"
[[ ! -e $disk && ! -e $work ]]
[[ -f $tmp/unrelated/keep && -d $tmp/unrelated ]]

# The test's private credentials remain inaccessible through a QEMU-searchable
# parent; an explicit check catches accidental mode broadening.
mkdir -p "$tmp/access/credentials"
chmod 711 "$tmp/access"
chmod 700 "$tmp/access/credentials"
[[ $(stat -c %a "$tmp/access") == 711 && $(stat -c %a "$tmp/access/credentials") == 700 ]]
if [[ $EUID == 0 ]] && command -v runuser >/dev/null && id nobody >/dev/null 2>&1; then
  runuser -u nobody -- test -x "$tmp/access"
  if runuser -u nobody -- test -x "$tmp/access/credentials"; then
    echo 'Unprivileged QEMU-like user unexpectedly traversed private credentials.' >&2
    exit 1
  fi
fi
printf 'Nested KVM cleanup checks passed.\n'
