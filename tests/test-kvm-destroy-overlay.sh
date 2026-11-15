#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/scenario/scripts" "$tmp/ephemeral" "$tmp/bases"
cp "$root/scripts/kvm-vm" "$tmp/scenario/scripts/kvm-vm"
cat >"$tmp/scenario/scripts/kvm-base-dir" <<EOF
#!/usr/bin/env bash
printf '%s\\n' '$tmp/bases'
EOF
chmod +x "$tmp/scenario/scripts/kvm-base-dir"
cat >"$tmp/bin/virsh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$VIRSH_LOG"
case ${VIRSH_MODE:?}:$* in
  absent:*dominfo*) echo 'error: Domain not found' >&2; exit 1 ;;
  connection:*dominfo*) echo 'error: failed to connect to hypervisor' >&2; exit 1 ;;
  present:*dominfo*) echo 'Name: test' ;;
  present:*domuuid*) echo "${DOMAIN_UUID:-11111111-1111-4111-8111-111111111111}" ;;
  present:*domstate*)
    [[ ${QUERY_FAIL:-0} == 0 ]] || exit 1
    if [[ ${POST_QUERY_FAIL:-0} == 1 && -e $VIRSH_LOG.absent ]]; then exit 1; fi
    if [[ -e $VIRSH_LOG.absent ]]; then echo 'error: Domain not found' >&2; exit 1; fi
    if [[ -e $VIRSH_LOG.stopped ]]; then echo 'shut off'; else echo "${DOMAIN_STATE:-running}"; fi ;;
  present:*destroy*) [[ ${DESTROY_FAIL:-0} == 0 ]] || exit 1; touch "$VIRSH_LOG.stopped" ;;
  present:*undefine*) [[ ${UNDEFINE_FAIL:-0} == 0 ]] || exit 1; touch "$VIRSH_LOG.absent" ;;
  *) echo "Unexpected virsh command: $*" >&2; exit 99 ;;
esac
SH
chmod +x "$tmp/bin/virsh"
export PATH="$tmp/bin:$PATH" VIRSH_LOG="$tmp/virsh.log" MOLECULE_EPHEMERAL_DIRECTORY="$tmp/ephemeral"
domain="molecule-cleanup-$(printf '%s' "$MOLECULE_EPHEMERAL_DIRECTORY" | sha256sum | cut -c1-8)"
overlay="$tmp/bases/$domain.qcow2"
marker="$MOLECULE_EPHEMERAL_DIRECTORY/kvm-cleanup.uuid"
export DOMAIN="$domain"
run_destroy() { "$tmp/scenario/scripts/kvm-vm" destroy cleanup >"$tmp/out" 2>&1; }
fail_destroy() { if run_destroy; then echo 'Expected destroy failure' >&2; exit 1; fi; }

# Rescue cleanup is idempotent only when all owned resources are absent.
export VIRSH_MODE=absent
run_destroy
printf 'foreign overlay\n' >"$overlay"
fail_destroy
[[ -e $overlay ]]
rm "$overlay"
: >"$VIRSH_LOG"

# A same-name foreign domain cannot be mutated without its matching marker.
export VIRSH_MODE=present
fail_destroy
! grep -Eq ' (destroy|undefine) ' "$VIRSH_LOG"

# A valid ownership marker is not enough to claim a domain that is absent;
# preserve the marker and overlay so disappearance cannot erase evidence.
printf '11111111-1111-4111-8111-111111111111\n' >"$marker"
printf 'owned overlay\n' >"$overlay"
export VIRSH_MODE=absent
: >"$VIRSH_LOG"
fail_destroy
[[ -e $marker && -e $overlay ]]
! grep -Eq ' (destroy|undefine) ' "$VIRSH_LOG"
rm "$marker" "$overlay"

# Marker values and symlinks are validated before destructive operations.
export VIRSH_MODE=present
printf 'not-a-uuid\n' >"$marker"
fail_destroy
rm "$marker"
ln -s /dev/null "$marker"
fail_destroy
rm "$marker"

# A mismatching UUID preserves both marker and overlay without mutation.
printf 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n' >"$marker"
printf 'owned overlay\n' >"$overlay"
export DOMAIN_UUID=11111111-1111-4111-8111-111111111111
: >"$VIRSH_LOG"
fail_destroy
[[ -e $marker && -e $overlay ]]
! grep -Eq ' (destroy|undefine) ' "$VIRSH_LOG"

# Start and stop also refuse to mutate a same-name domain with a foreign UUID.
for action in start stop; do
  : >"$VIRSH_LOG"
  if "$tmp/scenario/scripts/kvm-vm" "$action" cleanup >"$tmp/out" 2>&1; then
    echo "Expected $action to reject UUID mismatch" >&2
    exit 1
  fi
  [[ -e $marker && -e $overlay ]]
  ! grep -Eq ' (start|destroy) ' "$VIRSH_LOG"
done

# Stop and undefine failures preserve ownership evidence and storage.
printf '11111111-1111-4111-8111-111111111111\n' >"$marker"
export DESTROY_FAIL=1
fail_destroy
[[ -e $marker && -e $overlay ]]
unset DESTROY_FAIL
export UNDEFINE_FAIL=1
fail_destroy
[[ -e $marker && -e $overlay ]]
unset UNDEFINE_FAIL
rm -f "$VIRSH_LOG.stopped"
export QUERY_FAIL=1
fail_destroy
[[ -e $marker && -e $overlay ]]
unset QUERY_FAIL

# Even a successful undefine is insufficient if absence cannot be verified.
export POST_QUERY_FAIL=1
fail_destroy
[[ -e $marker && -e $overlay ]]
unset POST_QUERY_FAIL
rm -f "$VIRSH_LOG.stopped" "$VIRSH_LOG.absent"

# Matching ownership removes exactly the role overlay only after undefine.
: >"$VIRSH_LOG"
export DOMAIN_STATE=paused
run_destroy
[[ ! -e $marker && ! -e $overlay ]]
grep -q ' destroy 11111111-1111-4111-8111-111111111111$' "$VIRSH_LOG"
grep -q ' undefine 11111111-1111-4111-8111-111111111111$' "$VIRSH_LOG"

echo 'KVM destroy ownership checks passed.'
