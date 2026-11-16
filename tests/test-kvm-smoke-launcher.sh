#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/fixture/scripts" "$tmp/fixture/.venv/ansible-current/bin" "$tmp/logs"
# Exercise the unmodified launcher with fake dependencies outside the checkout.
cp "$repo_root/scripts/kvm-smoke-tmux" "$tmp/fixture/scripts/kvm-smoke-tmux"
launcher="$tmp/fixture/scripts/kvm-smoke-tmux"
cat >"$tmp/fixture/.venv/ansible-current/bin/molecule" <<'EOF'
#!/usr/bin/env bash
printf 'The mapping test must not execute Molecule.\n' >&2
exit 1
EOF
chmod +x "$tmp/fixture/.venv/ansible-current/bin/molecule"
touch "$tmp/Rocky-10.iso" "$tmp/Fedora-Server-dvd-x86_64-44-1.2.iso"
cat >"$tmp/bin/virsh" <<'EOF'
#!/usr/bin/env bash
if [[ $* == *' list --all --name' ]]; then exit 0; fi
if [[ $* == *'dominfo'* ]]; then exit 0; fi
exit 0
EOF
cat >"$tmp/bin/tmux" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >>"$TMUX_CAPTURE"
EOF
chmod +x "$tmp/bin/virsh" "$tmp/bin/tmux"
export PATH="$tmp/bin:$PATH" TMUX_CAPTURE="$tmp/tmux.log"
export TMPDIR="$tmp/logs"
export IDARSI_KVM_SMOKE_SETUP_HOST=/bin/true
for platform in rocky10 fedora44; do
  : >"$TMUX_CAPTURE"
  if [[ $platform == rocky10 ]]; then iso="$tmp/Rocky-10.iso"; else iso="$tmp/Fedora-Server-dvd-x86_64-44-1.2.iso"; fi
  "$launcher" ansible-current "$iso" "$platform" >/dev/null
  command=$(grep '^export PATH=' "$TMUX_CAPTURE" | head -n1)
  if [[ $platform == rocky10 ]]; then
    [[ $command == *"IDARSI_TEST_KVM_INSTALL_SOURCE_ROCKY10=$(printf '%q' "$(realpath "$iso")")"* && $command == *'-s kvm-smoke '* && $command != *'KVM_BASE_IMAGE_MODE=off'* ]]
  else
    [[ $command == *"IDARSI_TEST_KVM_INSTALL_SOURCE_FEDORA44=$(printf '%q' "$(realpath "$iso")")"* && $command == *'-s kvm-smoke-fedora44 '* && $command == *'KVM_BASE_IMAGE_MODE=off'* ]]
  fi
done
touch "$tmp/not-a-fedora.iso"
: >"$TMUX_CAPTURE"
if "$launcher" ansible-current "$tmp/not-a-fedora.iso" fedora44 >/dev/null 2>&1; then
  printf 'Invalid Fedora ISO basename was accepted.\n' >&2
  exit 1
fi
[[ ! -s "$TMUX_CAPTURE" ]]
rm "$tmp/fixture/.venv/ansible-current/bin/molecule"
if "$launcher" ansible-current "$tmp/Rocky-10.iso" rocky10 >"$tmp/missing.log" 2>&1; then
  printf 'Missing Molecule executable was accepted.\n' >&2
  exit 1
fi
grep -q 'Molecule environment not found:' "$tmp/missing.log"
[[ ! -s "$TMUX_CAPTURE" ]]
printf 'KVM smoke launcher mapping tests passed.\n'
