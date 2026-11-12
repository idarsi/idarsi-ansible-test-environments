#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir "$tmp/role"
if IDARSI_RUN_NESTED_KVM_TEST=1 "$root/scripts/test-nested-kvm" --role-path "$tmp/role" "$tmp/missing.iso" >"$tmp/out" 2>&1; then
  echo 'Expected invalid role path to fail.' >&2
  exit 1
fi
grep -q 'not an ansible-iac-roles-kvm role directory' "$tmp/out"
if IDARSI_RUN_NESTED_KVM_TEST=1 "$root/scripts/test-nested-kvm" --role-path >"$tmp/out" 2>&1; then
  echo 'Expected missing --role-path value to fail.' >&2
  exit 1
fi
grep -q -- '--role-path requires a directory' "$tmp/out"
if IDARSI_RUN_NESTED_KVM_TEST=1 env -u KVM_NESTED_ROLE_PATH -u IDARSI_KVM_ROLE_PATH \
  "$root/scripts/test-nested-kvm" "$tmp/missing.iso" >"$tmp/out" 2>&1; then
  echo 'Expected missing default role path to fail.' >&2
  exit 1
fi
grep -q 'provide the KVM role directory with --role-path or KVM_NESTED_ROLE_PATH' "$tmp/out"
mkdir -p "$tmp/env-role/tasks"
: >"$tmp/env-role/tasks/main.yml"
: >"$tmp/env-role/requirements.yml"
if IDARSI_RUN_NESTED_KVM_TEST=1 KVM_NESTED_ROLE_PATH="$tmp/env-role" \
  "$root/scripts/test-nested-kvm" "$tmp/missing.iso" >"$tmp/out" 2>&1; then
  echo 'Expected missing ISO to fail after accepting the environment role path.' >&2
  exit 1
fi
grep -q 'provide a readable Rocky 10 install ISO' "$tmp/out"
IDARSI_RUN_NESTED_KVM_TEST=0 "$root/scripts/test-nested-kvm" --help >/dev/null
"$root/scripts/render-nested-kvm-playbook" "$tmp/playbook.yml" inner-test
grep -Fq '    kvm_network: "idarsi-test"' "$tmp/playbook.yml"
grep -Fq '      kvm:' "$tmp/playbook.yml"
grep -Fq '          - name: "inner-test"' "$tmp/playbook.yml"
render_line=$(grep -nF 'render-nested-kvm-playbook' "$root/scripts/test-nested-kvm" | tail -n1 | cut -d: -f1)
mkdir_line=$(grep -nF 'dir=$(mktemp -d "$HOME/nested-kvm-playbook.XXXXXX")' "$root/scripts/test-nested-kvm" | cut -d: -f1)
transfer_line=$(grep -nF '"$work/playbook.yml" "molecule@$address:$playbook_dir/playbook.yml"' "$root/scripts/test-nested-kvm" | cut -d: -f1)
run_line=$(grep -nF 'ansible-playbook' "$root/scripts/test-nested-kvm" | tail -n1 | cut -d: -f1)
[[ -n $mkdir_line && $mkdir_line -lt $transfer_line && $render_line -lt $transfer_line && $transfer_line -lt $run_line ]] || {
  printf 'Expected a private playbook directory before transfer and execution of that exact path.\n' >&2
  exit 1
}
if grep -Fq '        network:' "$tmp/playbook.yml"; then
  echo 'The KVM network must be passed as a role variable, not blueprint data.' >&2
  exit 1
fi
printf 'Nested KVM CLI and playbook rendering checks passed.\n'
