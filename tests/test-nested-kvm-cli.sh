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
grep -Fq '            hostname: "nested-role-integration.example.test"' "$tmp/playbook.yml"
grep -Fq '                address: "192.168.250.210/24"' "$tmp/playbook.yml"
grep -Fq '                gateway: "192.168.250.1"' "$tmp/playbook.yml"
grep -Fq '                nameservers: ["192.168.250.1"]' "$tmp/playbook.yml"
"$root/scripts/render-nested-kvm-playbook" "$tmp/image-playbook.yml" image-test '/var/lib/libvirt/images/inner-test.qcow2'
grep -Fq '          - name: "image-test"' "$tmp/image-playbook.yml"
grep -Fq '              type: "image"' "$tmp/image-playbook.yml"
grep -Fq '              path: "/var/lib/libvirt/images/inner-test.qcow2"' "$tmp/image-playbook.yml"
! grep -Fq 'kickstart:' "$tmp/image-playbook.yml"
! grep -Eq '^            network:' "$tmp/image-playbook.yml"
grep -Eq '^            network:' "$tmp/playbook.yml"
grep -Fq '                address: "192.168.250.210/24"' "$tmp/playbook.yml"
if "$root/scripts/render-nested-kvm-playbook" "$tmp/bad-image.yml" image-test 'relative path.qcow2' >"$tmp/out" 2>&1; then
  echo 'Expected relative image path to be rejected.' >&2
  exit 1
fi
grep -Fq 'IMAGE_PATH must be an absolute path ending in .qcow2' "$tmp/out"
"$root/scripts/render-nested-kvm-playbook" "$tmp/quoted-image.yml" image-test '/var/lib/libvirt/images/a "quoted" path.qcow2'
grep -Fq 'path: "/var/lib/libvirt/images/a \"quoted\" path.qcow2"' "$tmp/quoted-image.yml"
cat >"$tmp/recap-bad.log" <<'EOF'
changed=0 is just a message, not a recap
PLAY RECAP *********************************************************************
localhost : ok=2 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
EOF
if "$root/scripts/check-nested-kvm-idempotence" "$tmp/recap-bad.log" >"$tmp/out" 2>&1; then
  echo 'Expected a non-idempotent localhost recap to fail despite a fake changed=0 message.' >&2
  exit 1
fi
cat >"$tmp/recap-good.log" <<'EOF'
PLAY RECAP *********************************************************************
localhost : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
EOF
"$root/scripts/check-nested-kvm-idempotence" "$tmp/recap-good.log"
grep -Fq "hostnamectl --static" "$root/scripts/test-nested-kvm"
grep -Fq 'virsh domblklist --details' "$root/scripts/test-nested-kvm"
grep -Fq 'clone_ipv4' "$root/scripts/test-nested-kvm"
grep -Fq 'ipaddress.IPv4Address' "$root/scripts/test-nested-kvm"
grep -Fq 'clone_deadline=' "$root/scripts/test-nested-kvm"
wait_definition_line=$(grep -nF 'wait_guest_ssh()' "$root/scripts/test-nested-kvm" | head -n1 | cut -d: -f1)
wait_first_call_line=$(grep -nE 'wait_guest_ssh "' "$root/scripts/test-nested-kvm" | head -n1 | cut -d: -f1)
[[ -n $wait_definition_line && -n $wait_first_call_line && $wait_definition_line -lt $wait_first_call_line ]] || {
  printf 'Expected wait_guest_ssh to be defined before every invocation.\n' >&2
  exit 1
}
grep -Fq 'nmcli connection modify' "$root/scripts/test-nested-kvm"
grep -Fq 'source_boot_id=$(ssh' "$root/scripts/test-nested-kvm"
grep -Fq 'source_new_boot_id == "$source_boot_id"' "$root/scripts/test-nested-kvm"
grep -Fq 'reboot_status == 255' "$root/scripts/test-nested-kvm"
if grep -F "sudo systemctl reboot'\" >/dev/null 2>&1 || true" "$root/scripts/test-nested-kvm"; then
  echo 'Reboot command must not mask failed reboot/SSH status.' >&2
  exit 1
fi
grep -Fq 'source_state' "$root/scripts/test-nested-kvm"
render_line=$(grep -nF 'render-nested-kvm-playbook' "$root/scripts/test-nested-kvm" | head -n1 | cut -d: -f1)
mkdir_line=$(grep -nF 'dir=$(mktemp -d "$HOME/nested-kvm-playbook.XXXXXX")' "$root/scripts/test-nested-kvm" | cut -d: -f1)
transfer_line=$(grep -nF '"$work/playbook.yml" "molecule@$address:$playbook_dir/playbook.yml"' "$root/scripts/test-nested-kvm" | cut -d: -f1)
run_line=$(grep -nF 'ansible-playbook' "$root/scripts/test-nested-kvm" | tail -n1 | cut -d: -f1)
[[ -n $mkdir_line && $mkdir_line -lt $transfer_line && $render_line -lt $transfer_line && $transfer_line -lt $run_line ]] || {
  printf 'Expected a private playbook directory before transfer and execution of that exact path.\n' >&2
  exit 1
}
if grep -Eq '^        network:' "$tmp/playbook.yml"; then
  echo 'The KVM network must be passed as a role variable, not blueprint data.' >&2
  exit 1
fi
printf 'Nested KVM CLI and playbook rendering checks passed.\n'
