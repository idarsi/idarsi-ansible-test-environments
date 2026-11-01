#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/modules/kvm_intel/parameters" "$tmp/modules/kvm_amd/parameters"
printf 'flags : fpu vmx\n' > "$tmp/intel"
printf '1\n' > "$tmp/modules/kvm_intel/parameters/nested"
"$root/scripts/check-nested-kvm-capability" "$tmp/intel" "$tmp/modules" | grep -q '^PASS: Intel'
for ((line = 0; line < 10000; line++)); do
  printf 'flags : fpu svm processor%d\n' "$line" >> "$tmp/amd"
done
printf '1\n' > "$tmp/modules/kvm_amd/parameters/nested"
"$root/scripts/check-nested-kvm-capability" "$tmp/amd" "$tmp/modules" | grep -q '^PASS: AMD'
printf '0\n' > "$tmp/modules/kvm_amd/parameters/nested"
if "$root/scripts/check-nested-kvm-capability" "$tmp/amd" "$tmp/modules" > "$tmp/output"; then exit 1; else [[ $? == 77 ]]; fi
grep -q 'nested virtualization is disabled' "$tmp/output"
printf 'flags : fpu\n' > "$tmp/unsupported"
if "$root/scripts/check-nested-kvm-capability" "$tmp/unsupported" "$tmp/modules" > "$tmp/output"; then exit 1; else [[ $? == 77 ]]; fi
grep -q 'neither Intel VMX nor AMD SVM' "$tmp/output"
printf 'Nested KVM capability detection tests passed.\n'
