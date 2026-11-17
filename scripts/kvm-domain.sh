#!/usr/bin/env bash

# Sourced helper: return both legacy identity fields as variables, with no
# stdout or backend access. Hash the supplied path bytes, not a resolved path.
idarsi_kvm_domain() {
  local instance=$1 ephemeral_directory=$2
  kvm_domain_hash=$(printf '%s' "$ephemeral_directory" | sha256sum | cut -c1-8)
  kvm_domain_name="molecule-${instance}-${kvm_domain_hash}"
  kvm_domain_name=${kvm_domain_name:0:63}
}
