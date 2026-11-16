#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kickstart="$repo_root/examples/molecule-kvm/fedora-44.ks.tmpl"

awk '
  /^%packages$/ { in_packages = 1; next }
  /^%end$/ && in_packages { exit }
  in_packages && $0 == "@core" { found_core = 1 }
  in_packages && $0 == "python3-libdnf5" { found_libdnf5 = 1 }
  END { if (!found_core || !found_libdnf5) exit 1 }
' "$kickstart" || {
  printf 'Fedora 44 Kickstart must declare @core and python3-libdnf5 in %%packages\n' >&2
  exit 1
}

printf 'Fedora 44 Kickstart package prerequisite test passed.\n'
