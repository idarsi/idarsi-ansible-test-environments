#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
renderer="$root/scripts/render-nested-kvm-playbook"
python3 "$renderer" "$tmp/install.yml" iso-vm
python3 "$renderer" "$tmp/image.yml" image-vm /var/lib/libvirt/images/source.qcow2 --state vm_present
python3 "$renderer" "$tmp/remove.yml" iso-vm --state vm_absent --purge-data-on-remove true
python3 "$renderer" "$tmp/validate.yml" iso-vm --state validate
python3 "$renderer" "$tmp/absent.yml" sentinel-vm --state absent
python3 - "$tmp" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
install = (root / "install.yml").read_text()
image = (root / "image.yml").read_text()
remove = (root / "remove.yml").read_text()
validate = (root / "validate.yml").read_text()
absent = (root / "absent.yml").read_text()
assert 'state: "install"' in install and 'type: "iso"' in install
assert 'state: "vm_present"' in image and 'type: "image"' in image
assert 'path: "/var/lib/libvirt/images/source.qcow2"' in image
assert 'purge_data_on_remove: false' in image
assert 'state: "vm_absent"' in remove and 'purge_data_on_remove: true' in remove
assert 'state: "validate"' in validate
assert 'state: "absent"' in absent
for path in root.glob("*.yml"):
    text = path.read_text()
    assert "roles:\n    - role:" in text
print("PASS: nested KVM renderer state and purge assertions")
PY
grep -Fq 'run_role_state "$image_vm" validate false --check' "$root/scripts/test-nested-kvm"
grep -Fq 'for mutating_state in install vm_present vm_absent absent' "$root/scripts/test-nested-kvm"
grep -Fq 'not marked as owned' "$root/scripts/test-nested-kvm"
grep -Fq 'Libvirt domains remain' "$root/scripts/test-nested-kvm"
grep -Fq 'for package in qemu-kvm libvirt virt-install qemu-img lorax' "$root/scripts/test-nested-kvm"
