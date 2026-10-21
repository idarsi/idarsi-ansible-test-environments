# KVM + Kickstart Molecule tests

The shared KVM lifecycle uses Molecule's built-in managed (default) driver and libvirt's
`virt-install` and `virsh` commands. Molecule still owns the scenario sequence:
it runs the shared create playbook, role converge and verify playbooks, then
the shared destroy playbook. No KVM driver plugin is required.

## Prepare the host (Rocky Linux 10 or Fedora 44)

```bash
./install.sh kvm ansible-current
source .venv/ansible-current/bin/activate
```

This installs QEMU/KVM, libvirt, `virt-install`, SSH tools, `tmux`, and starts
the default and shared `idarsi-test` libvirt networks. The shared network uses
`192.168.250.1/24`, NAT, and a DHCP pool of `.100` through `.199`; scenarios can
assign stable addresses outside that pool. The host needs hardware
virtualization enabled and a readable/writable `/dev/kvm`. Setup adds the
invoking user to the `libvirt` group; log out and back in for that membership
to take effect. The same setup creates and enables the `idarsi-test-bases`
directory storage pool at `/var/lib/libvirt/images/idarsi-test-bases` (or the
path selected by `IDARSI_TEST_KVM_BASE_DIR`) for reusable base images. Existing
network and pool definitions are validated and are never replaced when they
conflict with the shared network subnet/bridge or configured pool path. Check
the host before running Molecule:

```bash
scripts/setup-host check kvm
virsh --connect qemu:///system net-info idarsi-test
virsh --connect qemu:///system pool-info idarsi-test-bases
```

The installer reuses configured sources and searches `/var/lib/libvirt/boot`
for Rocky Linux 9 and 10 Minimal ISOs. It displays the sizes of all missing
images and collects every download decision before starting any transfer.
Accepted downloads run in parallel and each ISO is verified against its
official SHA256 checksum. Rocky 9 is exported as
`IDARSI_TEST_KVM_INSTALL_SOURCE`; Rocky 10 uses
`IDARSI_TEST_KVM_INSTALL_SOURCE_ROCKY10`.

After ISO selection, `install.sh` creates a reusable OS-only base image in
`/var/lib/libvirt/images/idarsi-test-bases`. It skips the ISO prompts when a
compatible base already exists. Molecule creates a per-VM copy-on-write
overlay from the base and sets the hostname, SSH key, and optional static
network connection in that overlay. An ISO can also create the base lazily
during the first Molecule run. Set `KVM_BASE_IMAGE_MODE=off` to force the
original full ISO install path, or change `KVM_BASE_IMAGE_REVISION` to build a
fresh base after changing OS preparation. The installer prepares the
base-image directory so Molecule does not need an interactive sudo prompt.

## Add the shared scenario

Copy the example files into the role repository and edit the ISO path. Use the
Kickstart template matching the guest distribution:

```text
examples/molecule-kvm/molecule.yml       -> role/molecule/kvm/molecule.yml
examples/molecule-kvm/rocky9-10.ks.tmpl  -> role/molecule/kvm/rocky9-10.ks.tmpl
examples/molecule-kvm/fedora-44.ks.tmpl  -> role/molecule/kvm/fedora-44.ks.tmpl
```

The KVM scenario also needs the role's existing converge and verify playbooks.
Copy those from its current Molecule scenario, or set their paths in the KVM
scenario's `ansible.playbooks` section. This keeps the same role tests running
against the new VM target.

The example config points `ansible.playbooks.create` and `destroy` at this
repository's shared playbooks. The activated venv sets
`IDARSI_TEST_ENVIRONMENT` and exposes its pinned collections, so Molecule can
run directly from the role repository:

```bash
cd /path/to/role
molecule test -s kvm
```

Each platform entry in `molecule.yml` defines:

| Key | Meaning | Default |
| --- | --- | --- |
| `install_source` | Local installer ISO or HTTP(S) install tree; optional if a compatible cached base exists | From activated venv |
| `kickstart` | Kickstart template path, relative to the scenario | Required |
| `memory_mb` | Guest memory in MiB | 4096 |
| `vcpus` | Virtual CPU count | 2 |
| `disk_size_gb` | Base and overlay qcow2 virtual disk size | 30 |
| `install_timeout` | Total seconds allowed for installation and SSH readiness | 3600 |
| `ssh_user` | Temporary guest account | `molecule` |
| `network` | Existing libvirt network | `default` |
| `ipv4_address` | Static guest address; omit to use DHCP | unset |
| `gateway` | Guest gateway when `ipv4_address` is set | `192.168.250.1` |
| `netmask` | Guest IPv4 netmask when static | `255.255.255.0` |
| `nameserver` | Guest DNS server when static | `192.168.250.1` |
| `libvirt_uri` | libvirt connection URI | `qemu:///system` |

The Kickstart template must use `@@SSH_USER@@`, `@@SSH_PUBLIC_KEY@@`, and
`@@NETWORK_CONFIGURATION@@`. The shared template selects DHCP while the base
image is installed. For each VM, the create helper generates a temporary
Ed25519 key in Molecule's ephemeral directory and injects it into a writable
overlay. It also sets that VM's hostname and, when requested, writes an
individual NetworkManager connection for its static IPv4 address. It then
waits until SSH is ready. The guest user has passwordless sudo. The example
Kickstart keeps SELinux enforcing and the firewall enabled with SSH allowed,
so roles can exercise host security settings in a real VM.

The destroy playbook removes each named libvirt guest and its managed disk. VM
names are scoped by a hash of the Molecule ephemeral directory so different
role scenarios do not collide. If a run is interrupted, `molecule destroy -s
kvm` invokes the same cleanup path.

Use a role-specific Kickstart when the target needs a different package set,
partition layout, subscription registration, or installation source. For
RHEL, provide installation media or a repository the host and guest can
access; this tooling does not store subscription credentials.

## Test this repository's KVM setup

The `kvm-smoke` scenario exercises the shared VM lifecycle, SSH connection,
Ansible converge and verify, SELinux enforcing mode, and guest cleanup. It
is configured for a Rocky Linux 10 installation ISO available to libvirt:

```bash
source .venv/ansible-current/bin/activate
export IDARSI_TEST_KVM_INSTALL_SOURCE_ROCKY10=/path/to/Rocky-10-x86_64-dvd.iso
molecule test -s kvm-smoke
```

Replace the example path with an ISO that already exists on the host, or run
`install.sh kvm` and accept the Rocky 10 Minimal image download.
The smoke scenario defaults to Rocky Linux 10; use the Fedora Kickstart template
in a role-specific scenario to test a Fedora 44 guest.

To run the smoke test with verbose output and watch the guest's serial console
at the same time, use the tmux wrapper:

```bash
./verify-install-kvm.sh /path/to/Rocky-10-x86_64-dvd.iso
```

The upper pane runs `molecule --debug test -s kvm-smoke` with Ansible verbosity
set to level 3; the lower pane waits for the new smoke-test guest and attaches
to `virsh console`. Use
`Ctrl+]` to detach from the guest console, and `Ctrl+b` then `d` to detach from
tmux. The tmux session remains available to reattach after detaching. To close
the session, press `Ctrl+b`, type `:kill-session`, and press Enter. The
wrapper expects a readable local ISO and an installed `.venv` for the selected
Ansible environment. It saves plain text Molecule output under
`/tmp/idarsi-ansible-test-environments/molecule-logs/` and prints the exact log
path. The serial console output is saved under
`/tmp/idarsi-ansible-test-environments/kvm-logs/`; the console pane prints its
path. Both log types older than seven days are removed at the next run. Run one
KVM smoke test at a time so the new guest can be identified unambiguously.
