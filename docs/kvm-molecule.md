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
the default libvirt network when it is present. The host needs hardware
virtualization enabled and a readable/writable `/dev/kvm`. Setup adds the
invoking user to the `libvirt` group; log out and back in for that membership
to take effect. Check the host before running Molecule:

```bash
scripts/setup-host check kvm
virsh --connect qemu:///system net-info default
```

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
| `install_source` | Local installer ISO or HTTP(S) install tree | Required |
| `kickstart` | Kickstart template path, relative to the scenario | Required |
| `memory_mb` | Guest memory in MiB | 4096 |
| `vcpus` | Virtual CPU count | 2 |
| `disk_size_gb` | New qcow2 disk size | 30 |
| `install_timeout` | Total seconds allowed for installation and SSH readiness | 3600 |
| `ssh_user` | Temporary guest account | `molecule` |
| `network` | Existing libvirt network | `default` |
| `libvirt_uri` | libvirt connection URI | `qemu:///system` |

The Kickstart template must use `@@SSH_USER@@` and `@@SSH_PUBLIC_KEY@@`. The
create helper generates a temporary Ed25519 key in Molecule's ephemeral
directory, renders those values, injects the Kickstart file into the installer
initrd, and waits until it can log in over SSH. The guest must create that
user with the supplied key and passwordless sudo. The example Kickstart keeps
SELinux enforcing and the firewall enabled with SSH allowed, so roles can
exercise host security settings in a real VM.

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
export IDARSI_TEST_KVM_INSTALL_SOURCE=/path/to/Rocky-10-x86_64-dvd.iso
molecule test -s kvm-smoke
```

Replace the example path with an ISO that already exists on the host. The
installer prepares KVM software but does not download operating-system media.
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
