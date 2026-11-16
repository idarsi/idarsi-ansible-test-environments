# KVM + Kickstart Molecule tests

The shared KVM lifecycle uses Molecule's built-in managed (default) driver and libvirt's
`virt-install` and `virsh` commands. Molecule still owns the scenario sequence:
it runs the shared create playbook, role converge and verify playbooks, then
the shared destroy playbook. No KVM driver plugin is required.

## Prepare the host (Rocky Linux 10 or Fedora 43/44)

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
to take effect. Setup creates and enables the `idarsi-test-bases` directory
storage pool at `/var/lib/libvirt/images/idarsi-test-bases` for reusable base
images. The shared `idarsi-test` network schema and the storage-pool type/target
are validated before installation; conflicting definitions are refused, never
replaced. The default network is only required to exist, be active, and have
autostart enabled; its XML schema is managed by libvirt and is not constrained
by this setup. Installation starts and enables valid existing resources as
needed. `scripts/setup-host check kvm` is
read-only and reports missing requirements. Nested virtualization is optional
and off by default. Set `IDARSI_ENABLE_NESTED_KVM=1` when running `install.sh
kvm` (or `scripts/setup-host install kvm`) to configure `nested=1` for the
detected Intel or AMD KVM module. Unsupported vendors are skipped. Existing
conflicting `/etc/modprobe.d/idarsi-nested-kvm.conf` files are preserved and
reported. This is install-only; modules are never unloaded or reloaded, so the
setting applies on a future module load. The `check` action remains read-only.
`IDARSI_TEST_KVM_BASE_DIR` is
accepted only when exactly equal to the canonical default path; custom paths
and symlink-based alternatives are unsupported to keep privileged directory
operations confined. Check the host before running Molecule:

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

It also detects existing RHEL 9 and 10 DVD ISOs in that directory, including
versioned filenames such as `rhel-9.8-x86_64-dvd.iso` and
`rhel-10.2-x86_64-dvd.iso`. Their paths are exported as
`IDARSI_TEST_KVM_INSTALL_SOURCE_RHEL9` and
`IDARSI_TEST_KVM_INSTALL_SOURCE_RHEL10`. RHEL media is not downloaded; set
these variables to override discovery or use media at another path. Explicit
paths and URLs must end in the matching `rhel-<major>[.<minor>]-x86_64-dvd.iso`
basename; invalid overrides fail setup rather than reusing cached state. For
example, set `install_source: "${IDARSI_TEST_KVM_INSTALL_SOURCE_RHEL9}"` in a
RHEL 9 platform entry. Use a
Kickstart suited to the RHEL release. This tooling does not register guests or
provide subscription credentials/repository access; configure those as needed
for the role under test. When an ISO is discovered in the libvirt boot
directory, setup adds only missing group/other traverse bits to that directory
and group/other read bits to the ISO so an unprivileged QEMU process can open
it regardless of its group membership.

After ISO selection, `install.sh` creates a reusable OS-only base image in
`/var/lib/libvirt/images/idarsi-test-bases`. It skips the ISO prompts when a
compatible base already exists. Molecule creates a per-VM copy-on-write
overlay from the base and sets the hostname, SSH key, and optional static
network connection in that overlay. An ISO can also create the base lazily
during the first Molecule run. Set `KVM_BASE_IMAGE_MODE=off` to force the
original full ISO install path, or change `KVM_BASE_IMAGE_REVISION` to build a
fresh base after changing OS preparation. The installer prepares the
base-image directory so Molecule does not need an interactive sudo prompt.

Fedora 44 images use `.kvm-install-source-fedora44` (set up by the Fedora 44
source preparation flow) and the Fedora 44 Kickstart. To prepare the image
before running Molecule, run `scripts/prepare-kvm-base-images` from an
interactive terminal after source setup. This one-time command may prompt for
sudo credentials while fixing ownership and permissions; subsequent Molecule
runs reuse the prepared base image without prompting. The helper prepares
Rocky and RHEL images with the Rocky Kickstart, and Fedora 44 with its matching
Fedora Kickstart.

## Add the shared scenario

Copy the example files into the role repository and edit the ISO path. Use the
Kickstart template matching the guest distribution:

```text
examples/molecule-kvm/molecule.yml       -> role/molecule/kvm/molecule.yml
examples/molecule-kvm/rocky9-10.ks.tmpl  -> role/molecule/kvm/rocky9-10.ks.tmpl
examples/molecule-kvm/fedora-43.ks.tmpl  -> role/molecule/kvm/fedora-43.ks.tmpl
examples/molecule-kvm/fedora-44.ks.tmpl  -> role/molecule/kvm/fedora-44.ks.tmpl
```

The Fedora 44 Kickstart uses the `@core` package group, which is available on
the Fedora Server DVD. Do not substitute `@^minimal-environment`: that
environment group is absent from the DVD repository metadata and causes
Anaconda's package selection to stall. The template explicitly adds
`openssh-server`, `sudo`, and `python3` for Molecule access and provisioning.

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
kvm` invokes the same cleanup path. A private UUID ownership marker in that
ephemeral directory guards stop, start, and destroy against same-name foreign
domains. Existing VMs created before ownership markers were introduced are
intentionally not auto-removed; remove those legacy domains and overlays
manually after verifying their ownership.

Use a role-specific Kickstart when the target needs a different package set,
partition layout, subscription registration, or installation source. For
RHEL, provide installation media or a repository the host and guest can
access; this tooling does not store subscription credentials.

## Test this repository's KVM setup

The `kvm-smoke` scenario is a Rocky Linux 10 smoke test. RHEL install sources
are intended for role-specific scenarios; this launcher does not dynamically
switch the smoke scenario to RHEL. The scenario exercises the shared VM
lifecycle, SSH connection, Ansible converge and verify, SELinux enforcing mode,
and guest cleanup. It is configured for a Rocky Linux 10 installation ISO
available to libvirt:

```bash
source .venv/ansible-current/bin/activate
export IDARSI_TEST_KVM_INSTALL_SOURCE_ROCKY10=/path/to/Rocky-10-x86_64-dvd.iso
molecule test -s kvm-smoke
```

Replace the example path with an ISO that already exists on the host, or run
`install.sh kvm` and accept the Rocky 10 Minimal image download.
The smoke scenario defaults to Rocky Linux 10; use the Fedora Kickstart template
in a role-specific scenario to test a Fedora 43 or 44 guest.

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
### Imported qcow2 guests

Platforms may use `image_path` instead of ISO `install_source`/`kickstart`.
The source must be a readable qcow2 image with an existing `KVM_SSH_USER`
account and DHCP-capable NetworkManager networking (default user: `molecule`).
The launcher validates the source, creates an owned copy-on-write overlay in
the managed base directory, customizes only that overlay (hostname and SSH
public key), and boots it with `virt-install --import`. The source image is
never modified or removed. Do not combine `image_path` with a nonempty
`install_source`. This import path is opt-in/manual; it does not replace ISO
installation coverage.

For a diagnostic Fedora 44 installation, use the dedicated scenario and
wrapper (the ISO path is passed explicitly, without relying on activation-hook
state):

```bash
source .venv/ansible-current/bin/activate
./verify-install-fedora44-kvm.sh "$(cat .kvm-install-source-fedora44)"
```

Use the official Fedora Server DVD x86_64 ISO named
`Fedora-Server-dvd-x86_64-44-*.iso` (for example, the release ISO from
`https://getfedora.org/server/`). The wrapper rejects other filenames; this
filename check is a guard against accidentally installing a different distro,
not cryptographic provenance verification. Verify the ISO checksum/signature
against Fedora's published release metadata before use.

This uses `molecule/kvm-smoke-fedora44`, Fedora 44 Kickstart and the same
shared KVM create/destroy, converge, tmux, logging, and serial-console flow.
Its install timeout is 7200 seconds to allow observing the longer Fedora
installer; Rocky remains at 3600 seconds. Fedora's tmux-launched Molecule
command sets `KVM_BASE_IMAGE_MODE=off`, forcing installation from the supplied
ISO rather than reusing cached base images. With base images disabled,
`kvm-vm` does not infer an OS key from the Kickstart basename. The wrapper
requires a readable local ISO, and the scenario verifies Fedora 44 and
enforcing SELinux.
For an existing prepared base, an optional platform `image_cache` mapping
enables read-only lookup when `image_path` is omitted or empty:

```yaml
platforms:
  - name: rocky9-image
    image_path: "${MOLECULE_KVM_IMAGE_PATH:-}"
    image_cache:
      os_key: "rocky9"
      kickstart: "${IDARSI_TEST_ENVIRONMENT}/examples/molecule-kvm/rocky9-10.ks.tmpl"
      ssh_user: "molecule"
      disk_size_gb: 30
```

All four cache identity fields are required; relative Kickstart paths resolve
against the scenario directory. Lookup uses `kvm-base-image find` with argv,
the template hash and current cache revision, selecting the first readable,
nonempty regular match in C-locale filename order. It never builds, ensures,
repairs, or downloads an image. Missing templates or compatible images fail
before any VM actions; prepare the cache separately. All platform image inputs
are resolved before provisioning begins.

A nonempty explicit `image_path` always wins and retains platform `ssh_user`
(default `molecule`); invalid explicit paths fail without cache fallback.
Cache-selected images instead use `image_cache.ssh_user` for customization,
SSH readiness, and Molecule connection details, even when platform `ssh_user`
differs. Do not combine either image selector with a nonempty `install_source`.
An empty `image_path` without cache metadata fails clearly. Existing ISO-only
platforms remain unchanged. Molecule (including direct TUI invocation) performs
this resolution itself; no TUI-side cache preparation is needed.
