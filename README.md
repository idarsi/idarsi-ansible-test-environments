# Idarsi Ansible Test Environments

This repository prepares a Rocky Linux 10 or Fedora 44 host for running Molecule tests in
Idarsi Ansible role repositories. Molecule scenarios stay in each role and
choose one of two target backends:

- **Podman** for fast container-based tests.
- **KVM + Kickstart** for full virtual machines, including SELinux and firewall
  behavior.

The same host setup and pinned Ansible environments can be reused across role
repositories. The KVM profile prepares a reusable NAT network at
`192.168.250.1/24`, including a DHCP pool and room for scenario-assigned static
addresses. This repository does not contain role tests or an alternate
containerized Ansible controller.

## Install

Clone this repository on Rocky Linux 10 or Fedora 44 and run the installer as your regular
user. It uses `sudo` when installing host packages or writing the shared KVM
ISO into libvirt's boot directory. By default, it
prepares both backends and installs the `ansible-current` venv:

```bash
./install.sh
source .venv/ansible-current/bin/activate
git clone https://github.com/idarsi/ansible-iac-role-postgresql.git
cd ansible-iac-role-postgresql
ansible-lint --profile production
molecule test
```

Install only one backend or choose a different Ansible line with:

```bash
./install.sh podman ansible-min
./install.sh kvm ansible-next
```

For the KVM profile, the installer reuses configured install sources or
searches `/var/lib/libvirt/boot` for Rocky Linux 9 and 10 Minimal ISOs. If any
are missing, it displays all missing image sizes and asks about each one
before starting downloads. Accepted images download in parallel, are checked
against their official SHA256 checksums, and are stored in
`/var/lib/libvirt/boot`. The selected sources are exported when you activate
the venv: `IDARSI_TEST_KVM_INSTALL_SOURCE` for Rocky 9 and
`IDARSI_TEST_KVM_INSTALL_SOURCE_ROCKY10` for Rocky 10. Either image can be
declined; set its corresponding variable before running a scenario that needs
it. After selecting an ISO, `install.sh` performs the one-time installation
and saves a sealed OS base qcow2 under
`/var/lib/libvirt/images/idarsi-test-bases`. If a compatible base is already
there, the ISO prompt and installation are skipped. The installer prepares
that directory for the invoking user, so Molecule can create and remove guest
overlays without an interactive `sudo` prompt.

Molecule creates a small copy-on-write qcow2 overlay per VM from that base,
then sets the VM hostname, SSH key, and optional static address in the overlay.
Tests therefore start from the same clean OS state without reinstalling the
OS. If only an ISO is available, the first Molecule run builds the base before
creating its guests. Set `KVM_BASE_IMAGE_MODE=off` to use the legacy full ISO
installation path. Set `KVM_BASE_IMAGE_REVISION` to a new value when you need
to invalidate old base images.

The available Ansible Core versions and shared Ansible Lint version are pinned
in [versions.yml](versions.yml):
`ansible-min` (2.19.12), `ansible-current` (2.20.8), and `ansible-next`
(2.21.3); Ansible Lint is 26.8.0 in each environment. Each has a separate
`.venv/` directory. Activate the chosen venv before running Molecule; activation
exports the shared tooling path and collection path to the role's scenario.

Role repositories must define their Molecule scenarios to use the desired
backend. See [role integration](docs/role-integration.md), the
[Podman guidance](docs/podman-molecule.md), and the
[KVM + Kickstart guide](docs/kvm-molecule.md).

This repository also has standalone smoke scenarios: run
`molecule test -s podman-smoke` for Podman, or
run `molecule test -s kvm-smoke` for KVM after `install.sh kvm`. The first KVM
setup creates the base image; later tests boot disposable overlays and start
much faster.

## Uninstall

Run `./uninstall.sh` to remove the venvs and any `libvirt` group membership
added by the installer. Libvirt networks remain available for other role
repositories. RPM packages remain installed unless you explicitly
run `./uninstall.sh --remove-host-packages`; that option removes only packages
recorded as installed by this repository. Destroy KVM guests from their role
scenarios before uninstalling.

Installer state is stored outside the clone under
`${XDG_STATE_HOME:-~/.local/state}/idarsi-ansible-test-environments/`.

## Maintain dependency pins

`versions.yml` is the source for the Ansible, Python, Ansible Lint, Molecule,
and shared collection pins. Update the generated environment requirements with:

```bash
scripts/update-dependencies
make validate
```

Role-specific collections belong in the role's own Galaxy requirements file;
they are not installed globally by this repository. Repository checks run with
`make validate` and `yamllint .`.
