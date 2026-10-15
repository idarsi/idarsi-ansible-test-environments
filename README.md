# Idarsi Ansible Test Environments

This repository prepares a Rocky Linux 10 host for running Molecule tests in
Idarsi Ansible role repositories. Molecule scenarios stay in each role and
choose one of two target backends:

- **Podman** for fast container-based tests.
- **KVM + Kickstart** for full virtual machines, including SELinux and firewall
  behavior.

The same host setup and pinned Ansible environments can be reused across role
repositories. This repository does not contain role tests or an alternate
containerized Ansible controller.

## Install

Clone this repository on Rocky Linux 10 and run the installer as your regular
user. It uses `sudo` when host packages need installing. By default, it
prepares both backends and installs the `ansible-current` venv:

```bash
./install.sh
source .venv/ansible-current/bin/activate
git clone https://github.com/idarsi/ansible-iac-role-postgresql.git
cd ansible-iac-role-postgresql
molecule test
```

Install only one backend or choose a different Ansible line with:

```bash
./install.sh podman ansible-min
./install.sh kvm ansible-next
```

The available Ansible Core versions are pinned in [versions.yml](versions.yml):
`ansible-min` (2.19.12), `ansible-current` (2.20.8), and `ansible-next`
(2.21.3). Each has a separate `.venv/` directory. Activate the chosen venv
before running Molecule; activation exports the shared tooling path and
collection path to the role's scenario.

Role repositories must define their Molecule scenarios to use the desired
backend. See [role integration](docs/role-integration.md), the
[Podman guidance](docs/podman-molecule.md), and the
[KVM + Kickstart guide](docs/kvm-molecule.md).

This repository also has standalone smoke scenarios: run
`molecule test -s podman-smoke` for Podman, or
set `IDARSI_TEST_KVM_INSTALL_SOURCE` to a local Rocky ISO and run
`molecule test -s kvm-smoke` for KVM. The KVM run installs a disposable VM and
can take several minutes.

## Uninstall

Run `./uninstall.sh` to remove the venvs and any `libvirt` group membership
added by the installer. RPM packages remain installed unless you explicitly
run `./uninstall.sh --remove-host-packages`; that option removes only packages
recorded as installed by this repository. Destroy KVM guests from their role
scenarios before uninstalling.

Installer state is stored outside the clone under
`${XDG_STATE_HOME:-~/.local/state}/idarsi-ansible-test-environments/`.

## Maintain dependency pins

`versions.yml` is the source for the Ansible, Python, Molecule, and shared
collection pins. Update the generated environment requirements with:

```bash
scripts/update-dependencies
make validate
```

Role-specific collections belong in the role's own Galaxy requirements file;
they are not installed globally by this repository. Repository checks run with
`make validate` and `yamllint .`.
