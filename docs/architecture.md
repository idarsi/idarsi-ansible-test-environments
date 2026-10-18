# Architecture

## Scope

This repository installs the tools required to run Molecule on Rocky Linux 10
or Fedora 44
and provides a shared KVM + Kickstart guest lifecycle. It supports two target
backends:

```text
role repository Molecule scenario
        -> activated pinned Ansible venv
        -> Podman containers or KVM guests
```

Each role owns its tests, Molecule scenario, target OS, and role-specific
collection requirements. One host setup and one or more pinned venvs can be
reused across role repositories. The venv activation exports the repository
path used by shared scenario playbooks and exposes the shared Galaxy
collections.

## Host setup

`install.sh` is the entrypoint. `scripts/setup-host` installs selected supported-host
Linux 10 RPM packages. The Podman profile installs Podman; the KVM profile
installs QEMU/KVM and libvirt, starts the default libvirt network, and adds the
invoking user to the `libvirt` group if needed. It also prepares the reusable
`idarsi-test` NAT network at `192.168.250.1/24`, with a DHCP pool from `.100`
through `.199` for guests that use DHCP and room for scenario-assigned static
addresses. Firmware virtualization must be enabled separately. Group changes
take effect after a new login.

`scripts/setup-venv` creates an isolated Python environment with the selected
ansible-core, Ansible Lint, Molecule, Runner, Podman plugin, and the common
`ansible.posix` and `containers.podman` collections. A role installs any
additional Galaxy collections from its own requirements file.

## KVM base images

The installer builds OS-only qcow2 base images under
`/var/lib/libvirt/images/idarsi-test-bases` after an ISO is selected. A Molecule
guest uses a copy-on-write overlay with its own hostname, machine identity,
SSH key, and optional static network profile. The same base can therefore
serve multiple guests and role scenarios. If a base is absent but an ISO source
is configured, the shared KVM create helper builds it on demand. Base images
are keyed by OS, disk size, SSH account, Kickstart content, install source, and
`KVM_BASE_IMAGE_REVISION`.

## Version matrix

`versions.yml` is the source for the three Ansible Core and Python pins, shared
Python packages, and shared collection versions. Each Ansible line has a
separate `.venv/ansible-*` directory. The pins describe this test setup; a
role documents its own supported compatibility range.
