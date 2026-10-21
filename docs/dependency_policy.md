# Dependency policy

## Shared environment

The virtual environments pin ansible-core, Ansible Lint, Molecule, Ansible
Runner, the Molecule Podman plugin, and the small set of collections needed by
the shared test setup. `versions.yml` is the source of truth; generated
requirements are checked by `scripts/check-dependencies`.

Dependabot intentionally does not update generated `requirements.txt` files.
Update dependency versions in `versions.yml` using `scripts/update-dependencies`,
then validate the generated requirements.

The common collections are `ansible.posix` and `containers.podman`. Roles
should prefer `ansible.builtin.*`; additional collections belong in the role's
own Galaxy requirements and must not be added here merely for one role.

## Updating

1. Check ansible-core and Python compatibility for all three pinned lines.
2. Update `versions.yml` and run `scripts/update-dependencies`.
3. Review the generated requirements and run `make validate`.
4. Run the affected roles' Molecule scenarios against Podman and KVM as
   appropriate.

PyPI and Galaxy dependencies use explicit versions. Host RPMs are installed
from Rocky Linux repositories without fixed package versions so normal Rocky
updates can provide security fixes.
