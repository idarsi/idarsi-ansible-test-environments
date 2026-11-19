# Role integration

For new managed scenarios use the
[dual-mode lifecycle contract](isolated-test-runs.md) and
`examples/molecule-managed-{podman,kvm}`. Copy `provisioner.env`, the
`driver.safe_files` collections glob, as well as
the shared playbook mapping. The same scenario supports direct
`molecule test/create/converge/verify/destroy`; no TUI or wrapper is required.
Use `scripts/test-run run --backend podman --scenario podman-validation` for
cooperative parallel full tests. Direct same-context concurrent guest use is
unsupported. A compatible helper implementing `idarsi.scenario-context/v1` is
required independently of where the pinned controller venv lives.
Dependency bootstrap can call `scripts/scenario-context resolve --backend podman
--scenario podman-validation` before create or initial destroy and install role
requirements into its validated `collections_directory`. Do not guess ephemeral
paths. Incomplete direct mutation operations retain all resources and leases;
recovery is inspection-only, not automatic reconciliation.

The shared `idarsi-test` networking and legacy playbooks described below apply
to legacy scenarios, not the private per-generation managed lifecycle.

Each Idarsi role keeps its Molecule scenarios and test cases in its own
repository. The shared test-environment repository supplies the activated
Ansible venv and common backend lifecycle tools.

## Run a role scenario

Activate the desired venv in the shell, then run Molecule from the role repo:

```bash
source /path/to/idarsi-ansible-test-environments/.venv/ansible-current/bin/activate
cd /path/to/ansible-role
molecule test
ansible-lint --profile production
```

The role's default Molecule scenario should target Podman for quick tests.
Define a separate KVM scenario for full Rocky/RHEL VM testing, and run it with
`molecule test -s kvm`. The shared `idarsi-test` NAT network provides guest
connectivity. Scenarios may set `ipv4_address` on a platform when stable
addresses are needed for cluster tests; DHCP remains the default. The KVM scenario can reference shared lifecycle
playbooks through the `IDARSI_TEST_ENVIRONMENT` variable set during venv
activation:

```yaml
ansible:
  playbooks:
    create: "${IDARSI_TEST_ENVIRONMENT}/molecule/kvm/create.yml"
    destroy: "${IDARSI_TEST_ENVIRONMENT}/molecule/kvm/destroy.yml"
```

See [Podman Molecule guidance](podman-molecule.md) and
[KVM + Kickstart guidance](kvm-molecule.md) for platform-specific details.

## Collections

The shared venv installs `ansible.posix` and `containers.podman`. Roles should
use `ansible.builtin.*` modules where possible. Declare any additional
collections the role needs in its own Galaxy requirements file and install
them in that role's Molecule dependency phase. For example:

```yaml
---
collections:
  - name: community.postgresql
    version: 3.0.0
```

Activation exports `IDARSI_MOLECULE_COLLECTIONS_FILE`, defaulting to
`collections-ansible-min.yml` for `ansible-min` and `collections.yml` for
`ansible-current`/`ansible-next`. An explicitly set value is preserved. Molecule
consumes this variable when selecting the role's collection requirements file
(for example in `molecule.yml`):

```yaml
dependency:
  name: galaxy
  options:
    requirements-file: "${IDARSI_MOLECULE_COLLECTIONS_FILE}"
```

The selected file is role-specific and its collections are installed by
Molecule, not in the shared venv.

The example is role-specific and is not installed in the shared venv.
