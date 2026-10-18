# Role integration

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

The example is role-specific and is not installed in the shared venv.
