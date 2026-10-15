# Podman Molecule tests

Podman is the quick target backend for role scenarios. On Rocky Linux 10,
install the host tools and a selected Ansible environment with:

```bash
./install.sh podman ansible-current
source .venv/ansible-current/bin/activate
cd /path/to/ansible-role
molecule test
```

The role's default Molecule scenario should define its Podman driver and
platform image. Keep the role's converge, verify, and scenario-specific
collection requirements in that role repository. The shared venv includes the
Molecule Podman plugin and `containers.podman` collection.

Podman containers are suited to quick configuration tests. Use the role's KVM
scenario when a test needs a full VM, SELinux, or firewall behavior that the
selected container cannot provide.

## Test this repository's Podman setup

This repository includes a small smoke scenario that checks the Podman driver,
Ansible connection, converge, verify, and cleanup:

```bash
source .venv/ansible-current/bin/activate
molecule test -s podman-smoke
```
