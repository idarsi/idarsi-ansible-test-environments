# Podman Molecule tests

Podman is the quick target backend for role scenarios. On Rocky Linux 10 and Fedora 43/44,
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
## Managed dual-mode scenarios

For managed Podman use `examples/molecule-managed-podman` and the
[versioned lifecycle contract](isolated-test-runs.md). The same default-driver
scenario runs directly with Molecule (no TUI/wrapper) or under `scripts/test-run
run --backend podman --scenario podman-validation` for isolated cooperative
parallel full tests. Keep its backend environment mapping. Helper v1 is required
independently of venv location; dependency bootstrap resolves the real ephemeral
collections directory before create. Direct retained guests are not safe for
same-context concurrent use. Incomplete mutations retain resources and leases
with inspection-only recovery. The legacy plugin guidance below is unchanged.
