# Testing

This repository prepares a reusable Rocky Linux 10 or Fedora 44 host for Molecule tests in
Idarsi Ansible role repositories. The shared controller venv supports two
target backends: Podman for fast tests and KVM + Kickstart for full virtual
machines. Role-specific scenarios and tests remain in each role repository.

| Ansible environment | ansible-core | ansible-lint | Python | Typical use |
| --- | --- | --- | --- | --- |
| `ansible-min` | 2.19.12 | 26.8.0 | 3.12 | Minimum supported line |
| `ansible-current` | 2.20.8 | 26.8.0 | 3.12 | Default development baseline |
| `ansible-next` | 2.21.3 | 26.8.0 | 3.12 | Forward compatibility |

Run `./install.sh [podman|kvm|all] [ansible-min|ansible-current|ansible-next]`
to prepare the host and selected venv. Activate the venv before running the
role's Molecule scenario. For KVM, the host also needs firmware virtualization
enabled and access to `/dev/kvm`; a new login is required if the installer adds
the user to the `libvirt` group.

The shared environments also provide Ansible Lint for role checks. Run
`ansible-lint --profile production` from the role repository; its repository
configuration and any justified exceptions remain role-owned.

Before submitting repository changes, run `make validate` and `yamllint .`.
The setup-script checks include an isolated RHEL install-source functional test
for versioned ISO discovery, explicit overrides, and `setup-venv` activation;
it uses temporary files and mocked environment-creation commands, without
network access or libvirt. Role behavior is verified by each role's own
Molecule scenarios.
