# Idarsi Ansible Test Environments

This repository provides reproducible Ansible Execution Environments for the
Idarsi `ansible-iac-role-*` repositories. It centralizes controller-side
tooling while leaving each role's Molecule scenarios in that role repository.

> **Pin the test environment, not the user's environment.**

The versions in this repository are test fixtures. A role's documented support
range is a separate compatibility contract and must not be replaced by these
exact pins.

## Environments

| Environment | Ansible Core | Python | Policy |
| --- | --- | --- | --- |
| `ansible-min` | 2.19.12 | 3.11 | Oldest Idarsi-supported line; blocking |
| `ansible-current` | 2.20.8 | 3.12 | Default development and release baseline; blocking |
| `ansible-next` | 2.21.3 | 3.12 | Forward compatibility signal; optionally non-blocking in role CI |

The initial matrix follows the upstream Ansible control-node support table.
See `versions.yml` for the single version source of truth and `docs/architecture.md`
for the rationale. Revalidate the matrix when an Ansible line changes lifecycle.

## Quick Start

Host prerequisites are Git, Podman, and basic POSIX shell tooling. The build
wrapper automatically runs the pinned Ansible Builder in a temporary Python
container when it is not installed on the host. Docker may
be used by setting `CONTAINER_ENGINE=docker` for image builds, but Molecule
scenarios use the Podman API and are supported primarily with Podman.

```bash
make build-current
podman system service --time=0 "$XDG_RUNTIME_DIR/podman/podman.sock"
make test ROLE_PATH=/path/to/ansible-iac-role-postgresql
```

Build another line with `make build-min` or `make build-next`. Use a specific
scenario or Molecule arguments with `MOLECULE_ARGS`, for example:

```bash
make test ROLE_PATH=/path/to/role ENVIRONMENT=ansible-min \
  MOLECULE_ARGS='test -s validation'
```

`make validate` renders every Builder definition without building an image.
The `scripts/test` wrapper mounts the role read-only and the host Podman
socket; it does not require a project-local Python installation. If
`MOLECULE_ARGS` is unset, the wrapper runs `test`; an explicitly empty value is
rejected. Arguments are parsed without shell evaluation, and shell
metacharacters or malformed quoting are rejected.

## Role Integration

Keep `molecule/` and all role-specific scenarios in the role repository. The
shared image supplies Ansible, Runner, Molecule, Podman support, and only the
small common collection set. A scenario can add its own `molecule/<scenario>/requirements.yml`
or install additional collections during its dependency phase.

For local testing, use the wrapper above. For GitHub Actions, call the
reusable workflow at `.github/workflows/molecule-reusable.yml` from this
repository at a reviewed tag or commit. See `docs/role-integration.md` for a
minimal caller workflow and OS-matrix pattern.

Target instances are not controller images. A role chooses its own Molecule
target images, such as Rocky Linux 9 or 10, based on its documented support;
this repository does not impose an OS matrix on roles.

## Builds and Publishing

`make build-current` creates a local image named
`localhost/idarsi/ansible-test:ansible-current`. Central CI publishes
version-labelled tags such as `ghcr.io/idarsi/ansible-test:2.20.8` and a
convenience alias for the environment. Tags are mutable registry references;
release-critical consumers should use a recorded image digest.

Images are built from a digest-pinned Rocky Linux base. No credentials or
secrets are copied into the image. CI smoke-tests and scans Ansible before
publishing. A `vX.Y.Z` tag is the release trigger; maintainers must enable
protected-tag rules, and publishing is gated on the tag being protected. Image
version tags are taken from `versions.yml`, not from `vX.Y.Z`. CI also verifies
the exported image checksum between scanning and publishing.

## Dependency Updates

`versions.yml` is authoritative for dependency pins. The update script
synchronizes the three Builder definitions, Python requirement files, and
Galaxy requirement files; `scripts/check-dependencies` verifies every generated
location and is run by the dependency workflow.
Every update is a reviewable pull request, followed by `make validate` and
image smoke tests. Dependabot monitors GitHub Actions and pip dependencies;
collection and base-image updates remain explicit because they need matrix
validation and supply-chain review.

Read `docs/dependency_policy.md` for the complete policy and security
boundaries.

## Repository Checks

```bash
make validate
yamllint .
```

The central build workflow validates and builds all three environments. The
dependency workflow checks YAML, pin consistency, and container image
vulnerabilities where the registry image is available.
