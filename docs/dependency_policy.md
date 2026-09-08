# Dependency Policy

## Principle

**Pin the test environment, not the user's environment.**

An environment is a reproducible test fixture, so it pins Python packages,
Ansible collections, ansible-core, and the base image digest. An Idarsi role
must document the supported compatibility range separately and should not add
these exact pins to its runtime metadata merely because CI uses them.

## What Is Pinned

- `ansible-core`, Runner, Molecule, and the Podman plugin use exact PyPI pins.
- `ansible.posix` and `community.general` use exact Galaxy versions.
- The Rocky Linux base uses an image digest rather than a mutable tag.
- System package names are intentionally not version-pinned: the base image
  repository resolves security updates during a rebuild. The resulting image
  digest is the immutable release artifact.

The common collections are limited to collections broadly used by Idarsi
roles plus `containers.podman`, which is required by the shared Molecule
provider. A role adds uncommon or service-specific collections in its own
scenario requirements; they are not added globally.

## Updating

1. Check upstream ansible-core lifecycle and Python compatibility.
2. Change `versions.yml` and collection/base-image pins deliberately.
3. Run `scripts/update-dependencies` and inspect every changed file.
4. Run `make validate`, build all environments, and smoke-test each image.
5. Run representative Idarsi role matrices before merging.
6. Publish only after CI passes and the dependency change is reviewed.

Dependabot opens updates for GitHub Actions and pip requirements. Collection,
Ansible, and base-image updates remain manually reviewed because they can
change module behavior or target compatibility.

The host-side Builder bootstrap uses `ansible-builder==3.1.1` in a temporary
Python 3.12 container when a developer does not already have Builder installed.
This keeps local hosts free of a project Python stack; the bootstrap pin must be
updated deliberately alongside `versions.yml`.

## Security

Images contain no secrets and run without privileged mode. The test wrapper
only mounts the host Podman socket because target lifecycle management needs an
API boundary; scenarios should not request privileged containers unless their
role genuinely tests that behavior. The socket mount is disabled in workflows
that only validate definitions. Use image scanning and dependency advisories
as signals, then rebuild promptly for security fixes.
