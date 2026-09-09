# Role Integration

Each role keeps its own `molecule/` scenarios. A typical caller workflow is:

```yaml
name: Molecule
on:
  pull_request:
  push:
    branches: [main]
jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        environment: [ansible-min, ansible-current, ansible-next]
      uses: idarsi/idarsi-ansible-test-environments/.github/workflows/molecule-reusable.yml@<reviewed-release-tag-or-commit-sha>
    with:
      environment: ${{ matrix.environment }}
      test_environment_ref: v1
      role_repository: ${{ github.repository }}
      role_ref: ${{ github.sha }}
      molecule_args: test
```

The workflow builds the selected shared image in the runner, checks out the
role, and invokes its existing Molecule scenario. For reproducible CI, replace
the placeholder with a reviewed release tag or commit SHA. Do not use an
unreviewed moving branch reference.

Role-specific target matrices remain in the role workflow. For example, a
role supporting Rocky 9 and 10 can add `target_image` to its matrix and pass it
as an environment variable consumed by that role's `molecule.yml`; the shared
controller image does not decide this.

Additional collections belong in a scenario's `requirements.yml`, for example:

```yaml
---
collections:
  - name: "community.postgresql"
    version: "3.0.0"
```

Do not add service-specific dependencies to the common image solely to make one
role convenient.

The central build workflow runs for `vX.Y.Z` tags, and only publishes when the
semantic tag is protected (`github.ref_protected == true`). Repository tag
protection must be enabled by maintainers; this document does not imply that
repository settings are configured. Image version tags are derived from the
Ansible versions in `versions.yml`, not from the release tag. Consumers should
pin a published image digest for release-critical use.
