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
    uses: idarsi/idarsi-ansible-test-environments/.github/workflows/molecule-reusable.yml@v1
    with:
      environment: ${{ matrix.environment }}
      test_environment_ref: v1
      role_repository: ${{ github.repository }}
      role_ref: ${{ github.sha }}
      molecule_args: test
```

The workflow builds the selected shared image in the runner, checks out the
role, and invokes its existing Molecule scenario. Pin the reusable workflow to
a reviewed release tag, or to a full commit SHA under a stricter policy.

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
