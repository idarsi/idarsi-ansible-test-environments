# Contributing

Dependency changes affect the shared test environment. Update
`versions.yml`, run `scripts/update-dependencies`, and review all generated
requirements. Before submitting, run:

```bash
make validate
yamllint .
```

`make validate` includes shell/nested fixtures, dependency-pin checks, and the
lightweight isolated-run Python suite (`make check-python` alone). It does not
start real backends or install dependencies. Activate an existing pinned
Molecule environment to include effective-config cases; without Molecule only
those cases explicitly skip, not the remaining stdlib tests. CI installs
pinned Molecule before running `make check-python` once.

When changing Molecule or host dependencies, exercise a disposable role using
the affected Podman or KVM scenario. Do not add role-specific collections to
the shared environment; declare them in the role repository.
