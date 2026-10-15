# Contributing

Dependency changes affect the shared Molecule environment. Update
`versions.yml`, run `scripts/update-dependencies`, and review all generated
requirements. Before submitting, run:

```bash
make validate
yamllint .
```

When changing Molecule or host dependencies, exercise a disposable role using
the affected Podman or KVM scenario. Do not add role-specific collections to
the shared environment; declare them in the role repository.
