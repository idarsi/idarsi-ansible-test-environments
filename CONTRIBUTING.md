# Contributing

Dependency changes are compatibility changes. Update `versions.yml`, run the
sync script, build all three images, and include upstream compatibility sources
in the pull request description. Do not replace exact release pins with
`latest` tags.

Before submitting:

```bash
make validate
yamllint .
```

Use a real disposable Idarsi role for image validation when changing Molecule,
collection, or system dependencies. Never add credentials, private registry
configuration, or host-specific paths to the image.
