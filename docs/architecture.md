# Architecture

## Boundaries

The repository owns controller dependencies only:

```text
role repository Molecule scenario
        -> shared execution environment
        -> role-selected target instances
```

The role owns its blueprint, inventory, scenario lifecycle, target operating
system, and role-specific collection requirements. The environment owns
`ansible-core`, `ansible-runner`, Molecule, the Podman plugin, a minimal common
collection set, and controller utilities.

Ansible Builder schema 3 renders each `execution-environment.yml` into a
Containerfile. The same definition works with Podman and Docker-compatible
build commands. The final image is intentionally a controller image, not a
privileged nested target host.

## Version Matrix

`versions.yml` is the review point for compatibility lines. Builder files keep
literal pins because Builder consumes ordinary YAML and must remain usable
without a custom preprocessor. The update script synchronizes those pins and
CI checks that they agree with the source file.

The selected lines are based on the upstream ansible-core control-node matrix:
2.19 supports Python 3.11-3.13, while 2.20 and 2.21 support Python 3.12-3.14.
Python 3.11 is therefore used only by the minimum line. A role may support a
wider range than this test matrix.

## Image Lifecycle

Builds use `quay.io/rockylinux/rockylinux` by immutable digest. Published
images use `ghcr.io/idarsi/ansible-test:<ansible-core-patch>` as the immutable
release tag, plus `ansible-min`, `ansible-current`, and `ansible-next` aliases.
Aliases are for convenience and may move. Release workflows should reference
the patch tag or digest. `latest` is not used by release-critical tests.

The central workflow builds, smoke-tests, and then pushes images. A failed
smoke test prevents publication.
