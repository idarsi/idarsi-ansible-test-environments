# Testing

This repository tests the controller images themselves. Role behavior is
tested by role repositories through the reusable workflow.

| Platform/image | Ansible or application versions | Molecule scenarios | Main coverage |
| --- | --- | --- | --- |
| Rocky Linux 9 controller | ansible-core 2.19.12, Python 3.11 | image smoke test | Builder output and Ansible availability |
| Rocky Linux 9 controller | ansible-core 2.20.8, Python 3.12 | image smoke test | Current release baseline |
| Rocky Linux 9 controller | ansible-core 2.21.3, Python 3.12 | image smoke test | Forward compatibility |
| Role-selected target images | Role-defined | role validation, baseline, lifecycle, guardrails | Delegated to each role |

## Commands

`make validate` renders all Builder definitions. `make build-current` builds
and smoke-tests the default image. `make test ROLE_PATH=...` runs the selected
role's Molecule command through the current controller image.

The central CI matrix runs all three image builds. Role CI should make
`ansible-min` and `ansible-current` blocking. `ansible-next` may be allowed to
fail only when the role explicitly documents that temporary policy.

## Gaps

This repository does not claim that every Idarsi role supports every target OS.
It also does not run a role scenario in this repository because scenarios
describe role behavior. Each role must maintain validation, baseline,
idempotence, lifecycle, and destructive guardrail coverage appropriate to its
public states.
