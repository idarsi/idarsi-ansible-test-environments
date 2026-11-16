# Testing

This repository prepares a reusable Rocky Linux 10 or Fedora 43/44 host for Molecule tests in
Idarsi Ansible role repositories. The shared controller venv supports two
target backends: Podman for fast tests and KVM + Kickstart for full virtual
machines. Role-specific scenarios and tests remain in each role repository.

Run `bash tests/test-kvm-image-cache.sh` from an activated shared environment
for VM-free image-cache selection tests. It invokes the real create playbook
with isolated launcher mocks and checks empty-path fallback, explicit-path
precedence, effective guest account and instance configuration, missing cache
and invalid metadata rejection before any VM actions, and ISO compatibility.
It also checks deterministic real cache lookup using temporary file fixtures
and is included in `make check-scripts`.
`bash tests/test-kvm-ssh-user-forwarding.sh` covers explicit-image account
forwarding. These focused checks do not replace runtime KVM/SELinux verification.

| Ansible environment | ansible-core | ansible-lint | Python | Typical use |
| --- | --- | --- | --- | --- |
| `ansible-min` | 2.15.13 | 6.22.2 | 3.9 | Minimum supported line |
| `ansible-current` | 2.20.8 | 26.8.0 | 3.12 | Default development baseline |
| `ansible-next` | 2.21.3 | 26.8.0 | 3.14 | Forward compatibility |

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
network access or libvirt. KVM base-image sealing ownership and permission
checks are also VM-free and use mocked commands. Role behavior is verified by
each role's own Molecule scenarios.

The KVM diagnostic smoke tests include Rocky 10 and Fedora 44. A focused
launcher mapping test mocks tmux and host checks; it verifies Rocky's default
mapping and the explicit Fedora 44 mapping without starting KVM. The Fedora 44
wrapper requires an official Fedora Server DVD ISO filename and disables base
image reuse to ensure the supplied ISO is actually tested. It permits a
7200-second installation and remains a manual KVM check, not part of
`make validate`.
To repair an existing environment's Fedora 44 activation hook without rebuilding
it or installing dependencies, run:

```bash
scripts/setup-venv --refresh-activation ansible-current
source .venv/ansible-current/bin/activate
```

The same command accepts `ansible-min` and `ansible-next`. It requires an
existing regular, non-symlink `bin/activate` and updates only its delimited
Fedora block, preserving everything outside it (including local integration
exports). Missing activation files and malformed or duplicate markers fail
without modification. Repeated refreshes are byte-for-byte idempotent.
Updates use an atomic rename and preserve activation-file permissions.
Activation reads `.kvm-install-source-fedora44` as literal single-line data
(including spaces and a missing final newline), only when
`IDARSI_TEST_KVM_INSTALL_SOURCE_FEDORA44` is unset or empty; explicit nonempty
overrides win. Normal environment creation installs the same hook.

The VM-free `bash tests/test-setup-venv-refresh.sh` fixture check covers all
three profiles, preservation, idempotence, replacement, literal data and
overrides, and invalid-file/marker rejection without touching real `.venv`
directories. It is also included in `make check-scripts`. Real activation and
TUI-equivalent KVM verification remain separate runtime checks.

VM-free cleanup fixtures (`test-kvm-destroy-overlay.sh`,
`test-kvm-explicit-disk.sh`, `test-kvm-overlay-cleanup.sh`, and
`test-kvm-base-image-ownership.sh` under `tests/`) cover paused guests and
preservation of storage on libvirt query, stop, or undefine failures. Cleanup
requires matching UUID ownership and verified removal before deleting storage;
uncertain failures retain storage and recovery files for manual inspection.

An explicit manual nested-KVM integration test is available on a capable KVM
host (not part of regular tests). After `./install.sh kvm` and configuring the
Rocky 10 ISO and the KVM role checkout, run
`IDARSI_RUN_NESTED_KVM_TEST=1 scripts/test-nested-kvm` (or pass the ISO path).
Provide the role checkout with `KVM_NESTED_ROLE_PATH=/path/to/ansible-iac-roles-kvm`
or `--role-path /path/to/ansible-iac-roles-kvm` (also supports
`--role-path=...`); there is no machine-specific default. The generated guest
blueprint selects the repository-created `idarsi-test` network, matching the
Kickstart network and lease polling.
It creates a uniquely named outer guest with host-passthrough CPU, installs this
checkout's KVM host setup inside it, then runs the selected role on that outer
guest to provision and install the inner Rocky guest from ISO. After checking
the ISO guest's Rocky OS, hostname, static address, SSH access, and second-run
idempotence, the harness discovers and validates the active NetworkManager
profile UUID and NIC device name, disables autoconnect on the static profile,
and adds an autoconnecting DHCP profile bound to that NIC (`ipv4.method=auto`,
`ipv6.method=disabled`). It reboots (tolerating the expected SSH disconnect)
and requires a DHCP lease matching the source NIC MAC plus SSH before gracefully
shutting down and preserving that qcow2 disk.
It then provisions a uniquely named clone using `source.type: image` and that
preconfigured disk, checks importing/booting the image and second-run
idempotence (`changed=0`), and verifies the clone has a lease matching its
libvirt NIC MAC, accepts SSH, boots Rocky, retains the inherited hostname, and
has the leased IPv4 address. This nested image-source integration test passed:
the ISO guest was converted from static networking to DHCP and rebooted
successfully, then its qcow2 disk was imported and booted as a clone with the
checks above. On failure, the harness prints libvirt domain, interface, and
lease diagnostics before cleanup. The image
path tests importing and booting a preconfigured ISO-installed Rocky image, not
arbitrary external/cloud image customization; its blueprint omits network
configuration because the image already carries its hostname and a DHCP
profile. The source guest stays shut off while the clone obtains its own lease
on `idarsi-test`. This manual run is runtime evidence for this nested host and
Rocky image workflow, not a general claim that arbitrary qcow2 images can be
customized. The outer test VM is
created only by manual harness invocation; the role is not run on the physical
host and cannot create a host-side role-managed VM. Role files are transferred
as a filtered tar archive without `.git`, tests, secret/credential-named files,
or local configuration. Ansible Core, Lorax, and the role's pinned collection
requirements are installed/resolved on the disposable outer guest only.
The VM-free `tests/test-nested-kvm-renderer.sh` checks exact rendered state and
purge options. Run it with `make check-scripts`; lifecycle runtime checks remain
manual and must operate only inside the disposable outer guest.
The nested harness additionally validates `state: validate` in check mode and
requires `install`, `vm_present`, `vm_absent`, and `absent` to fail closed in
check mode. It checks ISO removal without purge (including a no-op repeat),
image removal with manifest-scoped purge, refusal to remove a same-name
unmanaged sentinel domain, and refusal of `state: absent` while any domain is
defined. Only after those refusal checks does the harness undefine its exact
sentinel fixture; it then verifies `state: absent` removes the role's explicit
KVM package set and that a second run succeeds idempotently. Runtime evidence
remains pending until run on a nested-KVM-capable host.
Missing nested virtualization support is reported as `SKIP`; once opted in,
missing prerequisites or test failures are `FAIL`.
The prerequisite check requires readable CPU flags exposing `vmx` with an
active `kvm_intel` module reporting `nested=1`, or `svm` with active
`kvm_amd` reporting `nested=1`. Libvirt capability XML is not used because it
does not consistently advertise these CPU flags as named features. Run
`bash tests/test-nested-kvm-capability.sh` for VM-free detector coverage. The
inner guest exists only
inside the outer guest, so host-side destruction of the uniquely named outer
VM (including its disk) is ultimate cleanup even if SSH is unavailable. Inner
cleanup over SSH is best effort; failure to destroy the outer VM is reported.
Private temporary artifacts are removed on exit; no host-wide uninstall runs.
Allow at least 8 GiB RAM and four CPUs for the outer guest, in addition to the
inner guest resources.
The ISO blueprint requests 2048 MB, 2 vCPUs, and a 10 GB disk; the image-clone
blueprint requests 1024 MB, 1 vCPU, and a 10 GB disk. The harness verifies
libvirt `dominfo` memory/CPU and `domblkinfo` capacity against these declared
values for both guests. `tests/test_nested_kvm_resources.py` covers parser
success, resource mismatch, and missing fields without requiring a VM. The
role-owned `kvm-lifecycle` Molecule scenario invokes this harness and is a
manual, expensive integration check, not PR CI. Its one Rocky 10 host/guest
result and preconfigured ISO-derived image source are the limits of current
integration evidence.
The generated blueprint statically configures the inner guest at
`192.168.250.210/24` on the repository-created `idarsi-test` network, with
gateway and nameserver `192.168.250.1`. This address is outside the DHCP pool
`.100-.199`; the test asserts that the guest has the expected address over SSH.
The harness transfers only `config/idarsi-test-network.xml`, `scripts/setup-host`,
`scripts/kvm-base-dir`, and the role's `defaults`, `tasks`, `templates`, and
`requirements.yml` (not repository inventory, SSH keys, Git metadata, or local
configuration). It installs host automation directly, without invoking the
general-purpose `install.sh kvm` image-cache preparation. Run
`bash tests/test-nested-kvm-cli.sh` for VM-free role-path CLI coverage.
The inner-guest SSH private key is stored mode `0600` under the `molecule`
user's home directory.
