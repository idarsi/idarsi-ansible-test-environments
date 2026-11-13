# Testing

This repository prepares a reusable Rocky Linux 10 or Fedora 43/44 host for Molecule tests in
Idarsi Ansible role repositories. The shared controller venv supports two
target backends: Podman for fast tests and KVM + Kickstart for full virtual
machines. Role-specific scenarios and tests remain in each role repository.

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
network access or libvirt. Role behavior is verified by each role's own
Molecule scenarios.

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
idempotence, and verifies the clone has a lease matching its libvirt NIC MAC,
accepts SSH, boots Rocky, retains the inherited hostname, and has the leased
IPv4 address. On failure, the harness prints libvirt domain, interface, and
lease diagnostics before cleanup. The image
path tests importing and booting a preconfigured ISO-installed image, not image
customization; its blueprint omits network configuration because the image
already carries its hostname and a DHCP profile. The source guest stays shut
off while the clone obtains its own lease on `idarsi-test`. This image-source extension is
designed coverage and is pending runtime verification; it does not yet add
verified test evidence. The outer test VM is
created only by manual harness invocation; the role is not run on the physical
host and cannot create a host-side role-managed VM. Role files are transferred
as a filtered tar archive without `.git`, tests, secret/credential-named files,
or local configuration. Ansible Core, Lorax, and the role's pinned collection
requirements are installed/resolved on the disposable outer guest only.
The VM-free `tests/test-nested-kvm-renderer.sh` checks exact rendered state and
purge options. Run it with `make check-scripts`; lifecycle runtime checks remain
manual and must operate only inside the disposable outer guest.
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
