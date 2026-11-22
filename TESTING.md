# Testing

## Interrupted network-tail recovery checks

Use an already activated approved shared controller; do not create a worktree
venv:

```bash
python -B -m unittest discover -s tests -p 'test_isolated_recovery*.py' -v
```

These stdlib tests use temporary private Stores and fake host/backend evidence.
They cover non-writing dry-run, current-host observation, all-worker boot
matching, changed host/digest rejection, postboot absence reconciliation,
missing-seal preservation, strict ordinary cleanup, unknown protocols,
private existing locks/hardlinks, interrupted phases/retry, allocator-last
ordering and failed final-write rollback. Resource fixtures reject replaced
networks, bridge/interface/route/firewall leftovers, helper uncertainty,
foreign consumers, query failure and network reappearance. Journal fixtures
query exact-boot unique machine metadata without messages.
Review regressions additionally cover enclosing nft bitmask/unknown-expression
refusal, semantic literal/prefix/range/set selectors, full procfs visibility
(hidepid and unreadable metadata refuse), unknown helper configurations/includes,
escaped nested volatile mounts, bounded malformed XML in either inventory pass,
and absent-only legacy environment compatibility with measured runtime/source
receipts. Interpreter fixtures verify approved lane/pins, module origins and
normal trusted venv symlinks without using an actual controller/host probe.
Namespace fixtures distinguish unreadable/missing or invalid procfs identities
(including an empty link with a directory stat result) from validated namespace
mismatches. Both block recovery; equal valid identities pass only this guard.
These mocked checks neither identify the cause of a host anomaly nor establish
that recovery is unblocked.
Legacy firewall regressions exercise the exact hexadecimal `u32` enclosing-network
case, unknown extensions/options and malformed save syntax. Fake postboot apply
tests inject opaque selectors into either iptables view and require retained
lease/network intent, original missing seal and no resources_verified phase.
Security regressions additionally intercept the subprocess boundary (never
executing a tool) to verify authenticated fixed paths, root symlink/ACL policy,
multicall aliases, explicit restricted environment and read-only query grammar.
Reused network/domain/interface guards are exercised through that same runner.
Route fixtures cover gateway/source/via association, both address families,
explicit multipath, malformed destinations/unresolved references and corruption
during repeated verification, including original-seal/lease preservation and
bounded CLI errors.

There is **no approved teardown-driver profile**. Present networks always block;
these tests do not claim RPC cancellation, helper termination or real recovery.
Review and security review precede any real dry-run or maintenance preparation.
Before requesting a host reboot, the tester must establish persistent state,
fresh native observation validity and a viable postboot read-only check path,
including permissions for `nft`, `iptables-save` and `ip6tables-save`. Surviving
resources remain blocked. The current helper-association implementation also
requires a fully visible/readable procfs and **no current dnsmasq/radvd at all**;
even an unrelated default-network helper blocks because no config/include
association parser is approved. This may make postboot readiness unavailable,
and must be determined before requesting maintenance, not worked around by
stopping foreign services. Preparation authorizes neither reboot nor apply.
Readiness must also validate the fixed root-owned tool entry/target paths and
ability to query with the restricted environment and read-only virsh connection.
Caller wrappers, user configuration and PATH substitutions cannot make proof pass.
Full `make validate`, `yamllint .`, small owned-process crash fixtures and any
separately authorized runtime acceptance remain tester-owned.
See the [operator contract](docs/isolated-test-runs.md#interrupted-network-tail-recovery).

## Recorded bounded acceptance

On 2026-11-19, runtime acceptance passed with Python 3.12.16, Ansible Core
2.20.8 and Molecule 26.8.0 on the current controller, using Rocky Linux 10
guests: direct Podman/KVM full implemented lifecycles, retained direct Podman
commands and a new generation after destroy, supervised KVM smoke, and two
concurrent same-scenario supervised Podman runs. Cancellation after sealed
host create cleaned the selected run while its peer completed successfully.
A direct three-node Ceph run also passed idempotence and role verification,
preserving its context-private ansible.posix 2.1.0 through final cleanup.
This is not supervised Ceph cluster acceptance.

The tester also recorded 159 passing Python tests and a passing earlier
shell-check run; the affected overlay-cleanup fixture passed separately after
its mock repair. Dependency-pin
validation is a separate gate; these results do not imply it passed.
See the [technical acceptance table](docs/isolated-test-runs.md#verification)
for the exact scope and remaining matrix. Actual host-daemon mutation
interruption/late completion, crash/reboot recovery and all OS/controller lanes
are not established by this record; incomplete-operation safeguards have
mocked-suite evidence only.

## Dual-mode helper checks

`python3 -m unittest discover -s tests -p 'test_isolated_context.py' -v`
checks incomplete-operation refusal even with empty sessions, sealed-session
quiescence requirements, generic cleanup refusal for direct generations,
non-revival of cleaned generations and fail-closed partial handoffs. All backend
calls are absent or mocked. These checks do not establish runtime acceptance.
The same managed scenario is tested directly (including initial destroy,
dependency bootstrap, retained create/converge/verify and destroy) and through
the supervised launcher. Runtime interruption, late daemon completion, persistent
child session and interrupted cleanup acceptance remains tester-owned.
See [the technical contract](docs/isolated-test-runs.md).

The focused context regressions use the real installed `Config.env` exports
(including cached `MOLECULE_FILE`) for direct resolution/mapping and supervised
mapping-only destroy. Default and custom `MOLECULE_ENV_FILE` fixtures exercise
actual effective config without creating backend resources. Additional fixtures
reject stale initialized configuration and constrain unpublished-allocation
lease recovery.
`python3 -m unittest discover -s tests -p 'test_isolated_supervised_seals.py' -v`
checks incomplete create/cleanup refusal (including negative queries and late
objects), sealed-create cleanup after guest failure, cleanup seals before lease
release and unchanged legacy recovery. Backend commands are mocked throughout.

`python3 -m unittest discover -s tests -p 'test_isolated_admission.py' -v`
checks close-before-register and register-before-close races, the mutation-boundary
recheck, missing/invalid gates, unrelated/stale/reparented/inconsistent ancestry,
all-session registration and the closed-gate cleanup exception. A cheap fixture
uses actual `Config.env` plus two tiny Python child sessions and a mocked backend
to assert that every session and create intent is journalled before mutation.
Cancellation fixtures require the admission gate to be closed before stopping
workers. These are not backend acceptance or generic containment tests.

`test_isolated_private.py` checks private non-export publication states, actual
object recovery reconciliation, strict legacy fallback, Netbox-shaped omitted
metadata without foreign header reads, explicit references and query failures,
provenance mismatches, hardlinks, inode substitution and pending dependencies.
Backend queries are mocked; these checks do not replace runtime acceptance.

## Isolated-run launcher

The experimental `scripts/test-run` contract and runtime acceptance matrix are
documented in [isolated test runs](docs/isolated-test-runs.md). Its cheap tests
use temporary state and mocked backend commands:

```bash
make check-python
```

They cover concurrent allocator processes, discovery failures, inactive-network
and route conflicts, resource replacement, retained leases after cleanup
failure, worker start journaling/session recovery, and managed/legacy guards.
They do not demonstrate real Podman/KVM or all pinned Molecule compatibility.
The repository-checks workflow runs these unit tests on pull requests and its
weekly schedule, using Python 3.12 and no backend services. CI runs the same
`check-scripts`, `check-dependencies`, and `check-python` targets as
`make validate`, but installs pinned Molecule before `make check-python` so
effective-config cases run. The isolated-run suite runs only once per CI job.
Actual effective-config smoke tests run when an existing Molecule installation
is active (otherwise only those cases are explicitly skipped, not the stdlib
suite). Local minimum/current checks cover
inherited parallel and shared-state configuration. Filesystem fault-boundary
tests use only private temporary directories, never the real KVM storage
directory. They cover unnamed-inode publication, EEXIST, replacement refusal,
directory-fsync ordering, independent data disks and journal-write interleaving.
`StorageTraversalTests` additionally exercises search-only ancestors as an
unprivileged user, target-directory read/fsync requirements, symlink refusal
and unchanged trust checks. Its permission-denial cases explicitly skip under
root; all permission changes are confined to temporary test fixtures.
Focused `test_isolated_lifecycle.py` regressions launch only tiny local Python
processes in journalled test sessions: a writer survives its parent's timeout
or nonzero exit, in-session destroy defers removal, and supervisor cleanup stops
the writer before simulated deletion. Foreign-storage tests mock all backend
queries and cover nested backing stores, image chains missing from inactive
XML, pool/volume paths, inode aliases, query failures and partial disk-cleanup
retry. No real libvirt, Podman, guestfs or QEMU processes are used by these tests.
`test_isolated_graph.py` adds metadata-only concurrent cleanup evidence:
complete live XML without image opens, matching private managed captures for
inaccessible active disks, raw omission versus explicit qcow2 termination,
independent persistent references, rejected forged/stale/incomplete records,
pending dependency claims, and shared-lock/capture-before-start ordering.
Its backend queries are mocked; this is not concurrent VM runtime evidence.
`test_isolated_network.py` covers network teardown against direct bridges,
network names/UUIDs, network/kernel aliases, resolved actual interfaces and
divergent live/persistent definitions. It asserts no `net-destroy` on a
dependency, configuration mismatch or uncertain query, and retains successful
cleanup for proven-unrelated interfaces. Every backend and kernel-network query
in these tests is mocked.
The tester owns the remaining runtime matrix and crash-recovery acceptance.
The bounded same-scenario concurrency and post-create cancellation results above
do not establish interruption safety during a host-daemon mutation. No roles
have been migrated automatically.

## Existing environment checks

`bash tests/test-shared-shell-helpers.sh` is a VM-free regression check for
installer state paths and legacy KVM domain identities, included in
`make check-scripts`. Fixed legacy hash prefixes cover long, literal-special,
space-containing and non-normalized paths; account lookup mocks cover
`SUDO_USER`, `USER`, `id -un`, home fallback and empty/explicit `XDG_STATE_HOME`.
The checks also cover base/launcher naming agreement and 63-character
truncation, without creating state directories or querying a backend.

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

Host support does not imply every controller line supports every guest Python.
In particular, `ansible-min` (Core 2.15) cannot target Fedora 44's default
Python 3.14; use a compatible controller line for that guest. Pins remain
environment-specific.

Run `./install.sh [podman|kvm|all] [ansible-min|ansible-current|ansible-next]`
to prepare the host and selected venv. Activate the venv before running the
role's Molecule scenario. For KVM, the host also needs firmware virtualization
enabled and access to `/dev/kvm`; a new login is required if the installer adds
the user to the `libvirt` group.

The shared environments also provide Ansible Lint for role checks. Run
`ansible-lint --profile production` from the role repository; its repository
configuration and any justified exceptions remain role-owned.

Before submitting repository changes, run `make validate` and `yamllint .`.
`make validate` includes the shell/nested fixture checks, dependency-pin checks,
and `make check-python` isolated-run unittest discovery. It starts no real
Podman, KVM or nested-KVM backends and installs no dependencies. For local
effective-config coverage, activate an existing pinned Molecule environment
before running it.
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
The VM-free `bash tests/test-prepare-kvm-base-images.sh` fixture verifies all
five OS source/template mappings with mocked base-image and host-permission
commands; it does not prepare images or alter host directories.
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
its sourced `scripts/installer-state.sh`, `scripts/kvm-base-dir`, and the role's
`defaults`, `tasks`, `templates`, and `requirements.yml` (not repository
inventory, SSH keys, Git metadata, or local
configuration). It installs host automation directly, without invoking the
general-purpose `install.sh kvm` image-cache preparation. Run
`bash tests/test-nested-kvm-cli.sh` for VM-free role-path CLI coverage.
The inner-guest SSH private key is stored mode `0600` under the `molecule`
user's home directory.
