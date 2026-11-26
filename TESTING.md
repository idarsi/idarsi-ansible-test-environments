# Testing

## Failure diagnostics v1 (mocked only)

With the existing approved current controller, the focused developer check is:

```sh
.venv/ansible-current/bin/python -B -m unittest discover -s tests \
  -p 'test_isolated_failure_diagnostics.py' -v
```

It mocks all backend, guest, process/signal and collection boundaries. Private
disposable state checks cover ordering, sealed admission, original-exit
preservation, skip/cancel paths, durable ready multihost targets, exact Podman/KVM
ownership and transport arguments, bounded hanging/output cases, sanitization
before private artifact writes and unchanged cleanup delegation.
This does not establish native/backend acceptance. No new environments or
dependencies are installed; the tester owns broader mocked/runtime matrices.
See the [v1 contract](docs/isolated-test-runs.md#optional-failure-diagnostics-v1).

## Existing-generation guest proof

With an already activated approved controller and this checkout's helper binding:

```bash
python -B -m unittest discover -s tests -p 'test_isolated_existing_config.py' -v
python -B -m unittest discover -s tests -p 'test_isolated_guest_validation.py' -v
python -B -m unittest discover -s tests -p 'test_isolated_guest_proof_control.py' -v
python -B -m unittest discover -s tests -p 'test_isolated_logical_names.py' -v
```

These tests use private disposable state and mocked native observations, never
VM/backend mutation or SSH. They cover completed create followed only by sealed
owned-KVM stop/start operations, native stopped-target refusal and running-target
success, no-ops/other-guest history, malformed seals/workers/targets/order,
unchanged direct and supervised published mappings, quoted relocation using the
main guest-control comparator, finite confidential refusals, and byte/metadata
preservation including workers and admission. Names remain ASCII with the
existing character policy, now accepting 1–63 characters.

The installed-controller bridge tests are opt-in:
`IDARSI_TEST_INSTALLED_CONTROLLERS=1` requires all three existing approved lanes;
missing lanes are blockers, not installation requests. Without this flag those
two tests skip. No new environment or dependency installation is needed.
Portable CI parser regressions still run whenever Molecule is installed, even
without controller activation or a repository `.venv` layout. Their test-only
child fixture substitutes only the pure controller policy function, leaving
Molecule parsing, configuration guards and relocation comparisons real. It does
not spoof `sys.prefix` or `VIRTUAL_ENV` or add a production override. The
isolated-layout regression additionally proves the unmodified production bridge
still refuses missing authority. Explicit installed-lane fixtures exercise real
supervised policy acceptance and missing-activation refusal on each lane, without
the portable substitution. Run the portable layout check alone with:
`python -B -m unittest discover -s tests -p 'test_isolated_parser_portability.py' -v`.
The source-qualified historical role/direct acceptance records below are not
combined helper runtime evidence. The subsequent bounded combined acceptance is
recorded separately below; it does not extend native coverage to every controller.
Network provenance and recovery profile tests remain authoritative: changed
combined backend bytes must still refuse the frozen recovery source profile.
No source fingerprint is automatically updated to make a check pass.

## Combined-source acceptance — 2026-11-25

The reviewed combined implementation on base
`db87dc508c16d9bc68c85f5045e3ab0529cf388c` plus 24 uncommitted integration files
passed `make validate` and `yamllint .`. Full discovery reported **424 tests:
422 executed, two explicit installed-controller opt-in skips, zero failures or
errors**. Both opt-in requirements have separate passing evidence: the genuine
min/current/next installed bridge method and the current-controller read-only
bridge test. The shell target's two auxiliary four-test suites also passed;
they are not included in the 424 count. Ruff was unavailable, not installed or
represented as passing.

Subsequent explicitly authorized native acceptance passed on Python 3.12.16,
Ansible Core 2.20.8 and Molecule 26.8.0:

| Native scope | Result |
| --- | --- |
| Helper KVM, direct and supervised; Rocky Linux 9, one guest with root overlay and one 1-GiB data disk | Running proof, sealed stop, finite stopped-target refusal, stop no-op, sealed start, running proof and start no-op passed; ordinary cleanup sealed and cleaned. |
| Podman role whole `default`, KVM backend; Rocky Linux 9 **and** 10, retained direct lifecycle | Create/converge/idempotence/verify/destroy passed with the same retained generation; both hosts had idempotence `changed=0`. |
| Same whole two-OS consumer, canonical supervised full default lifecycle | Fresh native proofs and the full unchanged sequence passed; both hosts had idempotence `changed=0`; ordinary supervised cleanup passed. |

All four new generations were authoritatively cleaned, mutations sealed and
recorded worker births quiescent; exact owned resources were absent and both
supervised gates closed. The final supported admission check was clear.
Source maps, source-image bytes/metadata and foreign resource fingerprints were
unchanged. Proof snapshots preserved state/mapping/admission and native XML;
the helper fixture's repeated power controls are not a claim of power-operation
idempotence. The native window ended **08:33:28 UTC**; this record grants no
further execution authorization.

See the [source-qualified matrix and limits](docs/isolated-test-runs.md#combined-proofcontrol-acceptance)
for exact source-map fingerprints and remaining coverage. These results predate
this documentation-only update and any publication commit. Helper publication,
consumer pin update and CI against the published source remain pending; no
release-readiness or unpublished-pin CI claim is made.

## Cooperative supervised stop checks

With an existing approved controller, run:

```bash
python -B -m unittest discover -s tests -p 'test_isolated_cooperative_stop*.py' -v
```

The private temporary-journal unit fixtures invoke no backend tools or processes.
They verify admission closure before a busy resource-lock wait, completion seal
before any worker signal, missing/invalid seal refusal, timeout without signals
or deletion, failed gate/unsafe lock refusal, peer preservation and retry after
the original mutation seals. Existing admission and supervised-seal tests remain
regressions for denied late lifecycle entry, actual cleanup sealing and retained
uncertain operations.

`test_isolated_cooperative_stop_processes.py` adds tester-owned fixtures with
only disposable Python sessions: real admission/resource locks, durable seal
before actual session TERM, queued admission refusal, timeout without signals,
and missing-seal refusal. Their backend cleanup is mocked; all exact child
processes are terminated/reaped in `finally`. They require Linux pidfd support.
Real KVM stop-during-create/destroy plus concurrent-peer acceptance remains
tester-owned and unverified; these fixtures are not a backend cancellation barrier.

`test_isolated_create_stop.py` checks closed-gate create checkpoints and the
worker-bound `outcome: stopped` seal with fake backends. Ready instances are not
published; mismatched identity/checkpoint/worker, open gate, uncertain host RPC
and completion-write failure remain incomplete. A mocked KVM provisioner check
closes admission just after successful `virt-install` and verifies cancellation
before SSH polling; a start timeout never becomes a stopped-create seal.
`test_isolated_create_stop_processes.py` exercises the checkpoint-to-cleanup
path with real disposable Python sessions, gated cleanup worker and journal:
the stopped seal precedes session termination, guest/network cleanup and
`cleaned` publication. A second fixture executes the real backend teardown
method against mocked libvirt queries and a private temporary disk, asserting
exact-UUID hard destroy before undefine/unlink and preservation of a foreign
peer. Neither fixture starts or signals a real VM.

```bash
python -B -m unittest discover -s tests -p 'test_isolated_create_stop*.py' -v
```

The combined `test_isolated_guest_proof_control.py` private fixtures additionally
verify that every stopped-create checkpoint remains drainable but is never a
successful-create proof, even with stale ready mappings. Interrupted creates
with absent resource intents still refuse drain/proof rather than becoming
clean. Closed admission after completed create/guest-control history also
refuses proof. These checks preserve manifest, mapping, admission, worker lists
and filesystem metadata; they invoke no backend processes. Earlier native
acceptance above does not cover this cooperative-stop integration.

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

`python -B -m unittest discover -s tests -p 'test_isolated_direct_network_tail.py' -v`
uses only disposable fixture state. It checks refusal-only direct network-tail
diagnosis, original-journal preservation, no state creation/writes/backend
queries/signals, existing-pointer and lock failures, context/operation/handoff
mismatches, malformed or incomplete earlier guest operations, and rejection of
apply/force options. It establishes neither live resource absence nor recovery
eligibility. The default diagnostic grants no mutation or lease-release authority.
The same focused pattern `test_isolated_direct_network_tail*.py` also includes
pure historical-checkpoint bindings and bounded producing-source readers.
Byte-reader tests patch only the approved fingerprint definition for disposable
fixture bytes; a separate test verifies the real embedded 13-file composite.
They cover traversal, file/directory symlinks, hardlinks, FIFO, unsafe ownership
and permissions, replacement, late mutation and changed bytes/definitions.
No snapshot code is imported/executed and no runtime/backend query runs.
`test_isolated_direct_network_tail_standard.py` separately exercises the opt-in
rootless standard-libvirt profile with fake runtime/API/process boundaries:
private plan binding, exact acceptance and drift refusal, gated-worker intent
ordering, original-history preservation, independent parent settlement,
same-boot/session/visibility guards, kernel address/multipath-route leftovers,
two-snapshot churn, mutation uncertainty without retry, settlement-fsync failure
and explicit uncertain terminal publication/reconfirmation. Installed-runtime
fixtures distinguish measured package bytes/service birth from unverified loaded
images, hooks, firewall and helpers. No actual profile dry-run or apply is run by
these tests; tester-owned read-only qualification and separate operator apply
approval remain required.
Packaged-service argv regressions cover the actual systemd
`$VIRTNETWORKD_ARGS` representation using measured actual argv, rejecting unknown
variables/options, nonpackaged fragments, drop-ins, literal/actual conflicts,
unreadable/truncated/oversized cmdline and changed daemon birth before/after read.
The procfs/pidfd boundary is mocked; these tests do not read a host daemon.
The actual Fedora global timeout-abort drop-in has an exact byte fixture.
Qualification tests require its fixed package/build/source-RPM/hash/length,
safe root-owned file metadata and effective `TimeoutStopFailureMode=abort`;
unknown/additional paths, mismatched metadata/content/effective properties,
unsafe permissions and unreadable files refuse. No arbitrary override is ignored.
Address snapshot regressions accept ordinary `5301 -> 5300` valid/preferred
lifetime countdowns and canonical forever representations while rejecting
renewals, zero/deprecation or finite/infinite transitions, malformed values,
IP/prefix/scope/flag/interface/master/inventory changes and independent route/link
changes. Raw fixture observations are asserted unchanged. Independent tester
reads motivated this case; these mocked checks do not identify the exact
unpublished pair that caused an earlier CLI snapshot refusal.

On 2026-11-23, the tester recorded direct owned guest-control acceptance with
one Rocky Linux guest and one 1 GiB data disk: create, abrupt stop, stopped
no-op, start, running no-op and fixture verification passed. Initial destroy
was blocked: network-reference discovery refused foreign domains
referencing an absent network. The owned guest/disks were removed, but the
network and allocation were retained with an incomplete destroy operation.
On 2026-11-24, separately approved rootless standard-libvirt reconciliation
passed and released that allocation while preserving the original unsealed
destroy and history. This was reconciliation, not completion of the old destroy.

Fresh direct `kvm-forward` create/verify/destroy then passed with ordinary sealed
cleanup and creation-time ownership provenance. Fresh supervised
`kvm-supervised-control` passed the full implemented standard sequence, stop/start,
SSH and the 1 GiB data-disk checks; cleanup was sealed and every recorded session
was empty. These bounded checks used Python 3.12.16, Core 2.20.8, Molecule 26.8.0
and an existing Rocky Linux 9 qcow2 image, without image builds/downloads, sudo
or dependency installation. Tested source was `9c2cabe` plus uncommitted helper
changes, not a later documentation commit. Exact generations and code fingerprints
are recorded in the [technical acceptance record](docs/isolated-test-runs.md#recorded-guest-control-and-network-tail-acceptance).
Interruption/cancellation, broader OS/controller lanes, GUI and PostgreSQL role
acceptance are not established by these helper checks.

`python -B -m unittest discover -s tests -p 'test_isolated_network.py' -v`
checks the narrow confirmed-inactive foreign name-only dangling-reference
exception, strict default/recovery behavior, fresh complete inventories and two
matching dependency snapshots. Active or generation-owned domains, target
names/UUIDs, aliases/masters, resolved `actual` sources, embellished sources,
malformed discovery and between-snapshot churn still refuse destruction.
All backend/kernel operations in these tests are mocked.
Creation-time UUID/name evidence is also checked before guest definition and
after guest-journal clearing. Changed UUIDs retaining owned names, original
UUIDs with missing/changed descriptions, missing/ambiguous ownership provenance
and missing/duplicate observed domain names deny the dangling exception.

`python -B -m unittest discover -s tests -p 'test_isolated_guest_control.py' -v`
checks owned KVM guest control using private temporary state and mocked backend
commands: unsupported dispatch, CLI restrictions, existing-generation authority,
logical uniqueness, durable intent ordering, closed admission, result/seal
validation, exact-UUID transitions and no-ops, timeout/write-failure retention,
live/persistent identity, interface and backing-chain refusal. Active-image
headers are never opened; inactive headers must match the captured chain.
No guest or host-daemon operation is executed by these unit tests. Bounded
dual-mode runtime results are recorded above; wider interruption/cancellation
and platform acceptance remain tester-owned.
Additional review regressions compare two real installed Molecule config parses
(temporary supervisor root versus actual generation root), reject managed-save
state, filesystem/host-device exports and contradictory or ambiguous interface
sources in either XML definition. The real backend attachment guard is exercised
for changed bus, serial, format and extra disks.
The quoted-dependency regression also performs real supervisor-planning and
execution parses with space-containing ephemeral roots and the explicit shell
dependency command template. It covers command/environment fields together,
rejecting prefix collisions, foreign roots and unrelated context changes.
Standalone and both explicit dependency arguments also retain traversal-bearing
paths literally, including nested or internally cancelling `..` components.
Single/double/plain token tests preserve command spelling; unsupported escaped
forms stay literal rather than being reinterpreted. This is configuration-only
unit coverage. Separately, on 2026-11-24 the tester's three-guest PostgreSQL
`kvm-hard-patroni-failure` lifecycle passed with exit 0, including real leader
poweroff, promotion, same-domain restart, replica rejoin and SQL markers.
All four operations were sealed, the generation was cleaned and all eight
sessions were gone. The tested helper was `f9f0b7b` plus the uncommitted normalizer
fix, not a later follow-up commit; see the [qualified runtime evidence](docs/isolated-test-runs.md#quoted-dependency-hard-failure-acceptance).

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
