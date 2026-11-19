# Shared direct and supervised test runs (experimental)

## Dual-mode lifecycle and helper v1

The **same managed scenario** supports ordinary `molecule test`, `create`,
`converge`, `verify`, and `destroy`, without a wrapper or TUI. Activate a
compatible controller and set `IDARSI_TEST_ENVIRONMENT` to a checkout supplying
the versioned helper below. This requirement is independent of the controller
venv's installation path. Copy the managed example's `provisioner.env` backend
setting, `driver.safe_files` collection-preservation glob, and default-driver
create/destroy playbooks. The helper validates the effective safe-files entry
`${MOLECULE_EPHEMERAL_DIRECTORY}/collections/*`; otherwise Molecule's own
post-destroy pruning could delete installed collections.
`IDARSI_TEST_ENVIRONMENT` alone never indicates supervision.

Direct commands retain guests between invocations. Their context identity is
the canonical role checkout, scenario, backend and **actual effective Molecule
ephemeral directory**. Do not concurrently use guests from the same direct
context. For isolated cooperating parallel runs, use `scripts/test-run run`
instead; it gives each full test a distinct ephemeral directory and generation.
Legacy scenarios are not automatically converted.

### Stable machine interface

```bash
scripts/scenario-context capabilities --backend podman --scenario podman-validation --role /path/to/role
scripts/scenario-context resolve --backend podman --scenario podman-validation --role /path/to/role
```

Actions are `capabilities`, `resolve`, `init`, `inspect`, `create`, and `destroy`.
`--backend` and `--scenario` are required; `--role` defaults to the current
directory. Success writes one JSON object to stdout; errors exit 1, write a
diagnostic to stderr, and emit no success object. Internal `_worker` is not
public API.

There is no “legacy unsupported” success classification or fallback exit code:
nonzero capability results are errors, never permission to downgrade to a
legacy/direct execution path.

Required success fields:

```json
{
  "schema": "idarsi.scenario-context/v1",
  "mode": "direct",
  "lifecycle_modes": ["direct", "supervised"],
  "effective_config_validated": true,
  "role": "/canonical/role",
  "scenario": "podman-validation",
  "backend": "podman",
  "ephemeral_directory": "/actual/molecule/ephemeral",
  "collections_directory": "/actual/molecule/ephemeral/collections",
  "generation": null
}
```

Consumers must check schema and required fields and tolerate additive fields.
`mode` is `direct` or `supervised`; `generation` is null before allocation or
after cleanup, otherwise a canonical UUID. `inspect` additionally includes
`manifest` for an existing generation in either mode; `manifest.subnet` is
the allocated subnet and `manifest.direct_identity` is the direct identity.
`capabilities` and `resolve`
validate effective installed Molecule configuration without allocating resources;
they work **before dependency installation, create, and initial destroy**.
Direct resolution honors the invocation's exported `MOLECULE_ENV_FILE`, including
a nondefault `--env-file` selection. `MOLECULE_FILE` is checked against the actual
installed Config.env export (the effective cached file), not the source scenario
filename. Role/scenario checks still use the effective canonical source identity.
Dependency bootstrap must use `collections_directory` from `resolve`, not a
guessed cache location. Existing destinations must be real directories owned
by the controller UID and not writable by other users; symlink destinations
are rejected. Create the destination if absent before Galaxy installation.
The dependency phase remains role-owned, including its collection installation
lock; the helper does not install collections or lock an installer. Use
`resolve`, not `init`, when dependency installation needs no generation.
Initial destroy changes only the instance mapping, never collections.
No arbitrary shell metadata is read.
`init` allocates a lease without mutating a backend (read-only backend discovery
is required). It is not needed for dependency bootstrap. Shared playbooks call
`create`/`destroy` with Molecule's role, scenario, instance and ephemeral binding.

Presence of any `IDARSI_RUN_ID` or `IDARSI_HANDOFF*` variable selects strict
supervised validation, even if empty. Partial/invalid handoffs fail closed.
The launcher supplies `IDARSI_HANDOFF=v1`; role, scenario, backend, ephemeral,
running manifest and journalled worker session must all match. Supervised
destroy is mapping-only: only the outer supervisor removes its resources.

### Mutation safety and recovery limits

Context pointers and authoritative manifests live under the private Store root,
outside disposable Molecule ephemeral state. A journal is allocated before its
pointer is published. Each new resource generation has a distinct UUID; cleaned
generations are never revived. Lost ephemeral files do not lose ownership.
Configuration is bound at allocation: every create, including the first after
`init`, rejects a changed effective configuration before any backend mutation.
Destroy the generation and allocate a new one rather than silently reinterpreting
an initialized generation.

A short-lived direct controller holds context then generation supervisor locks.
It stops old journalled mutation sessions **before** acquiring the resource lock.
Each host mutation runs in a separate gated session: operation ID/action and
worker boot/PID/start identity are durable before the gate opens. The worker
owns the resource lock during backend changes. Completion is sealed only after
all backend commands and journal/mapping writes succeed, never in `finally`.
After worker completion the controller reloads the manifest. Resource/graph locks
are released in order; the graph lock never overlaps the allocator lock. The
allocator lock is acquired last to release a conclusively cleaned lease.
The user's shell and Molecule session are never signalled.

**Any failed/interrupted mutation is incomplete.** Before any subsequent
destruction, sessions are quiesced and every operation must have a valid seal.
An incomplete operation means **zero deletions and no lease release**, even
after reboot or when backend queries show no object: submitted daemon requests
may finish late. Interrupted destroy also retains its lease. Recovery for such
direct generations is presently **inspection-only**; neither generic cleanup,
reap, nor a force-clear is a cancellation barrier. Preserve the journal and
escalate for backend-specific cancellation/reconciliation implementation.
Completed sealed operations with empty sessions permit ordinary identity-checked
direct destroy. No detached/controller async/host sudo mutation workers are
supported. This is conservative collision safety, not an untrusted-code sandbox.
New supervised manifests explicitly declare `mutation_protocol: sealed-v1`.
Their host create operation records intent and its admitted, journalled session
identity before issuing backend commands, and seals only after successful
backend and journal/mapping writes. Molecule process exit is **not** a seal.
A subsequent guest converge/verify failure does not invalidate a sealed host
create. Outer cleanup stops sessions before resources and requires all prior
mutation seals; it then journals a separate gated cleanup worker and seals that
cleanup before releasing the lease. An incomplete create or cleanup retains
resources and lease even if all backend queries are negative or an object
appears late. Neither reboot nor client termination proves daemon cancellation.
Existing supervised version-1 manifests retain their original recovery path:
absence of `mutation_protocol` selects that legacy path; no operation seals or
provenance are backfilled or required for old supervised journals. An explicit
unsupported protocol version fails closed rather than selecting legacy recovery.

### Supervised tool sessions and closeable admission

New supervised runs additionally declare `admission_protocol: session-v1`.
Before launching their outer worker, the supervisor creates a private durable
`admission.json` with version, run ID and state `open`. The separate
`.admission.lock` protects this file; closure never overwrites a resource
manifest that a mutation worker may be updating. A missing or invalid gate for
this protocol fails closed. Closed gates are never reopened.

Normal controller tools such as Ansible may create new task sessions themselves.
After validating the complete handoff and effective role/scenario/backend/
ephemeral binding, admission locks **resources then admission**. It proves the
helper's entire PPID ancestry to the still-live, birth-checked journalled outer
worker. Linux pidfds pin every inspected process through the journal commit;
boot, UID, PID birth, SID, PPID and liveness are checked, then the whole chain is
re-read. Every session leader must itself be alive and in that proven chain.
All new session leaders, not only the helper's, are journalled before admission
returns. Same UID or a claimed parent PID alone grants no authority. Worker
records keep their original boot/PID/start shape so mutation seals remain bound
to the exact registered identity.

Prior authorization is not a mutation permit: at the actual lifecycle boundary,
while holding resources, the helper takes admission again and reloads identity,
running status, current session registration and the open gate. Create intent
is persisted before releasing admission; long backend work holds resources only.
Mapping-only supervised destroy also refuses a closed gate.

Cleanup (including cancellation) holds the generation supervisor lock, closes
admission durably, takes its latest worker snapshot under admission, releases
admission, and only then signals/waits for the registered sessions. It never
holds admission while waiting for resources or workers, nor resources while
quiescing them. A registrar already holding admission must commit before the
close snapshot; a registrar waiting on resources finds the gate closed and
cannot add a mutation afterward. After quiescence, resource locking and the
existing completion-seal barrier apply.

The supervisor's separately gated cleanup worker is the only exception to closed
scenario admission: it needs the exact journalled operation/session identity,
`purpose: supervisor-cleanup`, cleaning status and a closed gate. The start gate
is released only after that worker and operation are durable. This does not
reopen admission or permit scenario commands through the closed gate.

This supports admitted normal-tool sessions, **not generic process containment**.
An unregistered descendant must not independently mutate host backend resources
before admission. Detached/escaping host mutation workers, controller async and
host sudo workers remain unsupported. Guest-only untracked phases do not extend
this into a general containment guarantee. Historical manifests without the
admission protocol retain their original same-session authorization and recovery;
new ancestry/session provenance is never invented for old records.

One narrow orphan-allocation recovery is supported by `scripts/test-run cleanup
UUID` (also explicit reap): a direct manifest marked publication-pending whose
context pointer was never published, with no workers, operations, guests,
network, storage probe or instance mapping, may release its unused lease.
Recovery locks context before supervisor/resources and revalidates the journal
and pointer. A pointer naming this generation, any mutation history, or any
resource intent disqualifies it. A publication-pending manifest whose pointer
was written before a crash remains accessible through the normal context and
cannot use this exception. This is not reconciliation of interrupted mutations.

### Supervisor output identity

`scripts/test-run run` emits its first stdout line `Run ID: UUID`, flushed
**before any worker is started**. All pre-allocation discovery/config command
output is captured, not relayed to stdout. Consumers must accept that first
identity exactly once and never replace it with worker output, which is
untrusted and may contain spoofed `Run ID:` lines. On completion, use
`scripts/test-run inspect UUID` and validate its `id`, canonical `role`,
`scenario` and `backend` against the original request as well as its `status`.
Do not infer cleanup success from worker logs or supervisor termination.

`scripts/test-run` supervises **one full `molecule test`**, with a private
network, subnet, ephemeral directory and physical resource names. Logical
inventory names remain stable. It does not monitor CPU, RAM or storage
capacity. Bounded current-controller runtime acceptance is recorded below.
The full supported controller/OS matrix remains pending; do not interpret the
current results as unrestricted production-role migration approval.

## Prerequisites and scope

Activate an existing pinned environment as usual. The launcher itself uses
Python 3.9+ standard-library modules; a separate read-only configuration bridge
uses the active environment's installed Molecule parser, including its inherited
base configuration. No new YAML library is installed. Linux `/proc`, flock,
pidfds, `ip`, local rootless Podman, and access to local `qemu:///system` are
required. **Both backend discovery commands must work**, even when running
only one backend. Missing tools, permission errors and malformed discovery
results fail closed. Do not install another venv for this launcher.

The guarantee is for concurrent cooperating runs under **one Unix user on one
host**, including different clones and both backends. All clones use
`~/.idarsi-test-runs`, with the home directory resolved from the Unix account
database, not `$HOME` or XDG overrides. The state directory must be owned by
that UID with mode 0700. Never move/delete it to "unlock" a lease.
Do not share this directory between hosts or via a filesystem without reliable
flock/fsync semantics. Multiple runner users require a coordinator not provided
here. External tools can race allocation; do not independently allocate
overlapping networks while tests are running.

Libvirt NAT is **not a security boundary**. Guests can reach the host and
other routable networks; this tool is collision isolation, not sandboxing
untrusted code. Role playbooks and scenario configuration remain trusted.
Host backend mutation must remain in a journalled worker session. Normal tools'
new task sessions are supported only through the supervised admission protocol
above, before any host backend mutation. Detached host daemons, controller
async tasks, arbitrary host-side `setsid` mutation workers and host-side sudo
workers remain outside the contract. Guest services are unaffected; guest-only
untracked phases are not claimed to be generically contained.

## Migration

There is no automatic conversion of legacy scenarios. Existing legacy
`molecule` commands and the legacy KVM launchers keep their behavior.
Managed scenarios use the **default** driver for both backends and the shared
managed create/destroy playbooks, never the Podman plugin's destructive
name-based lifecycle.

Copy the relevant `examples/molecule-managed-{podman,kvm}/molecule.yml`
into a role's scenario directory, and retain its prepare/converge/verify
playbooks. Use the `provisioner.playbooks` mapping in the example for the
minimum line; current Molecule migrates that mapping to `ansible.playbooks`.
Do not define conflicting mappings in both places.

```bash
# From a role checkout, after activating an existing pinned environment:
/path/to/test-environments/scripts/test-run run --backend podman --scenario podman-validation
/path/to/test-environments/scripts/test-run run --backend kvm --scenario kvm-validation

# An explicit role checkout is also accepted:
/path/to/test-environments/scripts/test-run run --backend kvm --scenario kvm-validation /path/to/role
```

The launcher exports its own checkout as `IDARSI_TEST_ENVIRONMENT`.
Configuration interpolation follows the installed Molecule version.
Inherited `MOLECULE_*` CLI/environment overrides are removed, including
`MOLECULE_PARALLEL` (even the string `false` is truthy to older Molecule).
The actual effective configuration must have shared state disabled, including
top-level `shared_state` inherited from base configuration. Custom test sequences
are rejected. Do not override connection inventory variables with legacy
physical hostnames or addresses. The generated instance configuration maps
logical names to private physical names (Podman exec connection) or private
SSH addresses (KVM).

### Podman allowlist

Each platform accepts only:

- `name`, `groups`;
- `image`, with `pre_build_image: true`;
- `command` (argv list preferred; a string is split without a shell);
- `environment` (mapping of names to string values);
- `user`.

Images must already support the role's needs, including Python for Ansible
modules. Anonymous image volumes are disabled. Builds, privileged containers,
host namespaces/networking, bind mounts, volumes, capabilities, fixed or
ephemeral published ports, custom networks and arbitrary extra options are
not supported. Unknown options fail validation **before network creation**.
There are no sudo retries and no prune operation. Cleanup uses recorded
container IDs plus ownership labels, and never `network rm --force`.

Podman connections use `containers.podman.podman`, not SSH. The pinned
environment must already provide that collection. Backend context records the
UID, storage root, runtime root and network backend; cleanup refuses a context
change. Remote Podman overrides and rootful operation are rejected.

### KVM scope and cache behavior

Platforms accept `name`, `groups`, `ssh_user`, `memory_mb`, `vcpus`,
`disk_size_gb`, `install_timeout`, optional `data_disks`, and exactly one source:

- `image_path`: an existing qcow2 image with the SSH user already created.
  Completed shared base images can be used directly; they are never modified
  or deleted. Per-run overlays receive their own SSH key, hostname and static
  NetworkManager profile.
- `install_source` plus `kickstart`: direct ISO/URL installation using the
  existing `@@SSH_USER@@`, `@@SSH_PUBLIC_KEY@@` and
  `@@NETWORK_CONFIGURATION@@` template contract.

**Unlike the legacy launcher, managed mode does not automatically build or
publish shared cached bases.** Preparing a cache remains a separate legacy
setup operation outside an active run. Direct ISO installations are themselves
owned guests, not temporary untracked base-builder guests. This deliberate
first-version limitation avoids inheriting the legacy base-builder's
name-based traps and privileged cache publication. No unmerged KVM fixes are
required. Managed invocation of the legacy builder is explicitly refused.

Optional owned data disks use this deliberately narrow interface:

```yaml
data_disks:
  - name: "osd1"
    size_gb: 20
```

Names must be unique, lowercase safe identifiers of at most 16 characters;
`root` is reserved. Sizes are positive integers, not booleans. Up to 25 data
disks are supported. Every disk is qcow2/virtio with a stable serial such as
`itr-osd1` (`itr-root` for the root disk), and an independently journalled,
unique host filename. Caller host paths, backing images and arbitrary options
are forbidden for data disks. Complete live and persistent attachment sets
are checked without depending on XML order. Changed attachments, serials,
formats or file identities prevent automatic cleanup. Root-only version-1
manifests remain recoverable.
Before unlink, other domains' live and persistent storage definitions are also
checked. Explicit local backing chains and libvirt pool/volume paths are
resolved using checked backend queries. Explicit
live and persistent references are compared first, independently: XML can
override an image header. File/inode aliases count as references.

Complete authorized **live** libvirt XML can prove a local chain without
opening another run's qemu-owned 0600 disk. An explicit `<backingStore/>`
terminates qcow2; omission is unknown. Explicit raw format on an ordinary
local file may terminate without that element. Mirrors, dataStore/external
data, unsupported storage types/formats and malformed chains are rejected.

New managed disks have a complete header-chain capture after formatting and
customization, before domain startup: canonical paths, device/inode identities
and formats, with provenance. Omitted persistent backing metadata can be
supplemented **only** by a private validated manifest matching complete live
evidence. Validation includes the run UID, directory/file ownership and modes,
backend/context, domain UUID/name/description, exact attachments/serials,
every explicit live/persistent reference and all current chain inode identities.
Legacy, missing or incomplete records never become an authorization shortcut.
For generic or legacy cleanup targets, unknown inactive domains require fresh
readable evidence. When evidence is
otherwise incomplete, unprivileged `qemu-img info --backing-chain` is used;
permission errors retain resources safely. There is no sudo, chmod/chown repair
or `--force-share` retry.

### Managed storage-graph contract

Fresh exclusively published managed UUID disks are **private, non-export
lifecycle resources** under `supervisor-private-nonexport-v1`. Do not export
them to unmanaged consumers, aliases, backing chains or snapshots. Out-of-band
rebase, block jobs, external-data features and backing changes are unsupported.
Guest filesystem writes remain supported. Cooperating managed consumers must
register dependencies under the graph lock before preparation.

Eligibility is not a filename convention or a user bypass flag. It requires
the trusted owning run journal, context and domain identity, canonical path,
policy/protocol version, and matching actual single-link regular inode.
Publication durably records `intent`, then `inode-journalled`, then `published`
after exclusive O_TMPFILE/linkat publication and directory fsync. Intent alone
never authorizes cleanup. Recovery of `inode-journalled` requires reconciliation
with the actual named object; it does not upgrade or rewrite provenance.
Hardlinks or inode substitution block deletion, including final revalidation.

Only for eligible private cleanup targets, **omitted** foreign backing metadata
is outside the supported lifecycle guarantee. Cleanup does not open unrelated
foreign image headers with qemu-img, label omissions complete, or catch-ignore
permission errors. Every observed explicit live/persistent, backing,
pool-resolved and inode/path-alias reference still blocks deletion, as do
malformed, unsupported or unresolved sources, query failures and registered
managed dependencies. This is **not a universal host graph guarantee** or a
claim of safety for invisible unauthorized consumers or out-of-band changes.

Existing journals without explicit policy/publication provenance remain strict,
even if originally created using O_TMPFILE. No automatic policy retrofit,
silent adoption or recovery bypass is provided. In particular, the two retained
pre-policy test runs cannot qualify automatically; independently confirmed
original provenance/non-export evidence would require a separately reviewed,
explicit recovery route. Their manifests must not be backfilled.

A short cross-run `.storage-graph.lock` serializes managed source claims,
final chain capture/start, managed restart, and the final dependency check plus
unlink. Lock ordering is this run's resource lock, then the shared graph lock.
No other run's lifetime/resource lock is acquired: private manifests are read
atomically. Pending backing dependencies are journalled before preparation, so
cleanup cannot race a guest that has not started yet. Image customization,
installation and SSH waits do not hold the shared lock. Initial definition/start
is bounded to 60 seconds (including virt-install media preparation); slow media
preparation can fail this bound and requires explicit recovery, not a longer
shared-lock hold. ISO installation is polled outside the lock, with one
identity-checked final boot after its install-phase shutdown.
For direct ISO installation with data disks, the adapter adds a root-serial
`ignoredisk` directive so automatic partitioning cannot consume data disks.
Such templates must not supply a second `ignoredisk` directive.

Additional NICs, arbitrary guest disk attachment changes, firmware options and
nested-VM launcher features remain unsupported. Automatic base-cache building
is not part of this adapter.

Remove legacy `network`, `libvirt_uri`, `ipv4_address`, `gateway`, `netmask`
and `nameserver` fields: managed mode rejects them rather than silently
retaining fixed addresses. Networks are transient, have predetermined UUIDs,
short bridge names, and no autostart. Gateway/DNS is `.1`, static guest
addresses are `.10`–`.209`, DHCP is `.210`–`.250`. Static profiles require
NetworkManager, matching the repository's supported image convention.

Network teardown first verifies the recorded UUID/name and the generated
bridge, NAT, gateway and DHCP configuration. It then checks **both live and
persistent** foreign interface definitions, including resolved `actual`
interfaces. Network names/UUIDs, other libvirt network definitions sharing the
bridge, kernel alternative interface names and direct-device bridge masters
all count as dependencies. Unresolvable or unsupported interface source forms
fail closed. A same-name replacement or changed network configuration is never
treated as permission to destroy a bridge.

## State, cancellation and recovery

```bash
scripts/test-run list
scripts/test-run inspect RUN_ID
scripts/test-run cleanup RUN_ID
scripts/test-run reap --dry-run
scripts/test-run reap --apply
```

Allocation holds one cross-backend lock while discovering host addresses,
all nondefault IPv4 routes in all tables, active **and inactive** libvirt
networks, Podman networks and outstanding leases. It selects a disjoint /24
from RFC1918 space. An atomic, fsynced manifest is the lease; there is no
separate lease file that can diverge from the resource journal.
New run-directory entries and state-root ancestors are fsynced before resource
allocation. Disposable Molecule state is under `.work/RUN_ID/ephemeral`,
separate from `RUN_ID/manifest.json` and its locks. Molecule deleting the
ephemeral directory's parent cannot delete the ownership journal.

Every backend create has durable intent first. Libvirt UUIDs are predetermined;
Podman labels allow matching creation intent to actual IDs after an interrupted
create. Existing same-name foreign resources are never adopted, started or
deleted. Linux `O_TMPFILE` disk inodes are fsynced and their device/inode
identities durably journalled **before** publication through a no-overwrite
`/proc/self/fd` link. The open descriptor is retained through provisioning;
inode checks before and after disk tools also run on failure. Before creating
the KVM network, a journalled probe verifies this exact protocol, directory
fsync and collision refusal on the configured storage filesystem. Unsupported
filesystems fail closed; no capability or permission changes are attempted.
Trusted ancestors are traversed using pinned Linux `O_PATH` descriptors, so
root-owned search-only directories (such as mode 0711) need not be readable.
Only the validated target directory is reopened for reading and directory
fsync; symlink, ownership and writable-ancestor checks remain enforced.
Unlink is followed by directory fsync before lease release.
The lease and run journal already exist when this probe runs. It creates and
removes only its journalled temporary probe inode, before any backend network,
guest, or guest-disk creation.
Replacement identities, ambiguous discovery and cleanup failures retain the
manifest and subnet.

Normal completion and SIGINT/SIGTERM stop remaining controller workers, then
remove owned guests, owned disks, the private network and finally release the
lease. Controller cancellation uses bounded TERM/KILL waits and Linux pidfds.
A failed test remains failed; cleanup failure makes an otherwise successful
test fail. Do not send SIGKILL expecting immediate cleanup.

Molecule's managed `destroy` playbook only clears its disposable instance
mapping. **All resource removal is deferred to the outer supervisor**, including
normal final destroy and failed-create destroy. A provisioning command timeout
or nonzero exit may leave libguestfs/QEMU descendants in the worker session;
killing its immediate subprocess is not proof of quiescence. The supervisor
stops the complete journalled session before acquiring the resource lock and
deleting anything. In-session destruction never attempts to kill its own
Molecule supervisor. Uncertain session ownership or surviving workers retain
all resource ownership records. This remains a full supervised `test` interface,
not a standalone retained-environment create/destroy interface.

After SIGKILL/power loss, explicitly invoke `cleanup RUN_ID` or inspect
`reap --dry-run` before `reap --apply`. Recovery requires the supervisor lock,
the recorded UID/backend context, the boot identity and a full inspection of
the recorded worker session, including descendants whose leader has exited.
It stops surviving workers before acquiring the resource lock, then reloads the
journal before any status write or backend deletion. PID reuse is uncertainty,
not permission to signal an unrelated process. Neither age nor a missing PID
alone makes a run stale. Active supervisors are refused, not disrupted.
Transient networks missing after reboot are allowed when guest cleanup is
otherwise proven.

Manifests and ephemeral diagnostics remain private after cleanup, with status
`cleaned`; the lease is reusable. Inspect output can include platform environment
values: do not paste it publicly without reviewing it for secrets.
Before publication, a killed worker's unnamed inode is automatically reclaimed.
After publication, its inode identity is already journalled for explicit
recovery. Legacy ambiguous disk records and replacements still fail closed;
the tool never adopts a file merely because its name matches.

## Verification

### Recorded runtime acceptance

The following bounded results were recorded on 2026-11-19 with Python 3.12.16,
Ansible Core 2.20.8 and Molecule 26.8.0 in the current controller environment,
using Rocky Linux 10 guests. The lifecycle remains experimental outside this
verified scope. No wrapper or orchestrator is required for direct commands.

| Mode and scenario | Observed result |
| --- | --- |
| Direct Podman smoke | Full implemented test lifecycle passed, including initial destroy, syntax, create, converge, idempotence, verify and final destroy. |
| Direct retained Podman | Separate create/converge/verify/destroy commands passed; the generation stayed stable through retained use, and the next create allocated a new generation. |
| Direct KVM smoke | Full implemented test lifecycle passed. |
| Supervised KVM smoke | Full implemented lifecycle with a fresh guest passed; real helper inspect from guest phases verified the supervised context, and outer cleanup completed with sealed operations. |
| Concurrent supervised Podman | Two runs of the same fixture had distinct generations, subnets, networks and guest identities. Cancellation after sealed host create returned 130 and cleaned that run; its peer completed the implemented lifecycle with exit 0 and cleaned successfully. |
| Direct three-node Ceph | Private Galaxy ansible.posix 2.1.0 installation, initial destroy, lifecycle, idempotence (`changed=0` on all three hosts), role verification and final sealed cleanup passed. The private collection remained installed through final destroy/pruning. |

Only implemented fixture phases are counted; optional missing playbooks are not
reported as passed. The concurrent supervised fixtures were small Podman
scenarios, **not concurrent Ceph clusters**. No full supervised Ceph acceptance
is claimed, nor a separately repeated direct/supervised overlap after the
admission fix.

Cancellation was tested **after completed, sealed host create**, not during a
host-daemon mutation. Actual daemon interruption, delayed completion and
destructive crash/reboot recovery remain unverified; conservative incomplete-
operation refusal is supported by mocked tests, not actual-daemon cancellation
proof. Other guest OS versions and minimum/next controller runtime lanes remain
outside this acceptance record.

The corresponding backend-free record includes 159 passing Python tests and a
passing earlier shell-check run; the affected overlay-cleanup fixture passed
separately after its mock repair. Dependency-pin
validation remains a separate requirement and is not implied by runtime success.

Cheap unit checks:

```bash
python3 -m unittest discover -s tests -p 'test_isolated*.py' -v
bash -n scripts/kvm-vm scripts/kvm-base-image
git diff --check
```

The tester owns the remaining full runtime matrix on each supported pinned
line and relevant guest OS. Extend the bounded evidence above with:

1. Run two identical scenarios concurrently for each backend. Confirm distinct
   networks/subnets, guest/container IDs, disks/SSH keys and ephemeral state,
   with stable logical inventory names. For Podman verify exec connectivity.
2. Fail/interrupt one run; verify that the other continues unchanged.
3. Confirm successful cleanup and no lease release on forced cleanup failure.
4. Kill the supervisor, inspect surviving worker sessions, and explicitly
   recover. Repeat across a host reboot for transient-network disappearance.
5. Replace an owned resource's name with a foreign identity and confirm cleanup
   refuses it. Verify cached base images and unrelated guests remain untouched.

The table records only the demonstrated subset. The complete matrix, including
host-mutation interruption, crash/reboot recovery, replacement refusal and
concurrent KVM acceptance, is not established by those bounded results.
