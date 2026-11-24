# Shared direct and supervised test runs (experimental)

## Interrupted network-tail recovery

Use the **original canonical helper and original activated controller**, never
a worktree alias substituted into a TUI context:

```bash
scripts/test-run recover-destroy RUN_UUID --operation DESTROY_UUID --dry-run
scripts/test-run recover-destroy RUN_UUID --operation DESTROY_UUID --prepare-maintenance
scripts/test-run recover-destroy RUN_UUID --operation DESTROY_UUID --apply
```

Exactly one mode is required. There is no force, bulk reset, caller proof JSON,
PID/URI/path override, automatic reboot or daemon restart. Dry-run validates
existing private files and temporarily acquires existing kernel locks, without
initialization, directory fsync, manifest writes, signals, gate closure or
backend mutation. Bounded JSON reports eligibility/blocker codes, not private
manifests, machine IDs, environment values or journal messages. Blocked exits
are nonzero.

Scope is supervised `sealed-v1`/`session-v1` KVM: exactly one incomplete last
`destroy`/`supervisor-cleanup`, registered worker, all earlier operations sealed,
guests **exactly `[]`**, no storage probe/pending work, and a complete generated
transient NAT network intent. The reviewed synchronous legacy backend saves
guest-empty state only after guarded storage cleanup. Original canonical
role/scenario/helper/controller, local system-libvirt context and trusted source
profile must match. Direct, Podman, create, guest-tail, unknown protocols and
foreign/replaced resources remain unsupported.

The two historical environment annotations `IDARSI_TEST_ENVIRONMENT` and
`VIRTUAL_ENV` are optional **only when absent**, not when null, empty, malformed,
nonexistent or conflicting. Their absence reports
`historical_controller_environment_unrecorded` and uses
`legacy_runtime_measured` in the current `ansible-current` lane. Original
role/scenario/local backend and both create/destroy playbooks remain mandatory.
The actual executing module/entry root must equal their common canonical root;
current controller provenance is measured from `sys.prefix`, `sys.executable`,
trusted venv entry/target and reviewed existing tooling versions, never caller
environment claims. Foreign imports, arbitrary prefixes and worktree aliases
block. Standard venv interpreter symlinks are accepted only with trusted
entry/target paths. Original environment/config fields are never backfilled.
This exception enables diagnostics, native preparation and boot-fenced
absence-only reconciliation, never same-boot recovery or teardown.

### Boot proof and maintenance preparation

Same-boot recovery requires an audited actual running daemon/loaded driver/vendor
profile **and** authoritative historical no-detaching-hook evidence. Installed
virsh version, current hook absence and operator confirmation are insufficient.
This release has no accepted historical receipt/profile; that route reports
`historical_hook_receipt_missing`, never a fictitious RPC drain.

The supported route requires the current kernel boot to differ from **every**
original worker boot, with same-host provenance. Either verified root-controlled
persistent local journals must supply matching trusted boot/machine metadata,
or a previously recorded native current-host observation must validate.
Missing/conflicting/inaccessible journal evidence blocks; a path is not proof.

`--prepare-maintenance` makes a **nonterminal private audit write** only.
Under existing supervisor/resources locks it independently measures the current
kernel boot and root-controlled machine identity, requires every original worker
boot to match, checks a supported persistent local filesystem, and durably binds
the observation to the exact original operations/workers/resources/configuration
digest. It never closes admission, signals, queries/mutates backend resources,
releases leases, acknowledges TUI admission or reboots. Identical preparation
is idempotent; changed bindings cannot overwrite the observation. It cannot
backfill proof after a reboot.

This links a measured **present** boot to present host identity, not an invented
incident-time machine ID or root-signed attestation. It uses the project's
cooperative trusted-UID/private-Store and trusted local root model: malicious
same-UID edits, copied/migrated state, cloned identity, hostile root and remote
jobs are outside that boundary. After a separately authorized later reboot,
the machine identity must match and the boot differ from the observation and
all original workers.

**Before asking for reboot:** finish review/security/fake-process checks; validate
canonical helper/controller readiness and private persistent state (not volatile,
remote, uncertain or auto-cleaned storage); perform authorized native preparation
and validate it freshly; establish that postboot read-only checks can succeed.
The filesystem allowlist alone does not certify administrator retention policy.
A reboot interrupts host-wide work and requires separate explicit approval.
Preparation and ordinary owned-test stopping do not grant it. Same-boot legacy
runs remain blocked now.

### Absence-only reconciliation and audit history

This release implements the postboot **already absent** branch. Successful
local-libvirt discovery must prove the original UUID/name absent; complete
interface/address/route, nftables and legacy iptables reads must prove the exact
generated bridge/subnet/firewall footprint absent. Canonical read-only foreign
domain/network dependency checks remain. Current associated helpers, ambiguous
process metadata, bridge replacement, foreign use, incomplete queries and
permissions failures retain the lease. Reads of `nft`, `iptables-save` and
`ip6tables-save` must already be authorized; there is no privilege escalation
or dependency installation to make proof pass.

Recovery queries do **not** use caller PATH or the ordinary lifecycle runner.
Only fixed `/usr/sbin/{ip,nft,iptables-save,ip6tables-save}` and `/usr/bin/virsh`
entry paths are supported. Every ancestor and symlink hop/target must be
root-controlled, not group/world/current-UID writable; merged-/usr and root
alternatives links are supported. The resolved target is executed explicitly,
preserving the validated alias for xtables multicall operation. Missing or
untrusted tools block; there is no PATH fallback, sudo or installation.
This follows the existing non-root controller contract.

The recovery runner permits only enumerated read-query argument forms, adds
`--readonly` to the exact `qemu:///system` virsh connection, and passes an
explicit minimal environment: C locale, root-owned binary search directories,
HOME/XDG roots `/`, and disabled virsh history. Caller loader/auth/URI/shell/
Python configuration is not inherited; stdin and stderr are discarded, cwd is
`/`, and query time/output parsing are bounded. The same runner is injected
into both libvirt inventories and all reused foreign-domain/interface guards.
Ordinary lifecycle command behavior is unchanged.

Route proof queries **both IPv4 and IPv6**, validating typed destination,
gateway, preferred/source/from addresses, supported explicit `via` family/
address objects and nexthop/multipath paths. An associated gateway/source
blocks even with a disjoint destination and `onlink`. Exact `default` is a
valid destination sentinel, not a blanket subnet overlap; its gateway, source
and interface still must be unrelated. Malformed address strings, unknown
schema, unresolved `nhid`, encapsulation and unsupported nexthop forms block
instead of becoming negative evidence. No route repair is attempted.

Firewall evaluation intentionally supports a small nft selector whitelist:
literal/prefix/range/set address equality and interface-name equality/wildcards.
Bitmask/arithmetic, inverted or unknown expressions and named-set references
are uncertainty blockers, not evidence of absence. String traversal alone is
not a semantic proof. Unsupported rules may block even when an administrator
knows them to be unrelated; no automatic firewall rewrite is provided.
Both iptables save views likewise require complete framing and a tokenized
selector whitelist: literal source/destination networks, interfaces (including
trailing `+`), basic protocols/ports, explicit conntrack/state tests and comments.
Unknown extensions/options, inversions, opaque `u32`/BPF/ipset/iprange selectors,
arbitrary chain dispatch and NAT targets block instead of relying on dotted-IP
string searches. Missing extension arguments and malformed quoting also block;
no save output is executed or printed as an error.

Helper absence additionally requires a full root procfs with unrestricted PID
visibility and readable, stable per-process birth/UID/comm/cmdline/executable
metadata (kernel threads/zombies are handled explicitly). Restricted/unknown
hidepid, subset or overlaid process views block, regardless of assumed UID/gid
privilege. This MVP has **no approved helper configuration/include parser**:
any current dnsmasq/radvd blocks, even with apparently unrelated arguments or a
foreign/default-network config path. No arbitrary config files are read and no
helper is signalled. Consequently an ordinary default libvirt network may make
the postboot branch unavailable; readiness must establish this before a reboot
is proposed. It is not permission to stop foreign helpers or escalate privileges.

No new teardown/hook executes, so a current **mutation** driver profile is not
needed for this branch. There is deliberately **no approved surviving-network
teardown profile**: a present network reports
`current_mutation_profile_unavailable`, without `net-destroy`, `net-undefine`,
name-based helper kills or ad hoc cleanup. Future teardown requires separately
reviewed driver/vendor correspondence, synchronous hook policy, pre-erasure
birth/pidfd-pinned helper ownership and actual helper/kernel/firewall termination.
API success or UUID absence alone cannot supply that evidence.

Apply independently repeats proof: supervisor authority, additive durable intent,
closed admission/final original worker journal, canonical session stopping/empty
checks, then nonblocking resources-lock revalidation. The same-host boot fence
rules out historical local workers/descendants/daemon requests; PID absence alone
never does. No resources/admission lock is held while stopping. This read-only
absence branch launches no new backend resource worker.

Manifest version remains 1. Additive `recoveries.protocol: network-tail-v1`
retains target/digest/original workers/network, optional `host_observation`
(`current-host-v1`), measured `current_context` (binding mode/missing-field names,
canonical runtime paths/source hashes) and attempt IDs/phases: `intent`, `resources_verified`,
then `reconciled`/`outcome: reconciled`. Retry repeats **all** proofs; a saved phase
is not a reusable fence. Unknown protocols block. Original operations and missing
seals are never forged. Verified absence alone permits clearing network intent
and setting `cleaned`, under allocator lock acquired last without graph-lock
overlap. Write failures retain evidence and attempt lease rollback; unrecoverable
filesystem failure is not successful cleanup.
The native host observation includes a digest of the measured current context;
later source/controller/path changes invalidate it. There is no silent receipt
rewrite or automatic compatible-source upgrade. This is a new present-time
measurement, not historical interpreter attestation.
Interpreter/activation hashes and current Python/tooling versions are included;
even a same-path interpreter replacement can invalidate maintenance preparation.

Older helpers can inspect version-1 `cleaned`; ordinary mutation guards still
reject the original incomplete operation. Reconciliation is not original normal
PASS. Only after separately authorized real apply and fresh exact-context cleaned
inspection may the TUI's existing exact-token acknowledgement be used. Never
delete TUI state or clear another lease. Unit fixtures are not runtime proof.

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

Actions are `capabilities`, `resolve`, `init`, `inspect`, `create`, and `destroy`,
plus the KVM-only owned guest controls described below.
`--backend` and `--scenario` are required; `--role` defaults to the current
directory. Success writes one JSON object to stdout; errors exit 1, write a
diagnostic to stderr, and emit no success object. Internal `_worker` is not
public API.

### Owned KVM guest power control

KVM `capabilities` and `resolve` advertise
`guest_control_protocol: owned-kvm-v1` and
`guest_control_actions: [guest-stop, guest-start]`. Callers must require this
protocol before using these actions; older helpers reject them. Neither raw
`virsh` nor inferred domain names are a compatible fallback.

```bash
scripts/scenario-context guest-stop --backend kvm --scenario kvm-example --role /path/to/role --guest database
scripts/scenario-context guest-start --backend kvm --scenario kvm-example --role /path/to/role --guest database
```

`--guest` is the exact configured logical platform name and is valid only for
these actions. Stop is abrupt poweroff, not shutdown or removal. Start boots
the same persistent domain; it never defines a replacement. Disks, mappings,
network, generation and allocation remain intact. Results retain the context
schema and identity fields, adding `action`, `guest`, `operation` (UUID),
`changed` (boolean) and `state` (`shut-off` or `running`).

Both direct and supervised invocations require an existing unchanged generation
with a successfully sealed create and no incomplete mutation. The helper
compares effective configuration after normalizing only Molecule's ephemeral
root relocation from the supervisor's temporary config parse; the actual
current root is independently bound to the generation. All other configuration
and effective-environment fields remain compared.
Standalone path values relocate only when rooted at that exact ephemeral
directory, not when the root appears inside a foreign path or suffix collision.
Paths containing a native Linux `..` component remain literal, including nested
or internally cancelling traversals; normalization never resolves filesystem paths.
For explicit shell dependency commands, only the `--ephemeral-directory` and
`--molecule-file` argument paths relocate; simple single/double/plain quoting
and space-containing roots are supported without changing any other command
text. Unsupported escaped/compound argument forms stay literal and cannot
silently broaden configuration equivalence.
It validates unique logical ownership, exact domain UUID/name/description in both
live and persistent definitions, the owned network and interface, complete disk
attachments and recorded inode/backing-chain evidence. Running images are not
opened for header inspection: complete live XML must agree with the original
authorized chain. Inactive image headers are freshly compared with that chain,
never adopted as a new baseline. Extra storage, changed graphs, foreign
consumers, ambiguous queries and unsupported power states fail closed.
Managed-save state (or uncertainty about it) is refused before power mutation;
the helper never restores, removes or bypasses a saved-state image. Unsupported
device classes, including filesystem exports, host devices and NVRAM, are
refused in either domain definition. Every interface source and any resolved
`actual` source must agree with the owned network and bridge; ambiguous,
contradictory or unsupported source evidence is refused.
Already-running starts and already-off stops are validated no-ops, not bypasses.

Direct operations use the context/supervisor locks and a gated journalled worker;
supervised operations use the admitted current session and recheck the open
admission gate immediately before persisting intent. Resource and storage-graph
locks serialize validation and bounded exact-UUID backend operations. Only
successful postchecks receive a durable completion seal. Timeout, cancellation,
query failure or failed persistence leaves an incomplete mutation and retains
resources and lease; no automatic retry, restart or recovery authority is added.
Normal cleanup accepts fully validated completed guest operations, but refuses
incomplete ones even when the domain currently appears stopped or absent.

The VM-free regressions are `tests/test_isolated_guest_control.py`; they use
private temporary state and mocked backend boundaries. They do not establish
real KVM fault injection, runtime concurrency or interruption acceptance.

### Lifecycle context identity

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
These ordinary cleanup guards remain unchanged. The separate
[network-tail recovery](#interrupted-network-tail-recovery) command requires
same-host boot provenance plus complete absence evidence; reboot alone is not
that proof.
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

### Forward normal-network cleanup and inactive dangling references

Normal owned-network cleanup has one narrow unresolved-reference exception:
explicit inactive XML of a confirmed persistent, non-active foreign domain
whose C-locale `domstate` is exactly `shut off`, with a name-only
`<source network='...'>`, no source children/extra attributes and no `actual`
anywhere in the domain. The name must differ from the validated target
name/UUID and have zero name **and** UUID matches in a complete fresh network
inventory. Known owned-domain identities and generation ownership descriptions
remain ineligible, including after the guest journal has been cleared.
For new generations, `network.domain_ownership` is initialized with network
intent and durably accumulates every guest's original UUID **and name** before
domain creation. Guest removal never clears this evidence; both dependency
snapshots exclude either original identity independently of current descriptions.
The evidence is versioned, generation-bound and checked for ambiguity.
Historical manifests lacking creation-time evidence retain strict unresolved
reference refusal: cleanup never reconstructs or backfills an empty guest list.
Missing or duplicate domain names cannot prove foreign ownership.
Libvirt resolves this source by name; UUID matches are conservative collision
guards, not an alternative lookup rule. All later interfaces are still checked.
Active domains' inactive XML, unknown/paused/transitional states, missing
context, ambiguous or malformed inventories and resolved networks lacking an
unambiguous bridge deny.

Before normal `net-destroy`, two independent full read-only snapshots must agree:
domain/network inventories, active/persistent membership, exact domain states,
live/persistent XML, target configuration and fresh kernel-link facts. Failure
or change denies destruction. The supported host baseline remains native
distribution libvirt on Rocky Linux 10 and Fedora 43/44 (no alternate repository
or tool upgrade): it must provide plain `virsh domstate`, UUID list filters and
inactive domain/network XML, as documented by the
[upstream virsh manual](https://www.libvirt.org/manpages/virsh.html#domstate).
The helper uses `LC_ALL=C` and does not depend on `domstate --reason`.
Unsupported commands fail closed; host-lane runtime verification remains
tester-owned.

The shared graph lock coordinates cooperating helpers only. Two snapshots are
not an atomic libvirt transaction: trusted external administrators must keep
domain/network definitions and host links quiescent across discovery and
destruction. This is not sandboxing or protection against malicious same-UID
actors. Recovery callers do **not** opt into this exception; incomplete-operation
guards and recovery policy are unchanged. These source fixes authorize no
historical retry and claim no cleanup of retained resources.

### Existing inspection and recovery commands

#### Read-only direct network-tail diagnosis

The default direct diagnostic is deliberately refusal-only:

```bash
MOLECULE_EPHEMERAL_DIRECTORY=/path/to/current/ephemeral \
  scripts/scenario-context recover-network-tail --backend kvm \
  --scenario kvm-example --role /path/to/role \
  --operation ORIGINAL_DESTROY_OPERATION_UUID --dry-run
```

Use the actual existing direct ephemeral binding, not an invented directory.
The helper opens existing state and locks only. It does not initialize state,
run Molecule configuration, register or signal workers, query backends, create a
plan, or write an audit record. Missing/unsafe pointers, locks, bindings,
unsupported journals and supervised handoffs produce a bounded `eligible: false`
diagnostic. No `--apply`, `--force`, profile acceptance or mutation path is
available under this default contract.

The optional `--producing-source-root /path/to/approved/producing/source`
locates **bytes only**. The reader verifies exactly 13 fixed relative paths,
lengths and SHA-256 fingerprints against the embedded reviewed composite
`4f4af9b019ca41ea238b3c581ed8e6b80ab89eba97a27a556189fa9a790642c0`.
The root, descendants and files are descriptor-bound and no-follow;
unsafe ownership/permissions, links, nonregular files, changed bytes or unstable
reads block verification. Only the approved root-owned sticky `/tmp` ancestor
for the `/tmp/opencode` subtree is exempted from the ordinary non-writable
ancestor rule. The subtree itself must remain UID-owned and not group/world
writable. Nothing from the snapshot is executed, imported or used as
configuration. The location is not historical execution attribution, target
identity or digest authority. No default location or environment fallback
exists; a missing/unavailable source is explicitly reported, and public output
does not disclose its root path.

Successful byte verification still grants no eligibility. The historical
checkpoint profile and terminal-check contract are not enabled by this option.
Required independent forensic runtime, firewall and network-helper qualification
is unavailable under the default contract, so that diagnostic reports
`runtime_visibility_unavailable`, `firewall_visibility_unavailable` and
`helper_visibility_unavailable`, explicitly labelled as unavailable required
measurements, **not** a live permission probe or an absence assertion. No plan
digest, profile acceptance or apply route is exposed by the default diagnostic
or by source-byte verification alone.

When the exact final incomplete destroy and recorded empty guest checkpoint are
validated, but the original resource identity ledger is unavailable, the result
includes:

```json
{
  "eligible": false,
  "blockers": ["original_resource_identity_ledger_unavailable"],
  "network_only_scope_insufficient_for_terminal_cleanup": true,
  "apply_authorized": false,
  "lease_release_authorized": false,
  "audit_written": false
}
```

Audited producing-source ordering can support the *historical* interpretation
that a durable `guests: []` checkpoint followed completed guest/disk removal,
conditional on explicit source attribution. It does not identify the original
resources or freshly measure their absence. This default diagnostic accepts no
replacement proof contract and claims no terminal cleanup. Acceptance logs,
stale instance mappings and copied manifests are not adoption authority; no
historical ownership is reconstructed or backfilled. Neither reboot nor blind
ordinary destroy retry repairs missing proof. The original operation, context
pointer, network intent and lease remain unchanged. The separately reviewed
opt-in standard profile below changes that historical-proof contract explicitly.
Pure draft history/binding functions for
`direct-empty-checkpoint-network-tail-v1` are intentionally disconnected from
CLI eligibility: they require exactly one sealed create, then sealed guest
controls, then the sole incomplete destroy, and preserve exact JSON type/content
bindings. They never grant eligibility alone; the separate standard profile below
supplies its explicitly narrower runtime and settlement contract.

#### Opt-in standard-libvirt network-tail reconciliation

`direct-standard-libvirt-network-tail-v1` is a separate, rootless trust contract,
not a relaxation of the default forensic diagnostic or ordinary destroy:

```bash
MOLECULE_EPHEMERAL_DIRECTORY=/path/to/current/ephemeral \
  scripts/scenario-context recover-network-tail --backend kvm \
  --scenario kvm-example --role /path/to/role \
  --operation ORIGINAL_DESTROY_OPERATION_UUID --dry-run \
  --profile direct-standard-libvirt-network-tail-v1 \
  --producing-source-root /path/to/approved/producing/source
```

Activate an existing approved controller and its actual
`VIRTUAL_ENV`/`IDARSI_TEST_ENVIRONMENT` bindings first. The profile currently
requires Fedora 44's installed `libvirt-daemon-driver-network` build
`12.0.0-3.fc44`, source RPM `libvirt-12.0.0-3.fc44.src.rpm`. It measures installed
daemon/driver digests, version, service properties, PID/birth, fixed tools,
current controller/interpreter/helper sources, and the separately approved
producing-byte subset. Installed bytes are **not** loaded-image attestation.
There is no sudo, privileged collector, hook/config parser or forensic fallback.
The service must use the RPM-matching packaged `virtnetworkd.service` fragment.
The sole permitted drop-in is Fedora's exact
`/usr/lib/systemd/system/service.d/10-timeout-abort.conf`, owned by the reviewed
`systemd` build `259.8-1.fc44` with matching source RPM, RPM SHA-256 inventory,
596-byte content and fixed digest
`ae6b234f92bc22f1201a7572b59b454c9809f33c80d13f361b9674e1801acc37`.
The file is opened no-follow, root-owned/non-writable and checked stable;
`TimeoutStopFailureMode=abort` must also be the effective service property.
Its package/content/effective-property receipt is bound into the runtime plan.
Unknown, additional, altered or unreadable drop-ins refuse qualification.
No drop-ins is supported only with effective `TimeoutStopFailureMode=terminate`.
The single known `$VIRTNETWORKD_ARGS` representation is allowed
only with a pidfd-pinned, birth-rechecked read of actual `/proc/PID/cmdline`:
exact daemon argv, optionally `--timeout 120` or `--timeout=120`. No other
variable, expansion, option or configuration path is accepted. Unreadable,
truncated, oversized or changing argv remains unknown and blocks qualification;
environment files are neither parsed nor presumed empty.

Eligibility requires the exact existing direct context/pointer and original
history: one sealed create, only strictly sealed guest controls afterward, and
the final sole incomplete destroy. It accepts the durable empty guest checkpoint
as *historical* removal evidence conditional on explicit cooperative source
attribution—not fresh absence of original identities, log adoption or ownership
backfill. Every old recorded writer/session must be gone in the same boot, with
complete procfs visibility and no ambiguous PID reuse. Current generated network
XML and two fresh complete domain/network/kernel snapshots must agree. Only a
matching active transient generated network, or its independently verified
absence, is eligible; persistent/replaced/foreign-dependent networks refuse.
The narrow bare inactive foreign dangling-reference rule is separately applied
under this contract without manufacturing the missing old ownership ledger.
For comparison only, address `valid_life_time`/`preferred_life_time` accept
validated uint32 seconds or literal `forever` (`4294967295` has the same infinite
meaning). Positive finite counters may count down; increases, finite/infinite
changes and transitions through zero refuse. Preferred lifetime cannot exceed
valid lifetime, and partial/malformed lifetime pairs refuse. Only these numeric
countdowns are normalized: raw observations remain unchanged, while address,
prefix, scope, flags/deprecation, interface/name/master, inventory, route, link
and all other field changes still refuse. Unknown fields are never discarded.
No retry or sleep bypasses the two-snapshot guard.

A dry-run never writes state, registers/signals workers or mutates the backend.
`eligible: true` is **not** apply authorization. Review the exact plan digest,
target, observations, claims and assumptions, then obtain separate explicit
operator approval before invoking any apply. Source root identity is privately
bound into the plan, not published as a location. Apply requires the same
arguments with `--apply`, `--plan APPROVED_SHA256`, and
`--accept-profile direct-standard-libvirt-network-tail-v1`; dry-run rejects apply
acceptance options, and default/no-profile apply is rejected.

The accepted assumptions explicitly trust the standard running packaged
libvirt driver to perform its normal firewall/helper teardown, just as ordinary
backend cleanup does. They also exclude detaching hooks, untracked writers,
external automation/recreation, historical UUID/name/bridge reuse and filtered
host views. These are operator-accepted assumptions, not hidden measurements.
The resulting claim is `normal-libvirt-api-teardown-reconciliation` with
`original_destroy_completed: false`, independent firewall/helper verification
`unverified`, and loaded-image attestation `unverified`. It claims neither
universal host cleanup nor generic RPC draining.

Apply requalifies the exact plan before writing additive recovery intent. A
gated measured-interpreter worker is journalled before it may run; its sole
mutation grammar is synchronous `net-destroy` of the exact UUID—never guest,
disk, foreign-network, define/undefine, firewall or service mutation. It repeats
source/controller/runtime/writer/target proofs and fresh dependency snapshots.
The parent must actually observe successful child exit and independently prove
all recorded sessions empty plus fresh API UUID/name absence and kernel
bridge/address/subnet-route absence. A durable parent settlement receipt precedes
allocator-last terminal publication. The original incomplete operation and its
missing seal remain untouched; stale mappings are cleared only at terminal
settlement.

Timeout, query/mutation uncertainty, source/runtime/plan drift or failed
settlement persistence retains the nonterminal record and does not automatically
retry or signal anything. Intent/worker-only receipts require operator review;
they cannot be adopted as parent success. An uncertain terminal replace/fsync
reports `terminal_commit_unconfirmed`,
`allocator_may_already_be_released: true`, and `fresh_inspection_required: true`,
without speculative rollback. Explicit reconfirmation requires current proofs
again, not trust in a saved absence receipt. Terminal reconfirmation never
revives a cleaned generation.

#### General supervised commands

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

### Recorded guest-control and network-tail acceptance

On 2026-11-23, direct guest-control checks passed but final network cleanup was
blocked by foreign domains referencing an absent network. On 2026-11-24, the
tester recorded the following subsequent, separately scoped results:

| Mode / generation | Observed result |
| --- | --- |
| Approved rootless reconciliation / `a95147c2-8114-4cd9-9f88-f0faf3a49c73` | Standard-libvirt reconciliation passed and released the allocation. The original destroy remains unsealed and its history is preserved; this is not an ordinary destroy pass or independent firewall/helper attestation. |
| Fresh direct `kvm-forward` / `c109cc44-ee1a-4578-b910-d9cb416285af` | Molecule create/verify/destroy passed; ordinary cleanup was sealed and cleaned, with creation-time ownership provenance. |
| Fresh supervised `kvm-supervised-control` / `95f5eef2-ad1f-4332-b029-eefb2f864c35` | `test-run run --backend kvm` passed the full implemented standard sequence, stop/start, SSH and 1 GiB data-disk checks. Cleanup was sealed and cleaned; all recorded sessions were empty. |

The existing current controller used Python 3.12.16, Ansible Core 2.20.8 and
Molecule 26.8.0 with an existing Rocky Linux 9 qcow2 image. No image
build/download, sudo or dependency installation was needed. The tested source
was `9c2cabe6430439035c322efdaf93754e4da1a5cf` **plus uncommitted helper changes**,
before this documentation update—not a subsequently created commit.
Recorded code SHA-256 fingerprints were:

| Relative source | Tested SHA-256 |
| --- | --- |
| `scripts/isolated_runs/guest_control.py` | `1819e9607868b9a6f346aad3fdcf476a949ecb827bb0052505dfdd872e59176d` |
| `scripts/isolated_runs/backends.py` | `28aad734ea07457021b05a8877a1519b96cc6ba3d6e2f353618e239dbf760c93` |
| `scripts/isolated_runs/network_references.py` | `bc47dbd4aa0007ea30bea51cb115bffdb013f97641da9ae736f8661a21b34d7e` |

Portable invocation shapes, with the existing current controller activated:

```bash
# From the fixture role:
molecule create -s kvm-forward
molecule verify -s kvm-forward
molecule destroy -s kvm-forward

# From this helper checkout:
scripts/test-run run --backend kvm --scenario kvm-supervised-control /path/to/fixture-role
```

Reconciliation used the separately approved
[standard-libvirt profile](#opt-in-standard-libvirt-network-tail-reconciliation),
not a blind destroy retry. These results establish only the bounded helper
scope above. Host-mutation interruption/cancellation, broader OS/controller
coverage, GUI sessions and PostgreSQL role acceptance remain unverified by
this record. Raw runtime artifacts and fixture keys are not repository content.

### Quoted dependency hard-failure acceptance

On 2026-11-24, the tester recorded exit 0 for PostgreSQL
`kvm-hard-patroni-failure` with Core 2.20.8, Molecule 26.8.0 and three ephemeral
Rocky Linux 9 guests installed from an existing ISO.

| Generation | Observed result |
| --- | --- |
| `bc20d375-46a0-454e-b4fa-718dad6fff91` | Create/prepare/converge/idempotence (all `changed=0` on the idempotence pass)/verify/destroy passed. Leader `pg01` was abruptly stopped (`changed=true`, `shut-off`), and `pg03` was promoted. Restart returned `changed=true`, `running` for the same domain UUID `d2e1f3db-1947-4552-963b-cde5d8efcd4e`; the old leader rejoined as a replica. Before/after SQL markers were verified. Create/stop/start/destroy were sealed, the generation was authoritatively cleaned and all eight sessions were gone. No force, recovery or sudo was used. |

Tested helper source was `f9f0b7bd1af671035eb5e6fb5959826392acac4f`
**plus the uncommitted normalizer fix**; `guest_control.py` SHA-256 was
`c948843e33dfb78d6eae6328bbaac65fe91a2e7dffd8ea4f6a081c6720f4c998`.
Tested role source was `45f3547` plus uncommitted role changes. This evidence
precedes this documentation/follow-up commit; it does not claim execution at a
later commit, broader role/OS/GUI coverage or host-mutation cancellation safety.
The historical producing-source qualification and rootless reconciliation
profile remain unchanged; no snapshot fingerprints were updated for this fix.

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
