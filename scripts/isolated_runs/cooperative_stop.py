"""Close admission and drain sealed mutations before signalling their sessions."""

import sys
import time

from . import admission
from .state import RunError, Store, lock

MUTATION_DRAIN_TIMEOUT = 120
_CREATE_CHECKPOINTS = frozenset({"before-network", "before-guest", "guest-readiness"})


class CreateStopped(RunError):
    """Internal checkpoint after settled host commands, never an RPC failure."""

    def __init__(self, run_id: str, checkpoint: str) -> None:
        super().__init__("Create stopped at a completed host-command boundary")
        self.run_id = run_id
        self.checkpoint = checkpoint


def check_create_stop(store: Store, data: dict, checkpoint: str) -> None:
    """Only supervised creates opt into closed-gate checkpoints."""
    if "admission_protocol" not in data:
        return
    if (
        data.get("mode") != "supervised"
        or data.get("status") != "running"
        or data.get("mutation_protocol") != "sealed-v1"
        or data.get("admission_protocol") != admission.PROTOCOL
        or checkpoint not in _CREATE_CHECKPOINTS
    ):
        raise RunError("Invalid cooperative create checkpoint")
    if admission.gate(store, data["id"])["state"] == "closed":
        raise CreateStopped(data["id"], checkpoint)


def seal_stopped_create(store: Store, run_id: str, operation_id: str, stopped: CreateStopped) -> None:
    """Caller holds resources; seal a stopped mutation, not a successful create."""
    data = store.load(run_id)
    operation = data["operations"][-1]
    if (
        not isinstance(stopped, CreateStopped) or stopped.run_id != run_id
        or stopped.checkpoint not in _CREATE_CHECKPOINTS
        or data.get("mode") != "supervised" or data.get("status") != "running"
        or data.get("mutation_protocol") != "sealed-v1"
        or data.get("admission_protocol") != admission.PROTOCOL
        or admission.gate(store, run_id)["state"] != "closed"
        or operation["id"] != operation_id or operation["action"] != "create"
        or operation.get("completion") is not None
        or operation.get("worker") not in data["workers"]
        or operation["worker"] != admission.registered_current(data)
    ):
        raise RunError("Invalid stopped-create completion binding")
    operation.update(completion=operation_id, outcome="stopped", stop_checkpoint=stopped.checkpoint)
    data.pop("instances_ready", None)
    store.save(data)


def validate_stopped_seal(data: dict, operation: dict) -> None:
    """Distinguish a completed stop checkpoint from an arbitrary failure seal."""
    if (
        data.get("mode") != "supervised"
        or data.get("admission_protocol") != admission.PROTOCOL
        or data.get("mutation_protocol") != "sealed-v1"
        or operation["action"] != "create"
        or operation.get("stop_checkpoint") not in _CREATE_CHECKPOINTS
        or operation.get("completion") != operation["id"]
    ):
        raise RunError("Invalid stopped-create seal")


def drain_mutations(store: Store, run_id: str, timeout: float = MUTATION_DRAIN_TIMEOUT) -> dict:
    """Caller owns the supervisor lock; never cancel a mutation to obtain a seal.

    The resource lock covers the entire admitted host mutation, including its
    final durable completion write. Admission is closed *before* waiting, so no
    queued lifecycle helper may start another mutation after the lock is freed.
    Acquiring the lock is not itself completion evidence: all seals are checked.
    Timeout, failed writes and backend errors retain both resources and lease.
    """
    from .context import require_completed

    data = admission.close(store, run_id)
    if data.get("mode") != "supervised" or data.get("mutation_protocol") != "sealed-v1":
        raise RunError("Cooperative stop requires supervised sealed mutations")
    deadline = time.monotonic() + timeout
    announced = False
    while True:
        try:
            with lock(store.directory(run_id) / ".resources.lock", blocking=False):
                data = store.load(run_id)
                if (
                    data.get("mode") != "supervised"
                    or data.get("mutation_protocol") != "sealed-v1"
                    or data.get("admission_protocol") != admission.PROTOCOL
                    or admission.gate(store, run_id)["state"] != "closed"
                ):
                    raise RunError("Cooperative stop binding changed")
                require_completed(data, quiescent=False)
                return data
        except RunError as exc:
            # An unsafe lock, an incomplete seal or malformed state must not be
            # mistaken for an active mutation we can simply wait out.
            if not isinstance(exc.__cause__, BlockingIOError):
                raise
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RunError(
                "Active host mutation did not drain before the stop deadline; "
                "no worker signals or resource deletion attempted; retain resources and lease. "
                "After the mutation completes, retry exact-run cleanup; "
                "an incomplete mutation still requires backend-specific recovery."
            )
        if not announced:
            print(
                "Stop/cleanup: admission closed; waiting up to "
                f"{timeout:g} s for the active host mutation to complete before signalling workers.",
                file=sys.stderr, flush=True,
            )
            announced = True
        time.sleep(min(0.1, remaining))
