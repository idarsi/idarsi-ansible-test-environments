"""Close admission and drain sealed mutations before signalling their sessions."""

import sys
import time

from . import admission
from .state import RunError, Store, lock

MUTATION_DRAIN_TIMEOUT = 120


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
