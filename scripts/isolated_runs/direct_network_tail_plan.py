"""Pure historical-checkpoint bindings, never sufficient recovery authority alone.

Not wired into CLI eligibility. Source byte definition is approved separately;
runtime and terminal checks belong to the separate opt-in standard profile.
"""

import hashlib
import json
import re

from .direct_network_tail import validate_record
from .state import RunError

PROFILE = "direct-empty-checkpoint-network-tail-v1"


def canonical_bytes(value) -> bytes:
    """Serialize only exact JSON types, preserving distinctions such as true vs 1."""
    def validate(item):
        if item is None or type(item) in (bool, int, str):
            return
        if type(item) is list:
            for child in item:
                validate(child)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                validate(child)
            return
        raise RunError("unsupported_checkpoint_value_type")

    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def checkpoint_binding(data: dict, identity: dict, operation_id: str) -> dict:
    """Validate the narrow historical shape and snapshot its immutable evidence.

    This proves only record compatibility. It neither attributes historical
    execution to source bytes nor measures resource/process/daemon absence.
    """
    canonical_bytes(data)
    canonical_bytes(identity)
    validate_record(data, identity, operation_id)
    if type(data["version"]) is not int or type(data["uid"]) is not int:
        raise RunError("unsupported_checkpoint_value_type")
    history = data["operations"]
    if (
        len(history) < 2 or history[0]["action"] != "create"
        or any(operation["action"] not in ("guest-stop", "guest-start") for operation in history[1:-1])
        or data["workers"] != [operation["worker"] for operation in history]
        or len({worker["boot"] for worker in data["workers"]}) != 1
    ):
        raise RunError("unsupported_historical_checkpoint_history")
    for operation in history[1:-1]:
        if set(operation["result"]) != {"action", "guest", "operation", "changed", "state"}:
            raise RunError("unsupported_historical_guest_result")
    binding = {
        "profile": PROFILE, "generation": data["id"], "operation": operation_id,
        "direct_identity": identity, "direct_context": data["direct_context"],
        "configuration": data["config"], "context": data["context"],
        "original_operations": history, "original_workers": data["workers"],
        "original_network": data["network"], "subnet": data["subnet"],
        "original_stale_instance_mapping": data.get("instances_ready"),
        "checkpoint": "durable-empty-guests-historical-removal-conditional-on-source-attribution",
        "not_claimed": [
            "fresh-original-guest-or-disk-identity-absence",
            "historical-rpc-trace-or-generic-drain",
            "current-source-is-historical-execution-proof",
        ],
    }
    # A serialization round-trip returns a detached snapshot, never aliases
    # caller-owned mutable history, configuration, workers or network objects.
    return json.loads(canonical_bytes(binding))


def binding_digest(binding: dict) -> str:
    return hashlib.sha256(canonical_bytes(binding)).hexdigest()


def assert_unchanged(expected_digest: str, data: dict, identity: dict, operation_id: str) -> None:
    """Reject every bound content/type change; this grants no recovery authority."""
    if (
        type(expected_digest) is not str or not re.fullmatch(r"[a-f0-9]{64}", expected_digest)
        or binding_digest(checkpoint_binding(data, identity, operation_id)) != expected_digest
    ):
        raise RunError("historical_checkpoint_binding_changed")


def assess_checkpoint(data: dict, identity: dict, operation_id: str) -> dict:
    """Expose a draft checkpoint assessment, explicitly never an eligible plan."""
    binding = checkpoint_binding(data, identity, operation_id)
    return {
        "profile": PROFILE, "checkpoint_history_compatible": True,
        "checkpoint_binding_digest": binding_digest(binding),
        "eligible": False, "apply_authorized": False, "lease_release_authorized": False,
        "blockers": [
            "verified_approved_producing_source_receipt_required",
            "standard_runtime_qualification_and_parent_settlement_required",
        ],
    }
