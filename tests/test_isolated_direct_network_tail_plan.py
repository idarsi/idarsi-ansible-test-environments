"""Pure pending-contract checks; no filesystem, process or backend fixtures."""

import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import context, direct_network_tail_plan as draft
from isolated_runs.state import RunError


class CheckpointDraftTests(unittest.TestCase):
    def setUp(self):
        generation, boot, create, self.operation, network = [str(uuid.uuid4()) for _ in range(5)]
        self.identity = {
            "role": "/example/role", "scenario": "kvm-example", "backend": "kvm",
            "ephemeral_directory": "/example/ephemeral",
        }
        self.workers = [
            {"pid": 987650 + index, "start": str(index + 1), "boot": boot} for index in range(2)
        ]
        self.data = {
            "version": 1, "uid": os.getuid(), "id": generation, "mode": "direct",
            "backend": "kvm", "status": "running", "context_publication": "published",
            "role": self.identity["role"], "scenario": self.identity["scenario"],
            "direct_identity": self.identity,
            "direct_context": dict(
                self.identity, schema=context.SCHEMA, mode="direct", generation=generation,
                collections_directory="/example/ephemeral/collections",
            ),
            "context": {"libvirt": "qemu:///system"}, "subnet": "10.99.0.0/24",
            "network": {"id": network, "name": "itr-" + network.replace("-", "")[:24]},
            "guests": [], "workers": self.workers,
            "config": {
                "_idarsi_effective_role": self.identity["role"],
                "_idarsi_effective_scenario": self.identity["scenario"],
                "_idarsi_effective_ephemeral": self.identity["ephemeral_directory"],
                "_idarsi_effective_env": {
                    "MOLECULE_PROJECT_DIRECTORY": self.identity["role"],
                    "MOLECULE_SCENARIO_DIRECTORY": "/example/role/molecule/kvm-example",
                    "MOLECULE_EPHEMERAL_DIRECTORY": self.identity["ephemeral_directory"],
                },
                "platforms": [{"name": "database"}],
            },
            "instances_ready": [{"instance": "database"}],
            "operations": [
                {"id": create, "action": "create", "worker": self.workers[0], "completion": create},
                {"id": self.operation, "action": "destroy", "worker": self.workers[1]},
            ],
        }

    def test_compatible_checkpoint_is_not_eligible_and_requires_pending_reviews(self):
        before = copy.deepcopy(self.data)
        with patch("os.open") as opened, patch("subprocess.run") as command, \
                patch("isolated_runs.processes.process") as process:
            result = draft.assess_checkpoint(self.data, self.identity, self.operation)
            opened.assert_not_called()
            command.assert_not_called()
            process.assert_not_called()
        self.assertTrue(result["checkpoint_history_compatible"])
        self.assertFalse(result["eligible"])
        self.assertFalse(result["apply_authorized"])
        self.assertFalse(result["lease_release_authorized"])
        self.assertEqual(len(result["blockers"]), 2)
        self.assertNotIn("plan", result)
        self.assertNotIn("plan_digest", result)
        self.assertEqual(self.data, before)

    def test_binding_is_detached_from_caller_mutable_objects_and_detects_drift(self):
        binding = draft.checkpoint_binding(self.data, self.identity, self.operation)
        expected = draft.binding_digest(binding)
        draft.assert_unchanged(expected, self.data, self.identity, self.operation)
        self.data["instances_ready"][0]["address"] = "changed-not-authority"
        self.assertNotIn("address", binding["original_stale_instance_mapping"][0])
        self.assertEqual(draft.binding_digest(binding), expected)
        with self.assertRaisesRegex(RunError, "binding_changed"):
            draft.assert_unchanged(expected, self.data, self.identity, self.operation)

    def test_history_requires_one_create_no_preceding_destroy_and_exact_workers(self):
        for action in ("create", "destroy"):
            data = copy.deepcopy(self.data)
            identity = str(uuid.uuid4())
            operation = {"id": identity, "action": action, "completion": identity, "worker": self.workers[0]}
            data["operations"].insert(1, operation)
            with self.subTest(action=action), self.assertRaises(RunError):
                draft.checkpoint_binding(data, self.identity, self.operation)
        data = copy.deepcopy(self.data)
        data["workers"].append({"pid": 987660, "start": "3", "boot": self.workers[0]["boot"]})
        with self.assertRaisesRegex(RunError, "checkpoint_history"):
            draft.checkpoint_binding(data, self.identity, self.operation)
        data = copy.deepcopy(self.data)
        data["workers"][1]["boot"] = str(uuid.uuid4())
        with self.assertRaisesRegex(RunError, "checkpoint_history"):
            draft.checkpoint_binding(data, self.identity, self.operation)

    def insert_guest_operation(self):
        operation_id = str(uuid.uuid4())
        worker = {"pid": 987660, "start": "3", "boot": self.workers[0]["boot"]}
        operation = {
            "id": operation_id, "action": "guest-stop", "worker": worker,
            "completion": operation_id, "protocol": context.guest_control.PROTOCOL,
            "guest": "database", "domain_uuid": str(uuid.uuid4()),
            "result": {
                "action": "guest-stop", "guest": "database", "operation": operation_id,
                "changed": True, "state": "shut-off",
            },
        }
        self.data["workers"].insert(-1, worker)
        self.data["operations"].insert(-1, operation)
        return operation

    def test_sealed_guest_controls_are_bound_but_malformed_results_refuse(self):
        operation = self.insert_guest_operation()
        draft.checkpoint_binding(self.data, self.identity, self.operation)
        expected = draft.binding_digest(draft.checkpoint_binding(self.data, self.identity, self.operation))
        operation["result"]["changed"] = False
        with self.assertRaisesRegex(RunError, "binding_changed"):
            draft.assert_unchanged(expected, self.data, self.identity, self.operation)
        for result in (dict(operation["result"], changed=1), dict(operation["result"], extra="unknown")):
            operation["result"] = result
            with self.assertRaises(RunError):
                draft.checkpoint_binding(self.data, self.identity, self.operation)
        operation.pop("completion")
        with self.assertRaises(RunError):
            draft.checkpoint_binding(self.data, self.identity, self.operation)

    def test_exact_json_types_do_not_equate_boolean_and_integer_or_accept_float(self):
        self.assertNotEqual(draft.canonical_bytes({"value": True}), draft.canonical_bytes({"value": 1}))
        for value in (1.0, float("nan"), {"value": object()}, {1: "not-string-key"}):
            with self.subTest(value=type(value).__name__), self.assertRaisesRegex(RunError, "value_type"):
                draft.canonical_bytes(value)
        self.data["version"] = True
        with self.assertRaisesRegex(RunError, "value_type"):
            draft.checkpoint_binding(self.data, self.identity, self.operation)

    def test_no_caller_source_receipt_or_acceptance_can_grant_authority(self):
        with self.assertRaises(TypeError):
            draft.assess_checkpoint(self.data, self.identity, self.operation, accept_profile=draft.PROFILE)
        with self.assertRaises(TypeError):
            draft.assess_checkpoint(self.data, self.identity, self.operation, producing_source_digest="0" * 64)
        for digest in ("", "A" * 64, "0" * 63, "0" * 64):
            with self.subTest(digest=digest[:4]), self.assertRaises(RunError):
                draft.assert_unchanged(digest, self.data, self.identity, self.operation)


if __name__ == "__main__":
    unittest.main()
