"""Combined proof/control-history fixtures; no VM, SSH or mutation API calls."""

import contextlib
import copy
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid

import test_isolated_guest_validation as fixture
from isolated_runs import admission, cooperative_stop, guest_control, guest_validation as guest
from isolated_runs.backends import kvm_instance
from isolated_runs.guest_refusal import GuestRefusal
from isolated_runs.state import atomic_json


class CombinedProofTests(unittest.TestCase):
    setUp = fixture.GuestTests.setUp
    invoke = fixture.GuestTests.invoke
    query = fixture.GuestTests.query
    relocate_config = fixture.GuestTests.relocate_config

    def supervised(self):
        self.ephemeral = self.store.ephemeral(self.run_id)
        (self.ephemeral / "inventory").mkdir(mode=0o700)
        (self.ephemeral / "state.yml").write_text("{}")
        (self.ephemeral / "state.yml").chmod(0o600)
        self.config = self.relocate_config(self.ephemeral)
        self.artifact = self.ephemeral / "instance_config.yml"
        atomic_json(self.artifact, self.instances)
        os.environ.update(
            MOLECULE_EPHEMERAL_DIRECTORY=str(self.ephemeral),
            MOLECULE_INSTANCE_CONFIG=str(self.artifact),
            IDARSI_RUN_ID=self.run_id, IDARSI_HANDOFF="v1",
        )
        self.data.update(
            mode="supervised", mutation_protocol="sealed-v1",
            admission_protocol=admission.PROTOCOL, config=copy.deepcopy(self.config),
        )
        atomic_json(self.store.directory(self.run_id) / "admission.json",
                    {"version": 1, "id": self.run_id, "state": "open"})
        self.store.save(self.data)

    def ancestry(self):
        return patch.object(admission, "prove_sessions", side_effect=lambda data: (
            contextlib.nullcontext([data["workers"][0], {"pid": 456, "start": "2", "boot": "fixture"}])
        ))

    def operation(self, action, *, changed=True, logical="node"):
        target = next(item for item in self.data["guests"] if item["logical"] == logical)
        identity = str(uuid.uuid4())
        return {
            "id": identity, "action": action, "completion": identity,
            "protocol": guest_control.PROTOCOL, "guest": logical, "domain_uuid": target["id"],
            "worker": self.data["workers"][0],
            "result": {
                "operation": identity, "guest": logical, "action": action, "changed": changed,
                "state": "shut-off" if action == "guest-stop" else "running",
            },
        }

    def snapshot(self):
        result = {}
        for root in (self.store.root, self.ephemeral):
            for path in (root, *root.rglob("*")):
                info = path.lstat()
                result[str(path)] = (
                    info.st_mode, info.st_uid, info.st_gid, info.st_ino, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                    path.read_bytes() if path.is_file() else None,
                )
        return result

    def roundtrip(self):
        self.assertTrue(self.invoke()["validated"])
        stopped = self.operation("guest-stop")
        self.data["operations"].append(stopped)
        self.store.save(self.data)
        self.state = "shut off"
        before = self.snapshot()
        with self.assertRaises(GuestRefusal) as refused:
            self.invoke()
        self.assertEqual(refused.exception.code, "NATIVE_IDENTITY")
        self.assertEqual(before, self.snapshot())
        self.data["operations"].append(self.operation("guest-start"))
        self.store.save(self.data)
        self.state = "running"
        before = self.snapshot()
        self.assertTrue(self.invoke()["validated"])
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.store.load(self.run_id)["instances_ready"], self.instances)

    def test_direct_create_stop_refusal_start_proof_is_read_only(self):
        self.roundtrip()

    def test_supervised_create_stop_refusal_start_proof_never_registers(self):
        self.supervised()
        with self.ancestry(), patch.object(
            admission, "registered_current", side_effect=AssertionError("registration forbidden"),
        ):
            self.roundtrip()

    def test_cooperative_stop_drain_never_turns_stopped_create_into_guest_proof(self):
        self.supervised()
        original = copy.deepcopy(self.data)
        for checkpoint in ("before-network", "before-guest", "guest-readiness"):
            for ready in (False, True):
                with self.subTest(checkpoint=checkpoint, stale_ready_mapping=ready):
                    self.data = copy.deepcopy(original)
                    self.data["operations"][0].pop("completion")
                    self.store.save(self.data)
                    with patch.object(admission, "registered_current", return_value=self.data["workers"][0]):
                        admission.close(self.store, self.run_id)
                        cooperative_stop.seal_stopped_create(
                            self.store, self.run_id, "op",
                            cooperative_stop.CreateStopped(self.run_id, checkpoint),
                        )
                    self.data = self.store.load(self.run_id)
                    self.assertNotIn("instances_ready", self.data)
                    self.assertEqual("running", self.data["status"])
                    if ready:
                        # Even a stale mapping and independently readable open
                        # gate cannot promote a stopped seal to successful create.
                        self.data["instances_ready"] = copy.deepcopy(self.instances)
                        self.store.save(self.data)
                        atomic_json(self.store.directory(self.run_id) / "admission.json",
                                    {"version": 1, "id": self.run_id, "state": "open"})
                        before = self.snapshot()
                        with self.ancestry(), patch.object(
                            admission, "registered_current", side_effect=AssertionError("registration forbidden"),
                        ), self.assertRaises(GuestRefusal) as refused:
                            self.invoke()
                        self.assertEqual("NATIVE_IDENTITY", refused.exception.code)
                        self.assertEqual(before, self.snapshot())
                    drained = cooperative_stop.drain_mutations(self.store, self.run_id)
                    self.assertEqual(self.data, drained)
                    before = self.snapshot()
                    with self.ancestry(), patch.object(
                        admission, "registered_current", side_effect=AssertionError("registration forbidden"),
                    ), self.assertRaises(GuestRefusal):
                        self.invoke()
                    self.assertEqual(before, self.snapshot())
                    # Check the history boundary independently of closed admission.
                    with self.assertRaises(GuestRefusal):
                        guest.binding(self.data, self.args)

    def test_drain_refuses_interrupted_create_without_inferring_absence_is_clean(self):
        self.supervised()
        self.data["operations"][0].pop("completion")
        self.data.pop("instances_ready")
        self.data["guests"] = []
        self.data["network"] = None
        self.store.save(self.data)
        admission.close(self.store, self.run_id)
        before = self.snapshot()
        with self.assertRaisesRegex(fixture.RunError, "Incomplete mutation"):
            cooperative_stop.drain_mutations(self.store, self.run_id)
        with self.ancestry(), self.assertRaises(GuestRefusal):
            self.invoke()
        self.assertEqual(before, self.snapshot())
        self.assertEqual("running", self.store.load(self.run_id)["status"])
        self.assertEqual([], self.queries)

    def test_closed_admission_after_successful_create_refuses_proof_read_only(self):
        self.supervised()
        self.data["operations"].extend([
            self.operation("guest-stop"), self.operation("guest-start"),
        ])
        self.store.save(self.data)
        cooperative_stop.drain_mutations(self.store, self.run_id)
        before = self.snapshot()
        with self.ancestry(), patch.object(
            admission, "registered_current", side_effect=AssertionError("registration forbidden"),
        ), self.assertRaises(GuestRefusal) as refused:
            self.invoke()
        self.assertEqual("AUTHORITY_PARSE", refused.exception.code)
        self.assertEqual(before, self.snapshot())
        self.assertEqual([], self.queries)

    def test_completed_noops_and_other_guest_history_do_not_invalidate_target(self):
        platform = {**self.config["platforms"][0], "name": "peer"}
        self.config["platforms"].append(platform)
        peer = copy.deepcopy(self.data["guests"][0])
        peer.update(logical="peer", id=str(uuid.uuid4()), name="itr-" + uuid.uuid4().hex)
        self.data["guests"].append(peer)
        self.instances.append(kvm_instance(platform, self.data["subnet"], 1, self.key))
        atomic_json(self.artifact, self.instances)
        self.data["config"] = copy.deepcopy(self.config)
        for logical in ("node", "peer"):
            self.data["operations"].extend([
                self.operation("guest-stop", changed=False, logical=logical),
                self.operation("guest-start", changed=False, logical=logical),
            ])
        self.store.save(self.data)
        before = self.snapshot()
        self.assertTrue(self.invoke()["validated"])
        self.assertEqual(before, self.snapshot())
        self.supervised()
        with self.ancestry():
            before = self.snapshot()
            self.assertTrue(self.invoke()["validated"])
            self.assertEqual(before, self.snapshot())

    def invalid_histories(self):
        create = copy.deepcopy(self.data["operations"][0])
        stop = self.operation("guest-stop")
        start = self.operation("guest-start")
        histories = [
            [], [stop, create], [create, create], [create, {**start, "action": "destroy"}],
            [create, {**stop, "action": "unknown"}], [create, {**stop, "completion": None}],
            [create, {**stop, "protocol": "unsealed"}],
            [create, {**stop, "worker": {"pid": 999, "start": "1", "boot": "fixture"}}],
            [create, {**stop, "worker": {}}],
            [create, {**stop, "domain_uuid": str(uuid.uuid4())}],
            [create, {**stop, "guest": "unknown"}],
            [create, {**stop, "result": {**stop["result"], "operation": start["id"]}}],
            [create, {**stop, "result": {**stop["result"], "changed": 1}}],
            [create, {**stop, "result": {**stop["result"], "state": "running"}}],
            [create, stop, stop], [create, None],
            [{**create, "worker": {}}],
            [{**create, "completion": None}],
        ]
        for history in histories:
            self.data["operations"] = history
            self.store.save(self.data)
            before = self.snapshot()
            with self.subTest(history=history), self.assertRaises(GuestRefusal):
                self.invoke()
            self.assertEqual(before, self.snapshot())
        self.data["operations"] = [create]
        self.store.save(self.data)

    def test_direct_and_supervised_reject_unsupported_or_unsealed_history(self):
        self.invalid_histories()
        self.supervised()
        with self.ancestry():
            self.invalid_histories()

    def stale_mappings(self):
        for mapping in (None, [], [{**self.instances[0], "user": "foreign"}]):
            if mapping is None:
                self.data.pop("instances_ready", None)
            else:
                self.data["instances_ready"] = mapping
            self.store.save(self.data)
            before = self.snapshot()
            with self.subTest(mapping=mapping), self.assertRaises(GuestRefusal):
                self.invoke()
            self.assertEqual(before, self.snapshot())
        self.data["instances_ready"] = self.instances
        self.store.save(self.data)

    def test_both_modes_require_exact_published_mapping_not_artifact_alone(self):
        self.stale_mappings()
        self.supervised()
        with self.ancestry():
            self.stale_mappings()

    def test_main_typed_comparator_handles_quoted_relocation_and_preserves_differences(self):
        self.supervised()
        current_root = str(self.ephemeral)
        old_root = str(self.root / "planning root with spaces")
        original = self.relocate_config(Path(old_root))
        for config, root in ((self.config, current_root), (original, old_root)):
            config["dependency"] = {"command": (
                'python3 dependency.py --ephemeral-directory "' + root
                + '" --molecule-file \'' + root + "/molecule.yml' --other literal"
            )}
        self.data["config"] = original
        self.store.save(self.data)
        with self.ancestry():
            self.assertTrue(self.invoke()["validated"])
            baseline = copy.deepcopy(self.config)
            for update in (
                {"_idarsi_effective_ephemeral": current_root + "-foreign"},
                {"dependency": {"command": self.config["dependency"]["command"].replace("--other literal", "--other changed")}},
                {"literal": current_root + "/../traversal"},
                {"literal": current_root + "-foreign/file"},
                {"literal": ["idarsi.ephemeral-path/v1", "/file"]},
                {"_idarsi_effective_env": {**self.config["_idarsi_effective_env"], "UNRELATED": "changed"}},
            ):
                self.config = {**copy.deepcopy(baseline), **update}
                with self.subTest(update=update), self.assertRaises(GuestRefusal):
                    self.invoke()
            self.config = baseline
            # Both sides contain a traversal: unlike relocation, it stays literal.
            for suffix in ("/../outside", "/a/../inside"):
                self.data["config"] = {**copy.deepcopy(original), "literal": old_root + suffix}
                self.config = {**copy.deepcopy(baseline), "literal": current_root + suffix}
                self.store.save(self.data)
                with self.subTest(suffix=suffix), self.assertRaises(GuestRefusal):
                    self.invoke()


if __name__ == "__main__":
    unittest.main()
