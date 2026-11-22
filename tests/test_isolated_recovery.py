"""Recovery unit checks: temporary private Stores and fake host/backend evidence."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import admission, cli, context, network_recovery, recovery, recovery_host
from isolated_runs.state import RunError, Store, existing_lock

OLD_BOOT = "11111111-1111-4111-8111-111111111111"
NEW_BOOT = "22222222-2222-4222-8222-222222222222"
MACHINE = "1234567890abcdef1234567890abcdef"
ABSENT = {"network": "absent", "kernel": "absent", "helpers": "absent", "mutation": False}
REAL_CONTEXT = recovery.trusted_context


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = Store(self.root / "state")
        self.data = self.store.allocate("kvm", {"libvirt": "qemu:///system"}, lambda: [], self.root, "kvm-fixture")
        self.worker = {"pid": 987654, "boot": OLD_BOOT, "start": "1234"}
        create_id, self.operation = str(uuid.uuid4()), str(uuid.uuid4())
        network_id = str(uuid.uuid4())
        self.data.update(
            mode="supervised", mutation_protocol="sealed-v1", admission_protocol="session-v1",
            status="cleaning", workers=[self.worker], config={},
            network={"id": network_id, "name": "itr-" + network_id.replace("-", "")[:24]},
            operations=[
                {"id": create_id, "action": "create", "worker": self.worker, "completion": create_id},
                {"id": self.operation, "action": "destroy", "worker": self.worker, "purpose": "supervisor-cleanup"},
            ],
        )
        self.run_id = self.data["id"]
        self.store.save(self.data)
        admission.initialize(self.store, self.run_id)
        for path in (
            self.store.directory(self.run_id) / ".supervisor.lock",
            self.store.directory(self.run_id) / ".resources.lock",
            self.store.root / ".storage-graph.lock",
        ):
            path.touch(mode=0o600)
        self.addCleanup(patch.stopall)
        patch.object(recovery, "trusted_context", return_value={
            "mode": "recorded_runtime_measured", "missing": [], "current": {"fixture": "trusted"},
        }).start()
        self.boot = patch.object(recovery, "boot_id", return_value=OLD_BOOT).start()
        patch.object(recovery_host, "machine_identity", return_value=MACHINE).start()
        patch.object(recovery, "persistent_store").start()
        self.stop = patch.object(recovery, "stop_workers").start()
        patch.object(recovery, "members", return_value=[]).start()
        self.verify = patch.object(network_recovery, "verify_absent", return_value=ABSENT).start()
        self.journal = patch.object(recovery_host, "boot_fence", side_effect=RunError("historical_host_identity_unproven")).start()

    def prepare(self):
        return recovery.prepare(self.store, self.run_id, self.operation)

    def new_boot(self):
        self.prepare()
        self.boot.return_value = NEW_BOOT

    def manifest_bytes(self):
        return (self.store.directory(self.run_id) / "manifest.json").read_bytes()

    def apply(self):
        return recovery.apply(self.store, self.run_id, self.operation)

    def test_same_boot_dry_run_is_nonwriting_and_explicit(self):
        before = {path: path.read_bytes() for path in self.store.directory(self.run_id).iterdir() if path.is_file()}
        result = recovery.inspect(self.store, self.run_id, self.operation)
        self.assertFalse(result["eligible"])
        self.assertTrue(result["maintenance_preparation_available"])
        self.assertEqual(result["blockers"], ["same_boot_not_fenced", "historical_hook_receipt_missing"])
        self.assertEqual(before, {path: path.read_bytes() for path in before})
        self.stop.assert_not_called()
        self.verify.assert_not_called()
        self.assertEqual(admission.gate(self.store, self.run_id)["state"], "open")

    def test_prepare_writes_only_additive_observation_idempotently(self):
        before = copy.deepcopy(self.data)
        result = self.prepare()
        self.assertTrue(result["audit_written"])
        self.assertFalse(result["reboot_authorized"])
        after = self.store.load(self.run_id)
        observation = after.pop("recoveries")["host_observation"]
        self.assertEqual(after, before)
        self.assertEqual(observation["boot"], OLD_BOOT)
        self.assertEqual(observation["machine"], MACHINE)
        saved = self.manifest_bytes()
        self.assertFalse(self.prepare()["audit_written"])
        self.assertEqual(saved, self.manifest_bytes())
        self.verify.assert_not_called()
        self.stop.assert_not_called()
        self.assertEqual(admission.gate(self.store, self.run_id)["state"], "open")

    def test_prepare_cannot_backfill_after_boot_change(self):
        self.boot.return_value = NEW_BOOT
        with self.assertRaisesRegex(RunError, "preparation_requires_original_current_boot"):
            self.prepare()
        self.assertNotIn("recoveries", self.store.load(self.run_id))

    def test_prepare_requires_all_original_workers_current(self):
        self.data["workers"].append({"pid": 987653, "start": "9", "boot": NEW_BOOT})
        self.store.save(self.data)
        with self.assertRaisesRegex(RunError, "preparation_requires_original_current_boot"):
            self.prepare()

    def test_prepare_requires_persistent_store(self):
        with patch.object(recovery, "persistent_store", side_effect=RunError("state_persistence_unproven")):
            with self.assertRaisesRegex(RunError, "state_persistence_unproven"):
                self.prepare()
        self.verify.assert_not_called()

    def test_prepare_rereads_kernel_before_commit(self):
        self.boot.side_effect = [OLD_BOOT, NEW_BOOT]
        with self.assertRaisesRegex(RunError, "host_identity_changed"):
            self.prepare()
        self.assertNotIn("recoveries", self.store.load(self.run_id))

    def test_same_boot_apply_never_closes_gate_or_stops(self):
        with self.assertRaisesRegex(RunError, "same_boot_not_fenced"):
            self.apply()
        self.stop.assert_not_called()
        self.verify.assert_not_called()
        self.assertEqual(admission.gate(self.store, self.run_id)["state"], "open")

    def test_postboot_absence_reconciles_without_original_seal_or_backend_mutation(self):
        self.new_boot()
        original_operations = copy.deepcopy(self.data["operations"])
        result = self.apply()
        data = self.store.load(self.run_id)
        self.assertEqual(result["outcome"], "reconciled")
        self.assertEqual(data["status"], "cleaned")
        self.assertIsNone(data["network"])
        self.assertEqual(data["operations"], original_operations)
        self.assertNotIn("completion", data["operations"][-1])
        self.assertEqual(data["workers"], [self.worker])
        self.assertEqual(data["recoveries"]["network"], self.data["network"])
        self.assertEqual(data["recoveries"]["attempts"][-1]["phase"], "reconciled")
        self.journal.assert_not_called()
        with patch.object(context, "members", return_value=[]):
            with self.assertRaisesRegex(RunError, "Incomplete mutation"):
                context.require_completed(data)
        # Old inspect sees V1 cleaned; ordinary cleanup is a no-op, not a new seal.
        with patch.object(cli, "Backend") as backend:
            cli.cleanup(self.store, self.run_id)
            backend.assert_not_called()
        self.assertEqual(self.apply()["outcome"], "reconciled")

    def test_postboot_dry_run_no_audit_or_gate_changes(self):
        self.new_boot()
        before = self.manifest_bytes()
        result = recovery.inspect(self.store, self.run_id, self.operation)
        self.assertTrue(result["eligible"])
        self.assertEqual(result["route"], "observed-host-boot")
        self.assertEqual(self.manifest_bytes(), before)
        self.assertEqual(admission.gate(self.store, self.run_id)["state"], "open")
        self.stop.assert_not_called()

    def test_postboot_changed_machine_retains_everything(self):
        self.new_boot()
        before = self.manifest_bytes()
        with patch.object(recovery_host, "machine_identity", return_value="0" * 32):
            with self.assertRaisesRegex(RunError, "historical_host_identity_unproven"):
                self.apply()
        self.assertEqual(before, self.manifest_bytes())
        self.stop.assert_not_called()

    def test_missing_observation_cannot_infer_host_from_path(self):
        self.boot.return_value = NEW_BOOT
        with self.assertRaisesRegex(RunError, "historical_host_identity_unproven"):
            self.apply()
        self.journal.assert_called_once()
        self.stop.assert_not_called()

    def test_verified_journal_is_alternative_to_observation(self):
        self.boot.return_value = NEW_BOOT
        self.journal.side_effect = None
        self.journal.return_value = {"route": "host-boot", "current_boot": NEW_BOOT}
        self.assertEqual(self.apply()["outcome"], "reconciled")

    def test_present_network_or_unknown_queries_never_release(self):
        for reason in (
            "current_mutation_profile_unavailable", "bridge_or_interface_remains",
            "network_helper_remains", "firewall_footprint_remains", "network_replaced",
            "kernel_query_incomplete",
        ):
            with self.subTest(reason=reason):
                self.boot.return_value = OLD_BOOT
                # Reusing prepare is safe only with identical original binding.
                self.prepare()
                self.boot.return_value = NEW_BOOT
                self.verify.side_effect = RunError(reason)
                with self.assertRaisesRegex(RunError, reason):
                    self.apply()
                data = self.store.load(self.run_id)
                self.assertNotEqual(data["status"], "cleaned")
                self.assertEqual(data["network"], self.data["network"])
                self.assertNotIn("completion", data["operations"][-1])

    def test_invalid_or_changed_original_evidence_refuses(self):
        changes = (
            ("guests", [{"id": "unknown"}]), ("storage_probe", None),
            ("backend", "podman"), ("mode", "direct"),
            ("mutation_protocol", "future"), ("admission_protocol", "future"),
        )
        for key, value in changes:
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data[key] = value
                self.store.save(data)
                with self.assertRaises(RunError):
                    self.prepare()
        self.store.save(self.data)
        self.prepare()
        for key in ("role", "scenario", "context", "subnet"):
            with self.subTest(binding=key):
                data = self.store.load(self.run_id)
                original = data[key]
                data[key] = {} if key == "context" else "changed"
                self.store.save(data)
                with self.assertRaisesRegex(RunError, "recovery_binding_changed"):
                    self.prepare()
                data[key] = original
                self.store.save(data)

    def test_unknown_recovery_record_and_tampered_observation_refuse(self):
        self.prepare()
        for mutation in (
            lambda record: record.update(protocol="future"),
            lambda record: record["host_observation"].update(binding="wrong"),
            lambda record: record["host_observation"].update(boot=NEW_BOOT),
            lambda record: record.update(unrecognized=True),
        ):
            data = self.store.load(self.run_id)
            original = copy.deepcopy(data)
            mutation(data["recoveries"])
            self.store.save(data)
            with self.assertRaises(RunError):
                self.prepare()
            self.store.save(original)

    def test_new_current_boot_worker_cannot_borrow_original_boot_receipt(self):
        self.new_boot()
        data = self.store.load(self.run_id)
        data["workers"].append({"pid": 987650, "start": "999", "boot": NEW_BOOT})
        self.store.save(data)
        with self.assertRaisesRegex(RunError, "recovery_worker_journal_changed"):
            self.apply()
        self.stop.assert_not_called()

    def test_worktree_alias_is_not_original_helper_binding(self):
        data = copy.deepcopy(self.data)
        data["config"] = {
            "_idarsi_effective_env": {"IDARSI_TEST_ENVIRONMENT": "/different-helper"},
            "_idarsi_effective_role": data["role"], "_idarsi_effective_scenario": data["scenario"],
            "provisioner": {"playbooks": {"create": "/wrong/create.yml", "destroy": "/wrong/destroy.yml"}},
        }
        with patch.object(recovery, "executing_context", return_value={"root": "/expected", "prefix": "/controller"}), \
                patch.object(recovery, "trusted_path", side_effect=lambda path: path), \
                self.assertRaisesRegex(RunError, "original_playbook_binding_changed"):
            REAL_CONTEXT(data)

    def test_wrong_target_and_malformed_worker_or_operations_refuse(self):
        for operation in (str(uuid.uuid4()), self.operation.upper(), "bad"):
            with self.subTest(operation=operation), self.assertRaises((RunError, ValueError)):
                recovery.prepare(self.store, self.run_id, operation)
        for mutate in (
            lambda data: data["operations"][0].pop("completion"),
            lambda data: data["operations"][-1].update(action="create"),
            lambda data: data["operations"][-1].update(completion="wrong"),
            lambda data: data["operations"][-1].update(worker={}),
            lambda data: data["workers"][0].update(boot="bad"),
            lambda data: data["workers"][0].update(pid=True),
        ):
            data = copy.deepcopy(self.data)
            mutate(data)
            self.store.save(data)
            with self.subTest(data=mutate), self.assertRaises((RunError, ValueError)):
                self.prepare()

    def test_crash_after_intent_repeats_proofs_not_stale_evidence(self):
        self.new_boot()
        with patch.object(admission, "close", side_effect=OSError("fixture crash")):
            with self.assertRaises(OSError):
                self.apply()
        self.assertEqual(self.store.load(self.run_id)["recoveries"]["attempts"][-1]["phase"], "intent")
        self.verify.side_effect = RunError("network_helper_remains")
        with self.assertRaisesRegex(RunError, "network_helper_remains"):
            self.apply()
        self.assertNotEqual(self.store.load(self.run_id)["status"], "cleaned")
        self.verify.side_effect = None
        self.assertEqual(self.apply()["outcome"], "reconciled")
        self.assertEqual(len(self.store.load(self.run_id)["recoveries"]["attempts"]), 3)

    def test_crash_after_resources_verified_repeats_absence_checks(self):
        self.new_boot()
        self.verify.side_effect = [ABSENT, RunError("bridge_or_interface_remains")]
        with self.assertRaisesRegex(RunError, "bridge_or_interface_remains"):
            self.apply()
        data = self.store.load(self.run_id)
        self.assertEqual(data["recoveries"]["attempts"][-1]["phase"], "resources_verified")
        self.assertNotEqual(data["status"], "cleaned")
        self.verify.side_effect = None
        self.apply()
        self.assertEqual(self.store.load(self.run_id)["status"], "cleaned")

    def test_no_wait_or_stop_holding_resources_and_allocator_is_last(self):
        self.new_boot()

        def stopping(data):
            self.assertEqual(admission.gate(self.store, self.run_id)["state"], "closed")
            with existing_lock(self.store.directory(self.run_id) / ".resources.lock"):
                pass

        self.stop.side_effect = stopping
        saves = []
        original_save = self.store.save

        def saving(data):
            saves.append((data["status"], data["recoveries"]["attempts"][-1]["phase"]))
            if data["status"] == "cleaned":
                with self.assertRaisesRegex(RunError, "recovery_lock_busy"):
                    with existing_lock(self.store.root / ".allocator.lock"):
                        pass
                # Graph must not overlap allocator.
                with existing_lock(self.store.root / ".storage-graph.lock"):
                    pass
            original_save(data)

        with patch.object(self.store, "save", side_effect=saving):
            self.apply()
        self.assertEqual(saves[-2:], [("cleaning", "reconciled"), ("cleaned", "reconciled")])

    def test_failed_cleaned_write_rolls_back_lease_even_after_replace(self):
        self.new_boot()
        original_save = self.store.save

        def save(data):
            original_save(data)
            if data["status"] == "cleaned":
                raise OSError("fixture directory fsync failure")

        with patch.object(self.store, "save", side_effect=save), self.assertRaises(OSError):
            self.apply()
        data = self.store.load(self.run_id)
        self.assertEqual(data["status"], "cleanup_failed")
        self.assertEqual(data["network"], self.data["network"])

    def test_lock_contention_missing_hardlinked_manifest_and_lock_refuse(self):
        with existing_lock(self.store.directory(self.run_id) / ".resources.lock"):
            with self.assertRaisesRegex(RunError, "recovery_lock_busy"):
                self.prepare()
        manifest = self.store.directory(self.run_id) / "manifest.json"
        alias = self.root / "alias"
        os.link(manifest, alias)
        with self.assertRaises(RunError):
            self.prepare()
        alias.unlink()
        resource = self.store.directory(self.run_id) / ".resources.lock"
        os.link(resource, alias)
        with self.assertRaisesRegex(RunError, "unsafe_existing_lock"):
            self.prepare()
        alias.unlink()
        resource.unlink()
        with self.assertRaises(FileNotFoundError):
            self.prepare()
        self.assertFalse(resource.exists())

    def test_open_existing_does_not_initialize_or_fsync(self):
        missing = self.root / "missing"
        with self.assertRaises(FileNotFoundError):
            Store.open_existing(missing)
        self.assertFalse(missing.exists())
        with patch("isolated_runs.state.fsync_directory") as sync:
            self.assertEqual(Store.open_existing(self.store.root).load(self.run_id), self.data)
            sync.assert_not_called()

    def test_cli_exact_exclusive_modes_and_bounded_errors(self):
        for flags in ([], ["--apply", "--dry-run"], ["--force"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                cli.main(["recover-destroy", self.run_id, "--operation", self.operation, *flags])
        with patch.object(Store, "open_existing", return_value=self.store), \
                patch.object(recovery, "inspect", side_effect=RunError("Command failed: private secret")), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(["recover-destroy", self.run_id, "--operation", self.operation, "--dry-run"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["blockers"], ["recovery_probe_failed"])
        self.assertNotIn("secret", output.getvalue())
        with patch.object(Store, "open_existing", return_value=self.store), \
                patch.object(Store, "__init__", side_effect=AssertionError("must not initialize")), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(["recover-destroy", self.run_id, "--operation", self.operation, "--prepare-maintenance"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["outcome"], "maintenance_prepared")


if __name__ == "__main__":
    unittest.main()
