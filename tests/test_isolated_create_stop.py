"""Stopped creates seal only at explicit completed-command checkpoints."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import admission, backends, cli, context, cooperative_stop
from isolated_runs.state import RunError, Store


class CreateStopTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = Store(self.root / "state")
        self.data = self.store.allocate("kvm", {}, lambda: [], self.root, "fixture")
        self.run_id = self.data["id"]
        self.worker = {"pid": 123456, "start": "1", "boot": "fixture"}
        self.data.update(
            mode="supervised", status="running", mutation_protocol="sealed-v1",
            admission_protocol=admission.PROTOCOL, operations=[], workers=[self.worker],
            config={"platforms": []},
        )
        self.store.save(self.data)
        admission.initialize(self.store, self.run_id)
        for mocker in (
            patch.dict(os.environ, {
                "IDARSI_RUN_ID": self.run_id, "IDARSI_HANDOFF": "v1",
                "MOLECULE_EPHEMERAL_DIRECTORY": str(self.store.ephemeral(self.run_id)),
            }),
            patch.object(context, "resolved", return_value=({}, {})),
            patch.object(admission, "registered_current", return_value=self.worker),
        ):
            mocker.start()
            self.addCleanup(mocker.stop)

    def test_stopped_create_seals_without_publishing_ready_instances(self):
        def stopped(_platforms):
            admission.close(self.store, self.run_id)
            raise cooperative_stop.CreateStopped(self.run_id, "guest-readiness")

        with patch.object(cli, "Backend") as backend, patch.object(context, "mapping") as mapping:
            backend.return_value.create.side_effect = stopped
            with self.assertRaisesRegex(RunError, "stopped cooperatively"):
                cli.lifecycle(self.store, "create", self.run_id)
        mapping.assert_not_called()
        data = self.store.load(self.run_id)
        operation, = data["operations"]
        self.assertEqual(operation["id"], operation["completion"])
        self.assertEqual("stopped", operation["outcome"])
        self.assertEqual("guest-readiness", operation["stop_checkpoint"])
        self.assertNotIn("instances_ready", data)
        self.assertEqual("running", data["status"])  # Not a cleanup or test success.
        with patch.object(context, "members", return_value=[]):
            context.require_completed(data)

    def test_rpc_failure_never_receives_a_stop_completion_seal(self):
        def uncertain(_platforms):
            admission.close(self.store, self.run_id)
            raise RunError("Uncertain libvirt RPC")

        with patch.object(cli, "Backend") as backend:
            backend.return_value.create.side_effect = uncertain
            with self.assertRaisesRegex(RunError, "Uncertain libvirt"):
                cli.lifecycle(self.store, "create", self.run_id)
        self.assertNotIn("completion", self.store.load(self.run_id)["operations"][0])

    def test_wrong_run_open_gate_or_unknown_checkpoint_cannot_be_sealed(self):
        for close_gate, run_id, checkpoint in (
            (False, self.run_id, "guest-readiness"),
            (True, "wrong-run", "guest-readiness"),
            (True, self.run_id, "unknown-checkpoint"),
        ):
            with self.subTest(close_gate=close_gate, run_id=run_id, checkpoint=checkpoint):
                self.data["operations"] = [{
                    "id": "fixture-operation", "action": "create", "worker": self.worker,
                }]
                self.store.save(self.data)
                if close_gate:
                    admission.close(self.store, self.run_id)
                with self.assertRaisesRegex(RunError, "Invalid stopped-create"):
                    cooperative_stop.seal_stopped_create(
                        self.store, self.run_id, "fixture-operation",
                        cooperative_stop.CreateStopped(run_id, checkpoint),
                    )
                self.assertNotIn("completion", self.store.load(self.run_id)["operations"][0])

    def test_failed_stop_seal_write_keeps_original_operation_incomplete(self):
        save = self.store.save

        def failing_save(data):
            if data["operations"] and data["operations"][-1].get("outcome") == "stopped":
                raise OSError("Fixture completion write failed")
            save(data)

        def stopped(_platforms):
            admission.close(self.store, self.run_id)
            raise cooperative_stop.CreateStopped(self.run_id, "before-guest")

        with patch.object(cli, "Backend") as backend, patch.object(
            self.store, "save", side_effect=failing_save
        ):
            backend.return_value.create.side_effect = stopped
            with self.assertRaises(OSError):
                cli.lifecycle(self.store, "create", self.run_id)
        self.assertNotIn("completion", self.store.load(self.run_id)["operations"][0])

    def test_closed_gate_prevents_network_and_guest_creation(self):
        admission.close(self.store, self.run_id)
        backend = backends.Backend(self.store, self.data)
        with patch.object(backend, "network") as network:
            with self.assertRaises(cooperative_stop.CreateStopped):
                backend.create([])
        network.assert_not_called()

    def test_stop_after_network_does_not_start_another_guest(self):
        backend = backends.Backend(self.store, self.data)
        with patch.object(
            backend, "network", side_effect=lambda: admission.close(self.store, self.run_id)
        ), patch.object(backend, "create_domain") as create:
            with self.assertRaises(cooperative_stop.CreateStopped) as stopped:
                backend.create([{"name": "fixture"}])
        self.assertEqual("before-guest", stopped.exception.checkpoint)
        self.assertEqual([], self.store.load(self.run_id)["guests"])
        create.assert_not_called()

    def test_network_rpc_failure_is_not_a_safe_stop_checkpoint(self):
        backend = backends.Backend(self.store, self.data)
        with patch.object(backend, "network", side_effect=RunError("Uncertain network create")):
            with self.assertRaisesRegex(RunError, "Uncertain network") as failed:
                backend.create([])
        self.assertNotIsInstance(failed.exception, cooperative_stop.CreateStopped)

    def test_stopped_seal_cannot_complete_another_workers_operation(self):
        other_worker = dict(self.worker, pid=654321)
        self.data["workers"].append(other_worker)
        self.data["operations"] = [{
            "id": "fixture-operation", "action": "create", "worker": other_worker,
        }]
        self.store.save(self.data)
        admission.close(self.store, self.run_id)
        with self.assertRaisesRegex(RunError, "Invalid stopped-create"):
            cooperative_stop.seal_stopped_create(
                self.store, self.run_id, "fixture-operation",
                cooperative_stop.CreateStopped(self.run_id, "guest-readiness"),
            )
        self.assertNotIn("completion", self.store.load(self.run_id)["operations"][0])

    def test_readback_rejects_stopped_seal_with_unknown_checkpoint(self):
        self.data["operations"] = [{
            "id": "fixture-operation", "action": "create", "worker": self.worker,
            "completion": "fixture-operation", "outcome": "stopped",
            "stop_checkpoint": "unknown",
        }]
        with patch.object(context, "members", return_value=[]):
            with self.assertRaisesRegex(RunError, "Invalid stopped-create seal"):
                context.require_completed(self.data)

    def provision_fixture(self):
        directory = self.store.directory(self.run_id)
        key = directory / "kvm_ed25519"
        key.write_text("fixture-key-placeholder")
        Path(str(key) + ".pub").write_text("fixture-public-key-placeholder")
        kickstart = directory / "fixture.ks"
        kickstart.write_text("@@SSH_USER@@ @@SSH_PUBLIC_KEY@@ @@NETWORK_CONFIGURATION@@")
        self.data["network"] = {"name": "fixture-network"}
        guest = {
            "name": "fixture-guest", "id": "fixture-domain", "logical": "fixture",
            "disks": [{"path": str(directory / "fixture.qcow2"), "serial": "itr-root"}],
        }
        platform = {
            "name": "fixture", "ssh_user": "fixture", "install_source": "fixture-iso",
            "kickstart": str(kickstart), "disk_size_gb": 30,
            "memory_mb": 2048, "vcpus": 1, "install_timeout": 3600,
        }
        self.data["guests"] = [guest]
        self.store.save(self.data)
        return backends.Backend(self.store, self.data), guest, platform

    def test_kvm_readiness_wait_stops_after_successful_host_start_without_ssh(self):
        backend, guest, platform = self.provision_fixture()
        called = []

        def command(argv, **kwargs):
            called.append(argv[0])
            self.assertEqual("virt-install", argv[0])
            admission.close(self.store, self.run_id)
            return ""

        with patch.object(backend, "disk_command"), patch.object(backend, "verify_disk"), patch.object(
            backends, "image_chain", return_value={"fixture": True}
        ), patch.object(backends, "command", side_effect=command):
            with self.assertRaises(cooperative_stop.CreateStopped) as stopped:
                backend.provision_domain(guest, platform, 0)
        self.assertEqual("guest-readiness", stopped.exception.checkpoint)
        self.assertEqual(["virt-install"], called)

    def test_kvm_start_timeout_is_not_converted_to_cooperative_stop(self):
        backend, guest, platform = self.provision_fixture()
        with patch.object(backend, "disk_command"), patch.object(backend, "verify_disk"), patch.object(
            backends, "image_chain", return_value={"fixture": True}
        ), patch.object(backends, "command", side_effect=RunError("Uncertain start timeout")):
            with self.assertRaisesRegex(RunError, "Uncertain start") as failed:
                backend.provision_domain(guest, platform, 0)
        self.assertNotIsInstance(failed.exception, cooperative_stop.CreateStopped)


if __name__ == "__main__":
    unittest.main()
