"""New supervised host-mutation seals; all backend operations are mocked."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import cli, context
from isolated_runs.state import RunError, Store


class SupervisedSealTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(Path(self.temporary.name) / "state")
        self.data = self.store.allocate("podman", {}, lambda: [], Path(self.temporary.name), "podman-test")
        self.identity = {"pid": os.getsid(0), "boot": "fixture", "start": "1"}
        self.data.update(
            mode="supervised", mutation_protocol="sealed-v1", operations=[],
            workers=[self.identity], config={"platforms": []}, status="running",
        )
        self.store.save(self.data)
        self.run_id = self.data["id"]
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {
            "IDARSI_RUN_ID": self.run_id,
            "MOLECULE_INSTANCE_CONFIG": str(self.store.ephemeral(self.run_id) / "instance.yml"),
        }).start()
        patch.object(context, "resolved", return_value=({}, {})).start()
        patch.object(cli, "stop_workers").start()
        patch.object(context, "members", return_value=[]).start()

    def create(self):
        with patch.object(cli, "Backend") as backend:
            backend.return_value.create.return_value = [{"instance": "logical"}]
            cli.lifecycle(self.store, "create", self.run_id)
        operation = self.store.load(self.run_id)["operations"][0]
        self.assertEqual(operation["completion"], operation["id"])

    def spawn_cleanup(self, interrupted=False, fail=False):
        def fake_spawn(store, data, argv, env, cwd, operation):
            identity = {"pid": 987654, "boot": "fixture", "start": "2"}
            operation["worker"] = identity
            data["workers"].append(identity)
            store.save(data)
            self.assertNotIn("completion", store.load(self.run_id)["operations"][-1])
            outer = self

            class Child:
                def wait(self):
                    outer.assertNotEqual(store.load(outer.run_id)["status"], "cleaned")
                    if interrupted:
                        return 1
                    with patch.object(context, "members", return_value=[{"session": os.getsid(0)}]):
                        try:
                            context.worker(store, outer.run_id, operation["id"], "destroy")
                        except RunError:
                            if not fail:
                                raise
                            return 1
                    outer.assertEqual(store.load(outer.run_id)["status"], "destroyed")
                    return 0

            return Child()

        return patch.object(cli, "spawn", side_effect=fake_spawn)

    def test_incomplete_create_blocks_cleanup_even_after_late_daemon_object(self):
        with patch.object(cli, "Backend") as backend:
            backend.return_value.create.side_effect = RunError("uncertain daemon request")
            with self.assertRaisesRegex(RunError, "uncertain daemon"):
                cli.lifecycle(self.store, "create", self.run_id)
        operation = self.store.load(self.run_id)["operations"][0]
        self.assertNotIn("completion", operation)
        for observed in ([], ["late object"]):
            with self.subTest(backend_objects=observed), \
                    patch.object(cli, "Backend") as backend, \
                    patch.object(cli, "spawn") as spawn:
                with self.assertRaisesRegex(RunError, "Incomplete mutation"):
                    cli.cleanup(self.store, self.run_id)
                backend.assert_not_called()
                spawn.assert_not_called()
                self.assertNotEqual(self.store.load(self.run_id)["status"], "cleaned")

    def test_sealed_create_allows_cleanup_after_guest_failure(self):
        self.create()
        # A failed converge does not invalidate the completed host create.
        with self.spawn_cleanup(), patch.object(context, "Backend") as backend:
            cli.cleanup(self.store, self.run_id)
            backend.return_value.destroy_guests.assert_called_once()
            backend.return_value.destroy_network.assert_called_once()
        data = self.store.load(self.run_id)
        self.assertEqual(data["status"], "cleaned")
        self.assertEqual([op["action"] for op in data["operations"]], ["create", "destroy"])
        self.assertTrue(all(op["completion"] == op["id"] for op in data["operations"]))

    def test_failed_cleanup_has_no_seal_and_no_lease_release(self):
        self.create()
        with self.spawn_cleanup(fail=True), patch.object(context, "Backend") as backend:
            backend.return_value.destroy_guests.side_effect = RunError("uncertain removal")
            with self.assertRaisesRegex(RunError, "Incomplete mutation"):
                cli.cleanup(self.store, self.run_id)
            backend.return_value.destroy_network.assert_not_called()
        data = self.store.load(self.run_id)
        self.assertNotIn("completion", data["operations"][-1])
        self.assertNotEqual(data["status"], "cleaned")
        with patch.object(cli, "spawn") as spawn:
            with self.assertRaisesRegex(RunError, "Incomplete mutation"):
                cli.cleanup(self.store, self.run_id)
            spawn.assert_not_called()

    def test_interrupted_cleanup_retains_even_without_backend_objects(self):
        self.create()
        with self.spawn_cleanup(interrupted=True), patch.object(context, "Backend") as backend:
            with self.assertRaisesRegex(RunError, "Incomplete mutation"):
                cli.cleanup(self.store, self.run_id)
            backend.assert_not_called()
        data = self.store.load(self.run_id)
        self.assertNotIn("completion", data["operations"][-1])
        self.assertNotEqual(data["status"], "cleaned")

    def test_legacy_supervised_journal_recovery_needs_no_fabricated_seal(self):
        del self.data["mutation_protocol"]
        del self.data["operations"]
        del self.data["mode"]
        self.store.save(self.data)
        with patch.object(cli, "Backend"), patch.object(cli, "spawn") as spawn:
            cli.cleanup(self.store, self.run_id)
            spawn.assert_not_called()
        data = self.store.load(self.run_id)
        self.assertEqual(data["status"], "cleaned")
        self.assertNotIn("operations", data)
        self.assertNotIn("mutation_protocol", data)
        data.update(status="running", mutation_protocol="future-unsupported")
        self.store.save(data)
        with patch.object(cli, "Backend") as backend:
            with self.assertRaisesRegex(RunError, "Unsupported mutation protocol"):
                cli.cleanup(self.store, self.run_id)
            backend.assert_not_called()


if __name__ == "__main__":
    unittest.main()
