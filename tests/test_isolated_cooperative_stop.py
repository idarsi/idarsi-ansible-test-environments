"""Private-journal stop races; no backend tools or real processes are invoked."""

from contextlib import ExitStack
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import admission, cli, context, cooperative_stop
from isolated_runs.state import RunError, Store, lock


class CooperativeStopTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = Store(Path(temporary.name) / "state")
        self.data = self.store.allocate("kvm", {}, lambda: [], Path(temporary.name), "fixture")
        self.run_id = self.data["id"]
        self.worker = {"pid": 123456, "start": "1", "boot": "fixture"}
        self.data.update(
            mode="supervised", status="running", mutation_protocol="sealed-v1",
            admission_protocol=admission.PROTOCOL, operations=[], workers=[self.worker],
        )
        self.store.save(self.data)
        admission.initialize(self.store, self.run_id)
        stderr = patch.object(cooperative_stop.sys, "stderr", io.StringIO())
        stderr.start()
        self.addCleanup(stderr.stop)

    def operation(self, completed=False):
        operation = {"id": "fixture-operation", "action": "create", "worker": self.worker}
        if completed:
            operation["completion"] = operation["id"]
        self.data["operations"] = [operation]
        self.store.save(self.data)

    def test_closes_before_wait_and_only_returns_after_durable_seal(self):
        self.operation()
        with ExitStack() as held:
            held.enter_context(lock(self.store.directory(self.run_id) / ".resources.lock"))

            def complete(_delay):
                self.assertEqual("closed", admission.gate(self.store, self.run_id)["state"])
                self.assertNotIn("completion", self.store.load(self.run_id)["operations"][0])
                self.operation(completed=True)
                held.close()

            with patch.object(cooperative_stop.time, "sleep", side_effect=complete) as wait:
                data = cooperative_stop.drain_mutations(self.store, self.run_id)
            wait.assert_called_once()
        self.assertEqual("fixture-operation", data["operations"][0]["completion"])
        self.assertEqual("running", data["status"])  # No fabricated cleanup result.

    def test_cleanup_stops_sessions_only_after_active_mutation_seals(self):
        self.operation()
        with ExitStack() as held:
            held.enter_context(lock(self.store.directory(self.run_id) / ".resources.lock"))
            order = []

            def complete(_delay):
                order.append("seal")
                self.operation(completed=True)
                held.close()

            def stop(data):
                self.assertEqual("fixture-operation", data["operations"][0]["completion"])
                self.assertEqual("closed", admission.gate(self.store, self.run_id)["state"])
                order.append("stop")

            with patch.object(cooperative_stop.time, "sleep", side_effect=complete), patch.object(
                cli, "stop_workers", side_effect=stop
            ), patch.object(cli, "cleanup_sealed_locked", side_effect=lambda *_: order.append("cleanup")):
                cli.cleanup(self.store, self.run_id)
        self.assertEqual(["seal", "stop", "cleanup"], order)

    def test_busy_timeout_preserves_operation_and_never_signals_or_deletes(self):
        self.operation()
        original = self.store.load(self.run_id)
        with lock(self.store.directory(self.run_id) / ".resources.lock"), patch.object(
            cooperative_stop.time, "monotonic", side_effect=[0, 121]
        ), patch.object(cli, "stop_workers") as stop, patch.object(
            cli, "cleanup_sealed_locked"
        ) as cleanup:
            with self.assertRaisesRegex(RunError, "did not drain"):
                cli.cleanup(self.store, self.run_id)
        stop.assert_not_called()
        cleanup.assert_not_called()
        self.assertEqual(original, self.store.load(self.run_id))
        self.assertEqual("closed", admission.gate(self.store, self.run_id)["state"])

    def test_drained_create_reaches_cleaned_only_through_sealed_cleanup(self):
        self.operation(completed=True)
        peer = self.store.allocate("kvm", {}, lambda: [], Path(self.store.root.parent), "peer")
        peer_before = self.store.load(peer["id"])
        stopped = []

        def spawn(store, data, argv, env, cwd, operation):
            self.assertEqual("closed", admission.gate(store, self.run_id)["state"])
            self.assertEqual("cleaning", data["status"])
            self.assertEqual(1, len(stopped))  # Old sessions were stopped first.
            worker = {"pid": 654321, "start": "2", "boot": "fixture"}
            operation["worker"] = worker
            data["workers"].append(worker)
            store.save(data)
            outer = self

            class Child:
                def wait(self):
                    outer.assertNotIn("completion", store.load(outer.run_id)["operations"][-1])
                    with patch.object(context, "members", return_value=[{"session": os.getsid(0)}]):
                        context.worker(store, outer.run_id, operation["id"], "destroy")
                    outer.assertEqual("destroyed", store.load(outer.run_id)["status"])
                    return 0

            return Child()

        with patch.object(cli, "stop_workers", side_effect=lambda data: stopped.append(data)), patch.object(
            cli, "spawn", side_effect=spawn
        ), patch.object(context, "members", return_value=[]), patch.object(context, "Backend") as backend:
            cli.cleanup(self.store, self.run_id)
        backend.return_value.destroy_guests.assert_called_once()
        backend.return_value.destroy_network.assert_called_once()
        data = self.store.load(self.run_id)
        self.assertEqual("cleaned", data["status"])
        self.assertEqual(["create", "destroy"], [op["action"] for op in data["operations"]])
        self.assertTrue(all(op["completion"] == op["id"] for op in data["operations"]))
        self.assertEqual(2, len(stopped))
        self.assertEqual(peer_before, self.store.load(peer["id"]))

    def test_incomplete_or_invalid_seal_never_grants_cleanup_authority(self):
        for change in ({}, {"completion": "wrong"}, {"worker": {}}):
            with self.subTest(change=change):
                self.operation()
                self.data["operations"][0].update(change)
                self.store.save(self.data)
                with patch.object(cli, "stop_workers") as stop, patch.object(
                    cli, "cleanup_sealed_locked"
                ) as cleanup, patch.object(cooperative_stop.time, "sleep") as wait:
                    with self.assertRaisesRegex(RunError, "Incomplete mutation"):
                        cli.cleanup(self.store, self.run_id)
                stop.assert_not_called()
                cleanup.assert_not_called()
                wait.assert_not_called()
                self.assertEqual(self.data, self.store.load(self.run_id))

    def test_resource_lock_acquisition_without_seal_does_not_complete_mutation(self):
        self.operation()
        with ExitStack() as held:
            held.enter_context(lock(self.store.directory(self.run_id) / ".resources.lock"))
            with patch.object(cooperative_stop.time, "sleep", side_effect=lambda _: held.close()):
                with self.assertRaisesRegex(RunError, "Incomplete mutation"):
                    cooperative_stop.drain_mutations(self.store, self.run_id)
        self.assertNotIn("completion", self.store.load(self.run_id)["operations"][0])

    def test_failure_to_close_gate_never_signals_workers(self):
        with patch.object(admission, "close", side_effect=OSError("fixture write failure")), patch.object(
            cli, "stop_workers"
        ) as stop, patch.object(cli, "cleanup_sealed_locked") as cleanup:
            with self.assertRaises(OSError):
                cli.cleanup(self.store, self.run_id)
        stop.assert_not_called()
        cleanup.assert_not_called()

    def test_nonbusy_lock_failure_is_not_retried(self):
        with patch.object(cooperative_stop, "lock", side_effect=RunError("Unsafe lock")), patch.object(
            cooperative_stop.time, "sleep"
        ) as wait:
            with self.assertRaisesRegex(RunError, "Unsafe lock"):
                cooperative_stop.drain_mutations(self.store, self.run_id)
        wait.assert_not_called()

    def test_retry_can_drain_after_timeout_without_fabricating_original_seal(self):
        self.operation()
        with lock(self.store.directory(self.run_id) / ".resources.lock"):
            with self.assertRaisesRegex(RunError, "did not drain"):
                cooperative_stop.drain_mutations(self.store, self.run_id, timeout=0)
        self.assertNotIn("completion", self.store.load(self.run_id)["operations"][0])
        self.operation(completed=True)  # The original worker, not recovery, seals it.
        data = cooperative_stop.drain_mutations(self.store, self.run_id, timeout=0)
        self.assertEqual("fixture-operation", data["operations"][0]["completion"])

    def test_read_only_peers_unchanged_and_closed_gate_is_not_reopened(self):
        other = self.store.allocate("kvm", {}, lambda: [], Path(self.store.root.parent), "peer")
        original = self.store.load(other["id"])
        with patch.object(cooperative_stop.time, "sleep") as wait:
            cooperative_stop.drain_mutations(self.store, self.run_id)
            cooperative_stop.drain_mutations(self.store, self.run_id)
        wait.assert_not_called()
        self.assertEqual(original, self.store.load(other["id"]))
        self.assertEqual("closed", admission.gate(self.store, self.run_id)["state"])


if __name__ == "__main__":
    unittest.main()
