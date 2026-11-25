"""Cooperative stop with owned Python sessions; no backend commands are run."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import admission, cli, cooperative_stop, processes
from isolated_runs.state import RunError, Store, lock


def wait_for(predicate, timeout=5):
    """Bound fixture synchronization independently of the drain deadline."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("Owned-process fixture synchronization timed out")
        time.sleep(0.01)


def fixture_worker(root, run_id, mode, directory):
    """Run only as a separately journalled, fixture-owned Python session."""
    store = Store(Path(root))
    directory = Path(directory)
    data = store.load(run_id)
    # Do not inherit an unrelated supervisor's handoff authority.
    for key in list(os.environ):
        if key.startswith("IDARSI_HANDOFF"):
            del os.environ[key]
    os.environ.update(
        IDARSI_RUN_ID=run_id, IDARSI_HANDOFF="v1",
        MOLECULE_EPHEMERAL_DIRECTORY=data["ephemeral"],
    )

    def terminated(*_):
        operation = store.load(run_id)["operations"][0]
        (directory / (mode + ".signal")).write_text(
            json.dumps({"sealed": operation.get("completion") == operation["id"]})
        )
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminated)
    # The parent persists both immutable session identities before releasing us.
    if sys.stdin.readline() != "go\n":
        raise RuntimeError("Missing fixture start token")
    if mode == "queued":
        (directory / "queued.enter").touch()
        try:
            admission.authorize(store, run_id, data)
        except RunError as exc:
            if "admission is closed" not in str(exc):
                raise
            (directory / "queued.denied").touch()
        else:
            raise AssertionError("Queued admission unexpectedly succeeded")
    else:
        admission.authorize(store, run_id, data)
        with lock(store.directory(run_id) / ".resources.lock"):
            with admission.mutation_boundary(store, run_id, data) as (fresh, worker):
                fresh["operations"] = [
                    {"id": "owned-operation", "action": "create", "worker": worker}
                ]
                store.save(fresh)
            (directory / "active.ready").touch()
            wait_for(lambda: admission.gate(store, run_id)["state"] == "closed")
            if mode == "timeout":
                wait_for(lambda: (directory / "release").exists())
            if mode != "missing":
                fresh = store.load(run_id)
                fresh["operations"][0]["completion"] = "owned-operation"
                store.save(fresh)
                (directory / "active.sealed").touch()
    # Stay alive for real stop_workers signalling, but never leak indefinitely.
    time.sleep(12)
    raise RuntimeError("Fixture worker was not stopped within its lifetime bound")


@unittest.skipUnless(
    sys.platform == "linux"
    and hasattr(os, "pidfd_open")
    and hasattr(signal, "pidfd_send_signal"),
    "Linux procfs and pidfd signalling are required",
)
class CooperativeStopProcessTests(unittest.TestCase):
    def test_active_mutation_seals_before_signals_and_queued_admission_is_denied(self):
        self.run_scenario("finish")

    def test_drain_timeout_sends_no_signals_and_retains_unsealed_operation(self):
        self.run_scenario("timeout")

    def test_released_resource_lock_without_seal_still_refuses_cleanup(self):
        self.run_scenario("missing")

    def run_scenario(self, mode):
        with tempfile.TemporaryDirectory(prefix="cooperative-stop-") as temporary, ExitStack() as stack:
            directory = Path(temporary)
            store = Store(directory / "state")
            data = store.allocate("kvm", {}, lambda: [], directory, "owned-fixture")
            run_id = data["id"]
            data.update(
                mode="supervised", status="running", ephemeral=str(directory),
                mutation_protocol="sealed-v1", admission_protocol=admission.PROTOCOL,
                operations=[], workers=[],
            )
            store.save(data)
            admission.initialize(store, run_id)
            children = []
            try:
                for kind in ([mode, "queued"] if mode == "finish" else [mode]):
                    log = stack.enter_context((directory / (kind + ".log")).open("w"))
                    child = subprocess.Popen(
                        [sys.executable, "-B", str(Path(__file__).resolve()),
                         "--fixture-worker", str(store.root), run_id, kind, str(directory)],
                        stdin=subprocess.PIPE, stdout=log, stderr=log, start_new_session=True,
                    )
                    children.append(child)
                    identity = processes.process(child.pid)
                    self.assertIsNotNone(identity)
                    data["workers"].append(
                        {"pid": child.pid, "start": identity["start"], "boot": processes.boot_id()}
                    )
                store.save(data)
                children[0].stdin.write(b"go\n")
                children[0].stdin.flush()
                wait_for(lambda: (directory / "active.ready").exists())
                original = store.load(run_id)
                if mode == "finish":
                    children[1].stdin.write(b"go\n")
                    children[1].stdin.flush()
                    wait_for(lambda: (directory / "queued.enter").exists())

                real_stop = cli.stop_workers
                real_drain = cooperative_stop.drain_mutations

                def stop(fresh):
                    self.assertTrue((directory / "active.sealed").exists())
                    self.assertEqual("owned-operation", fresh["operations"][0]["completion"])
                    # Observe the queued helper's real rejection before stopping it.
                    wait_for(lambda: (directory / "queued.denied").exists())
                    real_stop(fresh)

                def drain(current_store, current_id):
                    return real_drain(
                        current_store, current_id, timeout=0.2 if mode == "timeout" else 3,
                    )

                with patch.object(cli, "stop_workers", side_effect=stop) as stopped, patch.object(
                    cli, "cleanup_sealed_locked"
                ) as backend_cleanup, patch.object(
                    cooperative_stop, "drain_mutations", side_effect=drain,
                ):
                    if mode == "finish":
                        cli.cleanup(store, run_id)
                        stopped.assert_called_once()
                        backend_cleanup.assert_called_once_with(store, run_id)
                        for kind, child in zip(("finish", "queued"), children):
                            self.assertEqual(0, child.wait(timeout=2))
                            evidence = json.loads((directory / (kind + ".signal")).read_text())
                            self.assertTrue(evidence["sealed"])
                        self.assertTrue((directory / "queued.denied").exists())
                    else:
                        message = "did not drain" if mode == "timeout" else "Incomplete mutation"
                        with self.assertRaisesRegex(RunError, message):
                            cli.cleanup(store, run_id)
                        stopped.assert_not_called()
                        backend_cleanup.assert_not_called()
                        self.assertTrue(all(child.poll() is None for child in children))
                        self.assertFalse(list(directory.glob("*.signal")))
                        self.assertEqual(original, store.load(run_id))
                self.assertEqual("closed", admission.gate(store, run_id)["state"])
                # Mocked backend cleanup must not fabricate a cleaned allocation.
                self.assertEqual("running", store.load(run_id)["status"])
            except Exception as exc:
                diagnostics = "\n".join(
                    path.name + ":\n" + path.read_text() for path in directory.glob("*.log")
                )
                raise AssertionError(f"{mode} process fixture failed:\n{diagnostics}") from exc
            finally:
                (directory / "release").touch()
                # These children create no descendants. Never discover or signal
                # unrelated sessions, and always reap the exact Popen children.
                for child in children:
                    if child.poll() is None:
                        child.terminate()
                    try:
                        child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=2)
                    finally:
                        child.stdin.close()


if __name__ == "__main__":
    if sys.argv[1:2] == ["--fixture-worker"]:
        fixture_worker(*sys.argv[2:])
    else:
        unittest.main()
