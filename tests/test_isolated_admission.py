"""Supervised tool-session admission without backend resources."""

import importlib.util
import contextlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import admission, cli, context, processes
from isolated_runs.state import RunError, Store, lock


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = Store(self.root / "state")
        self.data = self.store.allocate("podman", {}, lambda: [], self.root, "podman-test")
        self.run_id = self.data["id"]
        self.outer = {"pid": 100, "start": "10", "boot": "fixture"}
        self.data.update(
            mode="supervised", status="running", mutation_protocol="sealed-v1",
            admission_protocol=admission.PROTOCOL, operations=[], workers=[self.outer],
            config={"platforms": []},
        )
        self.store.save(self.data)
        admission.initialize(self.store, self.run_id)
        self.expected = {key: self.data[key] for key in ("id", "role", "scenario", "backend")}
        self.expected["ephemeral"] = str(self.store.ephemeral(self.run_id))
        self.chain = {
            pid: {
                "pid": pid, "parent": parent, "session": pid, "start": start,
                "uid": os.getuid(), "zombie": False,
            }
            for pid, parent, start in ((300, 200, "30"), (200, 100, "20"), (100, 10, "10"))
        }
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {
            "IDARSI_RUN_ID": self.run_id, "IDARSI_HANDOFF": "v1",
            "MOLECULE_EPHEMERAL_DIRECTORY": self.expected["ephemeral"],
            "MOLECULE_INSTANCE_CONFIG": str(self.store.ephemeral(self.run_id) / "instance.yml"),
        }).start()
        patch.object(admission, "boot_id", return_value="fixture").start()
        patch.object(admission, "process", side_effect=lambda pid: dict(self.chain[pid]) if pid in self.chain else None).start()
        patch.object(admission.os, "getpid", return_value=300).start()
        patch.object(admission.os, "getsid", return_value=300).start()
        patch.object(admission.os, "pidfd_open", side_effect=lambda pid: os.open(os.devnull, os.O_RDONLY)).start()

    def test_registers_all_sessions_then_close_snapshots_them_without_resource_wait(self):
        current = admission.authorize(self.store, self.run_id, self.expected)
        self.assertEqual(current["pid"], 300)
        registered = self.store.load(self.run_id)["workers"]
        self.assertEqual({item["pid"] for item in registered}, {100, 200, 300})
        # Closing must not acquire resources: a mutation may still own them.
        with lock(self.store.directory(self.run_id) / ".resources.lock"):
            snapshot = admission.close(self.store, self.run_id)
        self.assertEqual(snapshot["workers"], registered)
        self.assertEqual(admission.gate(self.store, self.run_id)["state"], "closed")
        with self.assertRaisesRegex(RunError, "never reopen"):
            admission.initialize(self.store, self.run_id)

    def test_close_before_registration_denies_without_appending_worker(self):
        admission.close(self.store, self.run_id)
        with self.assertRaisesRegex(RunError, "closed"):
            admission.authorize(self.store, self.run_id, self.expected)
        self.assertEqual(self.store.load(self.run_id)["workers"], [self.outer])

    def test_registration_racing_close_commits_before_close_snapshot(self):
        ready = threading.Event()
        release = threading.Event()
        closing = threading.Event()
        original = admission.prove_sessions

        @contextlib.contextmanager
        def pause(data):
            with original(data) as sessions:
                ready.set()
                if not release.wait(3):
                    raise AssertionError("registration gate was not released")
                yield sessions

        def close():
            closing.set()
            return admission.close(self.store, self.run_id)

        with patch.object(admission, "prove_sessions", side_effect=pause), ThreadPoolExecutor(2) as pool:
            registration = pool.submit(admission.authorize, self.store, self.run_id, self.expected)
            try:
                self.assertTrue(ready.wait(3))
                closure = pool.submit(close)
                self.assertTrue(closing.wait(3))
                self.assertFalse(closure.done())
            finally:
                release.set()
            registration.result(timeout=3)
            snapshot = closure.result(timeout=3)
        self.assertEqual({item["pid"] for item in snapshot["workers"]}, {100, 200, 300})
        self.assertEqual(admission.gate(self.store, self.run_id)["state"], "closed")

    def test_close_racing_registration_blocked_on_resources_wins(self):
        started = threading.Event()

        def register():
            started.set()
            return admission.authorize(self.store, self.run_id, self.expected)

        with ThreadPoolExecutor(1) as pool:
            with lock(self.store.directory(self.run_id) / ".resources.lock"):
                registration = pool.submit(register)
                self.assertTrue(started.wait(3))
                snapshot = admission.close(self.store, self.run_id)
                self.assertEqual(snapshot["workers"], [self.outer])
            with self.assertRaisesRegex(RunError, "closed"):
                registration.result(timeout=3)

    def test_authorized_then_closed_denies_create_and_mapping_destroy(self):
        admission.authorize(self.store, self.run_id, self.expected)
        admission.close(self.store, self.run_id)
        destination = Path(os.environ["MOLECULE_INSTANCE_CONFIG"])
        destination.write_text("preserve")
        with patch.object(context, "resolved", return_value=({}, {})), patch.object(cli, "Backend") as backend:
            for action in ("create", "destroy"):
                with self.assertRaisesRegex(RunError, "closed"):
                    cli.lifecycle(self.store, action, self.run_id)
            backend.assert_not_called()
        self.assertEqual(destination.read_text(), "preserve")
        self.assertEqual(self.store.load(self.run_id)["operations"], [])

    def test_unrelated_same_uid_stale_zombie_or_external_session_rejected(self):
        cases = (
            (300, "parent", 1), (100, "start", "11"), (200, "zombie", True),
            (300, "uid", os.getuid() + 1), (300, "session", 999),
            (200, "start", "40"),
        )
        for pid, field, value in cases:
            previous = self.chain[pid][field]
            with self.subTest(field=field, pid=pid):
                self.chain[pid][field] = value
                with self.assertRaises(RunError):
                    admission.authorize(self.store, self.run_id, self.expected)
                self.assertEqual(self.store.load(self.run_id)["workers"], [self.outer])
            self.chain[pid][field] = previous

    def test_whole_chain_rechecked_before_commit_and_reparent_rejected(self):
        reads = []

        def changed(pid):
            reads.append(pid)
            item = dict(self.chain[pid])
            if pid == 200 and reads.count(200) >= 3:
                item["parent"] = 1
            return item

        with patch.object(admission, "process", side_effect=changed):
            with self.assertRaisesRegex(RunError, "changed before admission"):
                admission.authorize(self.store, self.run_id, self.expected)
        self.assertEqual(self.store.load(self.run_id)["workers"], [self.outer])

    def test_missing_invalid_gate_and_ambiguous_session_fail_closed(self):
        path = self.store.directory(self.run_id) / "admission.json"
        original = path.read_text()
        path.unlink()
        with self.assertRaises(OSError):
            admission.authorize(self.store, self.run_id, self.expected)
        path.write_text('{"version":99,"state":"open"}')
        path.chmod(0o600)
        with self.assertRaisesRegex(RunError, "Invalid"):
            admission.authorize(self.store, self.run_id, self.expected)
        path.write_text(original)
        self.data["workers"].append(dict(self.outer))
        self.store.save(self.data)
        with self.assertRaisesRegex(RunError, "ambiguous"):
            admission.authorize(self.store, self.run_id, self.expected)

    def test_closed_gate_only_allows_explicit_journalled_cleanup_worker(self):
        operation = {
            "id": "cleanup", "action": "destroy", "worker": self.outer,
            "purpose": "supervisor-cleanup",
        }
        self.data["operations"] = [operation]
        self.data["status"] = "cleaning"
        self.store.save(self.data)
        with patch.object(context, "members", return_value=[{"session": 300}]), \
                patch.object(context, "Backend") as backend:
            with self.assertRaisesRegex(RunError, "cleanup admission"):
                context.worker(self.store, self.run_id, "cleanup", "destroy")
            backend.assert_not_called()
            admission.close(self.store, self.run_id)
            del operation["purpose"]
            self.store.save(self.data)
            with self.assertRaisesRegex(RunError, "cleanup admission"):
                context.worker(self.store, self.run_id, "cleanup", "destroy")
            backend.assert_not_called()
            operation["purpose"] = "supervisor-cleanup"
            self.store.save(self.data)
            context.worker(self.store, self.run_id, "cleanup", "destroy")
            backend.return_value.destroy_guests.assert_called_once()
        self.assertEqual(self.store.load(self.run_id)["status"], "destroyed")


@unittest.skipUnless(importlib.util.find_spec("molecule"), "Activate existing pinned Molecule")
class RealSessionAdmissionTests(unittest.TestCase):
    def test_real_config_env_and_two_detached_sessions_journal_before_backend(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = Store(root / "state")
            source = root / "molecule" / "podman-test" / "molecule.yml"
            source.parent.mkdir(parents=True)
            source.write_text((context.REPO / "examples/molecule-managed-podman/molecule.yml").read_text())
            data = store.allocate("podman", {}, lambda: [], root, "podman-test")
            run_id = data["id"]
            data.update(
                mode="supervised", status="running", mutation_protocol="sealed-v1",
                admission_protocol=admission.PROTOCOL, operations=[],
                config={"platforms": [{"name": "node"}]},
            )
            store.save(data)
            admission.initialize(store, run_id)
            result = root / "result.json"
            leaf = (
                "import json,os; from pathlib import Path; from unittest.mock import patch\n"
                "from isolated_runs import cli,processes; from isolated_runs.state import Store\n"
                "original_command=cli.command\n"
                "def fixture_command(*args,**kwargs):\n"
                " output=original_command(*args,**kwargs)\n"
                " try: json.loads(output)\n"
                " except ValueError: raise AssertionError('fixture bridge prefix: '+repr(output[:200]))\n"
                " return output\n"
                "cli.command=fixture_command\n"
                "store=Store(Path(" + repr(str(store.root)) + ")); run_id=" + repr(run_id) + "\n"
                "role=Path(" + repr(temporary) + ")\n"
                "config=cli.parse_configuration(role,'podman-test',dict(os.environ),direct=True)\n"
                "os.environ.update(config['_idarsi_effective_env'])\n"
                "proof=[]\n"
                "def create(platforms):\n"
                " d=store.load(run_id); assert len(d['workers'])==3, d['workers']\n"
                " op=d['operations'][-1]; assert op['worker']['pid']==os.getsid(0)\n"
                " assert 'completion' not in op\n"
                " pid=os.getpid()\n"
                " while True:\n"
                "  item=processes.process(pid); proof.append(item)\n"
                "  if pid==d['workers'][0]['pid']: break\n"
                "  pid=item['parent']\n"
                " return [{'instance':'logical'}]\n"
                "with patch.object(cli,'Backend') as backend:\n"
                " backend.return_value.create.side_effect=create\n"
                " cli.lifecycle(store,'create',run_id)\n"
                "Path(" + repr(str(result)) + ").write_text(json.dumps({'pid':os.getpid(),'sid':os.getsid(0),'ancestry':proof}))\n"
                "import time; time.sleep(60)\n"
            )
            middle = (
                "import subprocess,sys; subprocess.run([sys.executable,'-c',"
                + repr(leaf) + "],start_new_session=True,timeout=15)"
            )
            outer = (
                "import subprocess,sys,time; from pathlib import Path\n"
                "subprocess.Popen([sys.executable,'-c',"
                + repr(middle) + "],start_new_session=True)\n"
                "deadline=time.monotonic()+10\n"
                "while not Path(" + repr(str(result)) + ").exists() and time.monotonic()<deadline: time.sleep(0.01)\n"
                "assert Path(" + repr(str(result)) + ").exists()\n"
            )
            environment = dict(
                os.environ, PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
                PYTHONPATH=str(context.REPO / "scripts"), HOME=temporary,
                XDG_CACHE_HOME=str(root / "cache"), IDARSI_RUN_ID=run_id, IDARSI_HANDOFF="v1",
                IDARSI_TEST_ENVIRONMENT=str(context.REPO),
                MOLECULE_EPHEMERAL_DIRECTORY=str(store.ephemeral(run_id)),
            )
            child = processes.spawn(store, data, [sys.executable, "-c", outer], environment, temporary)
            try:
                self.assertEqual(child.wait(timeout=25), 0)
                observed = json.loads(result.read_text())
                final = store.load(run_id)
                self.session_evidence = {"ancestry": observed["ancestry"], "registered": final["workers"]}
                self.assertEqual(len(final["workers"]), 3)
                self.assertEqual(final["operations"][0]["worker"]["pid"], observed["sid"])
                self.assertEqual(final["operations"][0]["completion"], final["operations"][0]["id"])
                self.assertTrue(any(processes.members(item) for item in final["workers"]))
            finally:
                snapshot = admission.close(store, run_id)
                processes.stop_workers(snapshot)
                child.wait(timeout=5)
            self.assertTrue(all(not processes.members(item) for item in store.load(run_id)["workers"]))
