"""Real-process quiescence and mocked libvirt storage-graph regressions."""

import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
import uuid
import xml.etree.ElementTree as ET

from test_isolated_safety import Fixture
from isolated_runs import cli, processes, storage_references
from isolated_runs.backends import Backend
from isolated_runs.state import RunError
from isolated_runs.storage import Storage


class ProvisioningQuiescenceTests(Fixture):
    def exercise_surviving_writer(self, mode):
        self.run["status"] = "running"
        self.store.save(self.run)
        disk = self.root / "owned-test-disk"
        disk.touch()
        pidfile = self.root / "writer.pid"
        ready = self.root / "destroy-returned"
        writer = (
            "import os,time; from pathlib import Path; "
            "Path(" + repr(str(pidfile)) + ").write_text(str(os.getpid())); "
            "f=open(" + repr(str(disk)) + ",'a'); "
            "\nwhile True:\n f.write('x'); f.flush(); time.sleep(0.05)\n"
        )
        parent = (
            "import subprocess,sys,time; from pathlib import Path; "
            "subprocess.Popen([sys.executable,'-c'," + repr(writer) + "],"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
            "\nwhile not Path(" + repr(str(pidfile)) + ").exists(): time.sleep(0.01)\n"
            + ("time.sleep(60)\n" if mode == "timeout" else "sys.exit(7)\n")
        )
        worker = (
            "from pathlib import Path\nimport sys,time\n"
            "from isolated_runs.discovery import command\n"
            "from isolated_runs.state import Store,RunError\n"
            "from isolated_runs.cli import lifecycle\n"
            "from isolated_runs.backends import Backend\nfrom unittest.mock import patch\n"
            "try:\n command([sys.executable,'-c'," + repr(parent) + "],timeout=1)\n"
            "except RunError:\n pass\n"
            "with patch.object(Backend,'destroy_guests',lambda self: Path("
            + repr(str(disk)) + ").unlink()), patch.object(Backend,'destroy_network',lambda self: None):\n"
            " lifecycle(Store(Path(" + repr(str(self.store.root)) + ")),'destroy',"
            + repr(self.run["id"]) + ")\n"
            "Path(" + repr(str(ready)) + ").write_text('deferred')\ntime.sleep(60)\n"
        )
        environment = dict(
            os.environ, IDARSI_RUN_ID=self.run["id"],
            MOLECULE_INSTANCE_CONFIG=str(self.store.ephemeral(self.run["id"]) / "instance_config.yml"),
            PYTHONPATH=str(Path(__file__).resolve().parents[1] / "scripts"),
        )
        child = processes.spawn(
            self.store, self.run, [sys.executable, "-c", worker], environment, str(self.root),
        )
        try:
            deadline = time.monotonic() + 10
            while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists(), "worker did not reach deferred destroy")
            writer_pid = int(pidfile.read_text())
            self.assertFalse(processes.process(writer_pid)["zombie"])
            self.assertTrue(disk.exists(), "in-session destroy must not delete the disk")
            self.assertEqual(processes.process(writer_pid)["session"], child.pid)
            events = []

            def destroy(backend):
                # Supervisor cleanup must have stopped the entire session,
                # not merely the parent that timed out or exited nonzero.
                self.assertEqual(processes.members(backend.data["workers"][0]), [])
                current = processes.process(writer_pid)
                self.assertTrue(current is None or current["zombie"])
                events.append("delete")
                disk.unlink()

            with patch.object(Backend, "destroy_guests", destroy), \
                    patch.object(Backend, "destroy_network"):
                cli.cleanup(self.store, self.run["id"])
            child.wait(timeout=5)
            self.assertEqual(events, ["delete"])
        finally:
            processes.stop_workers(self.store.load(self.run["id"]))
            child.wait(timeout=5)

    def test_timeout_survivor_is_stopped_before_supervisor_deletion(self):
        self.exercise_surviving_writer("timeout")

    def test_nonzero_exit_survivor_is_stopped_before_supervisor_deletion(self):
        self.exercise_surviving_writer("failure")

    def test_uncertain_quiescence_preserves_resources_and_journal(self):
        self.run["status"] = "running"
        self.run["guests"] = [{"ownership": "must-survive"}]
        self.store.save(self.run)
        with patch.object(cli, "stop_workers", side_effect=RunError("uncertain session")), \
                patch.object(Backend, "destroy_guests") as destroy, self.assertRaises(RunError):
            cli.cleanup(self.store, self.run["id"])
        destroy.assert_not_called()
        self.assertEqual(self.store.load(self.run["id"]), self.run)

    def test_worker_cannot_signal_its_own_molecule_session(self):
        with patch.object(processes, "members") as members, self.assertRaisesRegex(RunError, "own worker session"):
            processes.stop_workers({"workers": [{
                "boot": processes.boot_id(), "pid": os.getsid(0), "start": "not-used",
            }]})
        members.assert_not_called()


class ForeignStorageTests(Fixture):
    def setUp(self):
        super().setUp()
        self.owned = self.root / ("itr-" + uuid.uuid4().hex + ".qcow2")
        self.owned.touch()
        info = self.owned.stat()
        self.disk = {"path": str(self.owned), "device": info.st_dev, "inode": info.st_ino}
        self.overlay = self.root / "foreign.qcow2"
        self.overlay.touch()

    def fake_command(self, argv):
        if argv[0] == "qemu-img":
            return json.dumps([{"filename": argv[-1], "format": "raw"}])
        self.fail("Unexpected backend query " + repr(argv))

    def xml(self, source, extra="", kind="file"):
        return ET.fromstring(
            "<domain><devices><disk device='disk' type='" + kind + "'>"
            + source + extra + "</disk></devices></domain>",
        )

    def test_owned_disk_in_nested_backing_store_refuses_deletion(self):
        middle = self.root / "middle.qcow2"
        middle.touch()
        root = self.xml(
            "<source file='" + str(self.overlay) + "'/>",
            "<backingStore type='file'><format type='qcow2'/><source file='" + str(middle) + "'/>"
            "<backingStore type='file'><format type='raw'/><source file='" + self.owned.name + "'/>"
            "<backingStore/></backingStore></backingStore>",
        )
        with patch.object(storage_references, "command", side_effect=self.fake_command), \
                self.assertRaisesRegex(RunError, "storage graph"):
            storage_references.assert_disk_unused(root, self.disk)

    def test_actual_image_chain_covers_omitted_inactive_backing_xml(self):
        root = self.xml("<source file='" + str(self.overlay) + "'/>")
        chain = [
            {"filename": str(self.overlay), "format": "qcow2", "backing-filename": self.owned.name},
            {"filename": str(self.owned), "format": "raw"},
        ]
        with patch.object(storage_references, "command", return_value=json.dumps(chain)), \
                self.assertRaisesRegex(RunError, "storage graph"):
            storage_references.assert_disk_unused(root, self.disk)

    def test_pool_volume_resolution_finds_inode_alias(self):
        alias = self.root / "volume-alias"
        os.link(self.owned, alias)
        root = self.xml("<source pool='testpool' volume='testvolume'/>", kind="volume")

        def query(argv):
            if "vol-path" in argv:
                return str(alias)
            if "vol-dumpxml" in argv:
                return "<volume><target><path>" + str(alias) + "</path></target></volume>"
            return self.fake_command(argv)

        with patch.object(storage_references, "command", side_effect=query), \
                self.assertRaisesRegex(RunError, "storage graph"):
            storage_references.assert_disk_unused(root, self.disk)

    def test_volume_backing_definition_is_resolved(self):
        root = self.xml("<source pool='pool' volume='overlay'/>", kind="volume")

        def query(argv):
            if "vol-path" in argv:
                return str(self.overlay)
            if "vol-dumpxml" in argv:
                return (
                    "<volume><target><path>" + str(self.overlay) + "</path></target>"
                    "<backingStore><path>" + str(self.owned) + "</path></backingStore></volume>"
                )
            return self.fake_command(argv)

        with patch.object(storage_references, "command", side_effect=query), \
                self.assertRaisesRegex(RunError, "storage graph"):
            storage_references.assert_disk_unused(root, self.disk)

    def test_volume_query_failure_is_not_absence(self):
        root = self.xml("<source pool='pool' volume='volume'/>", kind="volume")
        with patch.object(storage_references, "command", side_effect=RunError("volume unavailable")), \
                self.assertRaisesRegex(RunError, "volume unavailable"):
            storage_references.assert_disk_unused(root, self.disk)

    def test_unsupported_remote_or_missing_reference_fails_closed(self):
        for root in (
            self.xml("<source protocol='rbd' name='pool/image'/>", kind="network"),
            self.xml("<source file='/nonexistent/idarsi-safety-test/image'/>"),
            self.xml(""),
            self.xml("<source file='" + str(self.overlay) + "'/>", "<mirror/>"),
        ):
            with self.subTest(xml=ET.tostring(root)), self.assertRaises((RunError, OSError)):
                storage_references.assert_disk_unused(root, self.disk)

    def test_external_data_file_is_not_silently_ignored(self):
        root = self.xml("<source file='" + str(self.overlay) + "'/>")
        chain = [{
            "filename": str(self.overlay), "format": "qcow2",
            "format-specific": {"data": {"data-file": str(self.owned)}},
        }]
        with patch.object(storage_references, "command", return_value=json.dumps(chain)), \
                self.assertRaisesRegex(RunError, "External-data"):
            storage_references.assert_disk_unused(root, self.disk)

    def test_incomplete_image_chain_is_not_absence(self):
        root = self.xml("<source file='" + str(self.overlay) + "'/>")
        chain = [{"filename": str(self.overlay), "format": "qcow2", "backing-filename": self.owned.name}]
        with patch.object(storage_references, "command", return_value=json.dumps(chain)), \
                self.assertRaisesRegex(RunError, "Incomplete"):
            storage_references.assert_disk_unused(root, self.disk)

    def test_inactive_foreign_backing_reference_blocks_backend_unlink(self):
        backend = Backend(self.store, self.run)
        backend.storage = Storage(self.root)
        backend.data["guests"] = [{"disks": [self.disk]}]
        live = self.xml("<source file='" + str(self.overlay) + "'/>")
        inactive = self.xml("<source file='" + str(self.owned) + "'/>")

        def query(argv):
            if "list" in argv:
                return "foreign-domain"
            if "dumpxml" in argv:
                return ET.tostring(inactive if "--inactive" in argv else live, encoding="unicode")
            self.fail("Unexpected query " + repr(argv))

        with patch.object(backend, "check_context"), patch.object(backend, "owned_domain", return_value=None), \
                patch("isolated_runs.backends.command", side_effect=query), \
                patch.object(storage_references, "command", side_effect=self.fake_command), \
                patch.object(backend.storage, "remove") as remove, self.assertRaises(RunError):
            backend.destroy_guests()
        remove.assert_not_called()
        self.assertTrue(self.owned.exists())

    def test_partial_multi_disk_cleanup_preserves_journal_for_retry(self):
        backend = Backend(self.store, self.run)
        backend.storage = Storage(self.root)
        second = {"path": str(self.root / ("itr-" + uuid.uuid4().hex + ".qcow2"))}
        with backend.storage.publish(second, lambda: None):
            pass
        backend.data["guests"] = [{"disks": [self.disk, second]}]
        backend.save()
        remove = backend.storage.remove

        def fail_second(disk):
            if disk is second:
                raise RunError("unlink temporarily unavailable")
            remove(disk)

        with patch.object(backend, "check_context"), patch.object(backend, "owned_domain", return_value=None), \
                patch("isolated_runs.backends.command", return_value=""):
            with patch.object(backend.storage, "remove", side_effect=fail_second), self.assertRaises(RunError):
                backend.destroy_guests()
            self.assertFalse(self.owned.exists())
            self.assertTrue(Path(second["path"]).exists())
            self.assertEqual(len(self.store.load(self.run["id"])["guests"][0]["disks"]), 2)
            backend.destroy_guests()
        self.assertFalse(Path(second["path"]).exists())
        self.assertEqual(self.store.load(self.run["id"])["guests"], [])


if __name__ == "__main__":
    unittest.main()
