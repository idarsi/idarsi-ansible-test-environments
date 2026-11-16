"""Crash-boundary and actual configuration regressions; no backend execution."""

import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from isolated_runs import cli, state
from isolated_runs.backends import Backend, REPO, validate_platforms
from isolated_runs.state import RunError, Store
from isolated_runs.storage import Storage


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = Store(self.root / "state")
        self.run = self.store.allocate("kvm", {}, lambda: [], self.root, "validation")


class JournalTests(Fixture):
    def test_cleanup_reload_after_lifecycle_worker_commit(self):
        load = self.store.load
        first = [True]

        def interleaved_load(run_id):
            snapshot = load(run_id)
            if first[0]:
                first[0] = False
                fresh = load(run_id)
                fresh["network"] = {"id": "committed-before-status-write"}
                self.store.save(fresh)
            return snapshot

        def guests(backend):
            self.assertEqual(backend.data["network"]["id"], "committed-before-status-write")

        with patch.object(self.store, "load", side_effect=interleaved_load), \
                patch.object(cli, "stop_workers"), \
                patch.object(Backend, "destroy_guests", guests), \
                patch.object(Backend, "destroy_network"):
            cli.cleanup(self.store, self.run["id"])

    def test_failed_stop_never_overwrites_worker_journal(self):
        def stop(snapshot):
            fresh = self.store.load(self.run["id"])
            fresh["network"] = {"id": "latest-write"}
            self.store.save(fresh)
            raise RunError("still running")

        with patch.object(cli, "stop_workers", side_effect=stop), self.assertRaises(RunError):
            cli.cleanup(self.store, self.run["id"])
        fresh = self.store.load(self.run["id"])
        self.assertEqual(fresh["network"]["id"], "latest-write")
        self.assertEqual(fresh["status"], "allocated")

    def test_molecule_parent_deletion_cannot_delete_journal_or_locks(self):
        directory = self.store.directory(self.run["id"])
        for name in (".supervisor.lock", ".resources.lock"):
            (directory / name).touch()
        shutil.rmtree(self.store.ephemeral(self.run["id"]).parent)
        self.assertEqual(self.store.load(self.run["id"])["id"], self.run["id"])
        self.assertTrue((directory / ".supervisor.lock").exists())
        self.assertTrue((directory / ".resources.lock").exists())

    def test_new_ancestor_entries_are_synced_top_down(self):
        events = []
        target = self.root / "new" / "nested" / "state"
        with patch.object(state, "fsync_directory", side_effect=lambda path: events.append(path)):
            state.private_directory(target)
        self.assertLess(events.index(self.root), events.index(target.parent))
        self.assertLess(events.index(target.parent), events.index(target))
        self.assertEqual(events[-1], target.parent)

    def test_run_directory_parent_sync_precedes_manifest_commit(self):
        events = []
        original = self.store.save
        with patch.object(state, "fsync_directory", side_effect=lambda path: events.append(path)), \
                patch.object(self.store, "save", side_effect=lambda data: (events.append("save"), original(data))):
            run = self.store.allocate("kvm", {}, lambda: [], self.root, "validation")
        self.assertLess(events.index(self.store.root), events.index("save"))
        self.assertLess(events.index(self.store.directory(run["id"])), events.index("save"))


class StorageTests(Fixture):
    def setUp(self):
        super().setUp()
        self.storage = Storage(self.root)
        self.record = {"path": str(self.root / ("itr-" + uuid.uuid4().hex + ".qcow2"))}

    def test_publication_is_journalled_before_link_and_collisions_refused(self):
        def save():
            self.assertFalse(Path(self.record["path"]).exists())
            self.assertIsInstance(self.record["inode"], int)

        with self.storage.publish(self.record, save):
            info = Path(self.record["path"]).stat()
            self.assertEqual(info.st_ino, self.record["inode"])
            other = {"path": self.record["path"]}
            with self.assertRaises(FileExistsError), self.storage.publish(other, lambda: None):
                pass
        self.storage.remove(self.record)
        self.assertFalse(Path(self.record["path"]).exists())

    def test_journal_failure_leaves_no_named_inode(self):
        with self.assertRaises(RuntimeError), self.storage.publish(
            self.record, lambda: (_ for _ in ()).throw(RuntimeError("fsync failed")),
        ):
            pass
        self.assertFalse(Path(self.record["path"]).exists())

    def test_link_failure_leaves_no_named_inode_and_recovery_is_safe(self):
        with patch("isolated_runs.storage.os.link", side_effect=OSError("unsupported")), \
                self.assertRaises(OSError), self.storage.publish(self.record, lambda: None):
            pass
        self.assertFalse(Path(self.record["path"]).exists())
        self.storage.remove(self.record)

    def test_failure_after_publication_remains_owned_for_recovery(self):
        with self.assertRaises(RuntimeError):
            with self.storage.publish(self.record, lambda: None):
                raise RuntimeError("provisioning failed")
        self.assertTrue(Path(self.record["path"]).exists())
        self.storage.remove(self.record)

    def test_replacement_during_provisioning_is_never_adopted(self):
        with self.assertRaises(RunError):
            with self.storage.publish(self.record, lambda: None):
                Path(self.record["path"]).unlink()
                Path(self.record["path"]).write_text("foreign")
        with self.assertRaises(RunError):
            self.storage.remove(self.record)
        self.assertEqual(Path(self.record["path"]).read_text(), "foreign")

    def test_unlink_is_followed_by_directory_fsync(self):
        with self.storage.publish(self.record, lambda: None):
            pass
        events = []
        unlink = os.unlink
        with patch("isolated_runs.storage.os.unlink", side_effect=lambda *a, **kw: (events.append("unlink"), unlink(*a, **kw))), \
                patch("isolated_runs.storage.os.fsync", side_effect=lambda fd: events.append("fsync")):
            self.storage.remove(self.record)
        self.assertEqual(events, ["unlink", "fsync"])

    def test_symlink_storage_ancestor_rejected(self):
        link = self.root / "alias"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError), Storage(link).directory():
            pass

    def test_exact_protocol_probe_uses_temporary_fixture_filesystem_only(self):
        self.storage.probe()
        self.assertEqual(list(self.root.glob("itr-*.qcow2")), [])

    def test_partial_data_disk_creation_is_independently_recoverable(self):
        first = self.record
        second = {"path": str(self.root / ("itr-" + uuid.uuid4().hex + ".qcow2"))}
        with self.assertRaises(RuntimeError):
            with self.storage.publish(first, lambda: None):
                with self.storage.publish(second, lambda: None):
                    raise RuntimeError("second format failed")
        for disk in (first, second):
            self.storage.remove(disk)
            self.assertFalse(Path(disk["path"]).exists())


class StorageTraversalTests(Fixture):
    def traversal_fixture(self):
        ancestor = self.root / "search-only"
        target = ancestor / "owned-storage"
        target.mkdir(parents=True, mode=0o700)
        # Current-user-owned 0111 exercises the same denied-read/permitted-
        # search distinction as root-owned 0711 for an unprivileged caller.
        # Only temporary fixture permissions are changed, never host paths.
        ancestor.chmod(0o111)
        self.addCleanup(ancestor.chmod, 0o700)
        return ancestor, target

    @unittest.skipIf(os.geteuid() == 0, "Requires actual unprivileged permission enforcement")
    def test_search_only_ancestor_allows_readable_fsync_capable_target(self):
        ancestor, target = self.traversal_fixture()
        with self.assertRaises(PermissionError):
            os.open(str(ancestor), os.O_RDONLY | os.O_DIRECTORY)
        storage = Storage(target)
        with storage.directory() as fd:
            self.assertEqual(os.fstat(fd).st_ino, target.stat().st_ino)
            self.assertEqual(os.listdir(fd), [])
            os.fsync(fd)
        # Publication/collision refusal/unlink fsync still work through the
        # same target descriptor; this probes only the temporary fixture FS.
        storage.probe()
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual(ancestor.stat().st_mode & 0o777, 0o111)

    def test_search_only_traversal_still_refuses_ancestor_and_target_symlinks(self):
        ancestor, target = self.traversal_fixture()
        alias = self.root / "ancestor-alias"
        alias.symlink_to(ancestor, target_is_directory=True)
        target_alias = self.root / "target-alias"
        target_alias.symlink_to(target, target_is_directory=True)
        for path in (alias / target.name, target_alias):
            with self.subTest(path=path), self.assertRaises(OSError), Storage(path).directory():
                pass

    @unittest.skipIf(os.geteuid() == 0, "Requires actual unprivileged permission enforcement")
    def test_final_target_still_requires_read_permission(self):
        _, target = self.traversal_fixture()
        target.chmod(0o111)
        self.addCleanup(target.chmod, 0o700)
        with self.assertRaises(PermissionError), Storage(target).directory():
            pass
        self.assertEqual(target.stat().st_mode & 0o777, 0o111)

    def test_search_only_ancestor_still_enforces_trust_checks(self):
        ancestor, target = self.traversal_fixture()
        ancestor.chmod(0o113)
        with self.assertRaisesRegex(RunError, "world-writable"), Storage(target).directory():
            pass


class AttachmentTests(Fixture):
    def test_live_and_persistent_xml_both_checked(self):
        backend = Backend(self.store, self.run)
        guest = {"name": "owned", "id": "domain-id", "disks": [{"path": "/root"}]}
        xml = (
            "<domain><name>owned</name><description>idarsi-run:" + self.run["id"]
            + "</description><devices><disk device='disk'><source file='/root'/>"
            "</disk></devices></domain>"
        )
        with patch("isolated_runs.backends.command", side_effect=[
            "domain-id", "owned", xml, "domain-id", xml.replace("/root", "/foreign"),
        ]), self.assertRaisesRegex(RunError, "attachment set"):
            backend.owned_domain(guest)

    def test_owned_domain_removed_before_any_root_or_data_unlink(self):
        backend = Backend(self.store, self.run)
        backend.storage = Storage(self.root)
        guest = {"name": "owned", "id": "domain-id", "disks": []}
        for _ in range(2):
            disk = {"path": str(self.root / ("itr-" + uuid.uuid4().hex + ".qcow2"))}
            with backend.storage.publish(disk, lambda: None):
                pass
            guest["disks"].append(disk)
        backend.data["guests"] = [guest]
        events = []

        def command(argv):
            if "domstate" in argv:
                return "running"
            if "destroy" in argv or "undefine" in argv:
                events.append(argv[-2])
                self.assertTrue(all(Path(disk["path"]).exists() for disk in guest["disks"]))
            return ""

        remove = backend.storage.remove
        with patch.object(backend, "check_context"), \
                patch.object(backend, "owned_domain", side_effect=[ET.Element("domain"), None]), \
                patch("isolated_runs.backends.command", side_effect=command), \
                patch.object(backend.storage, "remove", side_effect=lambda disk: (events.append("unlink"), remove(disk))):
            backend.destroy_guests()
        self.assertEqual(events, ["destroy", "undefine", "unlink", "unlink"])

    def test_replaced_data_inode_refuses_domain_mutation(self):
        backend = Backend(self.store, self.run)
        backend.storage = Storage(self.root)
        disk = {"path": str(self.root / ("itr-" + uuid.uuid4().hex + ".qcow2"))}
        with backend.storage.publish(disk, lambda: None):
            pass
        disk["inode"] += 1
        backend.data["guests"] = [{"disks": [disk]}]
        with patch.object(backend, "check_context"), \
                patch.object(backend, "owned_domain") as query, self.assertRaises(RunError):
            backend.destroy_guests()
        query.assert_not_called()
        self.assertTrue(Path(disk["path"]).exists())

    def test_root_only_manifest_normalization(self):
        disk = {"path": "/root.qcow2", "device": 1, "inode": 2}
        self.assertEqual(Backend.disks({"disk": disk}), [disk])

    def test_complete_attachment_set_is_order_independent_but_strict(self):
        backend = Backend(self.store, self.run)
        guest = {"disks": [
            {"path": "/root", "serial": "itr-root"},
            {"path": "/data", "serial": "itr-osd1"},
        ]}
        xml = ET.fromstring("<domain><devices>"
                            "<disk device='disk'><source file='/data'/><serial>itr-osd1</serial>"
                            "<target bus='virtio'/><driver type='qcow2'/></disk>"
                            "<disk device='disk'><source file='/root'/><serial>itr-root</serial>"
                            "<target bus='virtio'/><driver type='qcow2'/></disk>"
                            "</devices></domain>")
        backend.verify_attachments(guest, xml)
        xml.find("./devices/disk/serial").text = "foreign"
        with self.assertRaises(RunError):
            backend.verify_attachments(guest, xml)

    def test_data_disk_allowlist_and_types(self):
        image = self.root / "base.qcow2"
        image.touch()
        platform = {"name": "node", "image_path": str(image), "data_disks": [{"name": "osd1", "size_gb": 20}]}
        self.assertEqual(validate_platforms("kvm", [platform], self.root)[0]["data_disks"], platform["data_disks"])
        for invalid in (
            [{"name": "root", "size_gb": 20}], [{"name": "../bad", "size_gb": 1}],
            [{"name": "a", "size_gb": True}], [{"name": "a", "size_gb": 0}],
            [{"name": "a", "size_gb": 1, "path": "/foreign"}],
            [{"name": "a", "size_gb": 1}, {"name": "a", "size_gb": 2}],
        ):
            with self.subTest(invalid=invalid), self.assertRaises(RunError):
                validate_platforms("kvm", [dict(platform, data_disks=invalid)], self.root)

    def test_iso_data_disks_reject_conflicting_partition_scope(self):
        source = self.root / "test.iso"
        source.touch()
        kickstart = self.root / "test.ks"
        kickstart.write_text("@@NETWORK_CONFIGURATION@@\nignoredisk --only-use=vdb\n")
        with self.assertRaisesRegex(RunError, "ignoredisk"):
            validate_platforms("kvm", [{
                "name": "node", "install_source": str(source), "kickstart": str(kickstart),
                "data_disks": [{"name": "osd1", "size_gb": 20}],
            }], self.root)


@unittest.skipUnless(importlib.util.find_spec("molecule"), "Activate an existing pinned Molecule environment")
class EffectiveConfigTests(Fixture):
    def setUp(self):
        super().setUp()
        self.scenario = self.root / "molecule" / "validation"
        self.scenario.mkdir(parents=True)
        self.source = self.scenario / "molecule.yml"
        self.source.write_text((REPO / "examples/molecule-managed-podman/molecule.yml").read_text())
        self.environment = cli.managed_environment()
        self.environment.update(
            HOME=str(self.root), XDG_CACHE_HOME=str(self.root / "cache"),
            MOLECULE_EPHEMERAL_DIRECTORY=str(self.store.ephemeral(self.run["id"])),
        )
        # The bridge must execute the same pinned interpreter as this test.
        self.environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]

    def test_actual_config_with_inherited_parallel_sanitized(self):
        with patch.dict(os.environ, {"MOLECULE_PARALLEL": "true"}):
            sanitized = cli.managed_environment()
        self.assertNotIn("MOLECULE_PARALLEL", sanitized)
        self.environment.pop("MOLECULE_PARALLEL", None)
        data = cli.parse_configuration(self.root, "validation", self.environment)
        self.assertEqual(data["driver"]["name"], "default")
        self.assertFalse(data.get("shared_state", False))
        validate_platforms("podman", data["platforms"], self.scenario)

    def test_actual_top_level_shared_state_rejected(self):
        self.source.write_text(self.source.read_text() + "\nshared_state: true\n")
        with self.assertRaisesRegex(RunError, "shared_state"):
            cli.parse_configuration(self.root, "validation", self.environment)

    def test_actual_inherited_base_shared_state_rejected(self):
        base = self.root / ".config" / "molecule" / "config.yml"
        base.parent.mkdir(parents=True)
        base.write_text("shared_state: true\n")
        with self.assertRaisesRegex(RunError, "shared_state"):
            cli.parse_configuration(self.root, "validation", self.environment)


if __name__ == "__main__":
    unittest.main()
