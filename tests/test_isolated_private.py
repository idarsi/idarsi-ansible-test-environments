"""Private lifecycle provenance and observable references; no backend execution."""

import copy
import os
from unittest.mock import patch
import uuid
import xml.etree.ElementTree as ET

from test_isolated_graph import GraphFixture
from isolated_runs import storage_references as refs
from isolated_runs.backends import Backend
from isolated_runs.state import RunError, lock
from isolated_runs.storage import Storage


class PrivateDiskTests(GraphFixture):
    def setUp(self):
        super().setUp()
        self.a_path.unlink()
        self.a_disk = {"path": str(self.a_path), "name": "root", "serial": "itr-root"}
        self.owner_guest = {
            "id": str(uuid.uuid4()), "name": "itr-" + uuid.uuid4().hex,
            "disks": [self.a_disk],
        }
        self.run.update(status="running", guests=[self.owner_guest])
        self.states = []
        self.storage = Storage(self.root)
        with self.storage.publish(self.a_disk, self.save_publication, owner_id=self.run["id"]):
            pass
        self.foreign = self.definition(False)
        self.foreign.find("description").text = "legacy-netbox"

    def save_publication(self):
        self.states.append((copy.deepcopy(self.a_disk), self.a_path.exists()))
        self.store.save(self.run)

    def eligible(self):
        return refs.eligible_private_disk(
            self.store, self.context, self.run["id"], self.owner_guest["id"], self.a_disk, self.root,
        )

    def check_private(self, live=None, persistent=None):
        refs.assert_owned_domain_unused(
            live, persistent, self.a_disk, self.store, self.context,
            self.run["id"], self.owner_guest["id"], self.root,
        )

    def test_publication_states_and_actual_recovery_reconciliation(self):
        self.assertEqual(
            [(disk["publication"]["state"], exists) for disk, exists in self.states],
            [("intent", False), ("inode-journalled", False), ("published", True)],
        )
        self.assertTrue(self.eligible())
        self.a_disk["publication"]["state"] = "inode-journalled"
        self.store.save(self.run)
        before = self.store.load(self.run["id"])
        self.assertTrue(self.eligible())
        self.assertEqual(self.store.load(self.run["id"]), before)
        self.a_path.unlink()
        with self.assertRaises((RunError, FileNotFoundError)):
            self.eligible()

    def test_netbox_omission_never_opens_foreign_headers(self):
        self.b_path.chmod(0)
        self.addCleanup(self.b_path.chmod, 0o600)
        with patch.object(refs, "command", side_effect=AssertionError("no foreign header queries")):
            self.check_private(self.foreign, copy.deepcopy(self.foreign))
        self.assertFalse(refs.xml_evidence(self.foreign, True)[0]["complete"])

    def test_legacy_and_generic_remain_strict(self):
        self.a_disk.pop("publication")
        self.store.save(self.run)
        self.assertFalse(self.eligible())
        with patch.object(refs, "command", side_effect=RunError("unreadable")):
            with self.assertRaisesRegex(RunError, "unreadable"):
                self.check_private(self.foreign, self.foreign)
            with self.assertRaisesRegex(RunError, "unreadable"):
                refs.assert_domain_unused(self.foreign, None, self.a_disk)

    def test_intent_policy_owner_path_and_inode_mismatch_refuse(self):
        original = copy.deepcopy(self.a_disk["publication"])
        for key, value in (
            ("state", "intent"), ("policy", "future"), ("protocol", "unknown"),
            ("owner", str(uuid.uuid4())), ("path", str(self.b_path)), ("inode", -1),
        ):
            with self.subTest(field=key):
                self.a_disk["publication"] = dict(original, **{key: value})
                self.store.save(self.run)
                with self.assertRaises(RunError):
                    self.eligible()

    def test_context_and_owner_identity_mismatch_refuse(self):
        self.run["context"] = {"libvirt": "qemu:///session"}
        self.store.save(self.run)
        with self.assertRaises(RunError):
            self.eligible()

    def test_hardlink_and_replacement_refuse_eligibility_and_unlink(self):
        alias = self.root / "hardlink"
        os.link(self.a_path, alias)
        with self.assertRaisesRegex(RunError, "hardlinks"):
            self.eligible()
        with self.assertRaisesRegex(RunError, "hardlinks"):
            self.storage.remove(self.a_disk)
        alias.unlink()
        self.a_path.rename(alias)  # Keep old inode allocated to avoid reuse.
        self.a_path.touch()
        with self.assertRaises(RunError):
            self.eligible()
        with self.assertRaises(RunError):
            self.storage.remove(self.a_disk)

    def test_explicit_live_persistent_backing_and_symlink_references_refuse(self):
        alias = self.root / "alias"
        alias.symlink_to(self.a_path)
        for path in (self.a_path, alias):
            for backing in (False, True):
                for persistent in (False, True):
                    with self.subTest(path=path, backing=backing, persistent=persistent):
                        root = self.definition(backing)
                        query = "./devices/disk/" + ("backingStore/" if backing else "") + "source"
                        root.find(query).set("file", str(path))
                        with patch.object(refs, "command", side_effect=AssertionError("no header query")):
                            with self.assertRaises(RunError):
                                self.check_private(None if persistent else root, root if persistent else None)

    def test_pool_resolved_reference_and_query_error_refuse(self):
        root = copy.deepcopy(self.foreign)
        disk = root.find("./devices/disk")
        disk.set("type", "volume")
        source = disk.find("source")
        source.attrib.clear()
        source.attrib.update(pool="fixture", volume="disk")
        volume = "<volume><target><path>" + str(self.a_path) + "</path></target></volume>"
        with patch.object(refs, "command", side_effect=[str(self.a_path), volume]):
            with self.assertRaises(RunError):
                self.check_private(root)
        with patch.object(refs, "command", side_effect=RunError("query denied")):
            with self.assertRaisesRegex(RunError, "query denied"):
                self.check_private(root)

    def test_malformed_unsupported_and_unresolved_sources_refuse(self):
        for attributes in (
            {"file": str(self.b_path), "unexpected": "value"},
            {"protocol": "rbd", "name": "image"},
            {"file": str(self.root / "missing")},
        ):
            with self.subTest(attributes=attributes):
                root = copy.deepcopy(self.foreign)
                source = root.find("./devices/disk/source")
                source.attrib.clear()
                source.attrib.update(attributes)
                with self.assertRaises((RunError, FileNotFoundError)):
                    self.check_private(root)

    def test_registered_pending_dependency_blocks_private_target(self):
        self.guest["source_chain"] = {
            "version": 1, "complete": True, "provenance": "qemu-img-before-start",
            "members": [refs.member(self.a_path, "qcow2")],
        }
        self.store.save(self.b)
        with self.assertRaises(RunError):
            refs.assert_pending_unused(self.store, self.context, self.run["id"], self.a_disk)

    def test_backend_private_cleanup_holds_graph_lock_through_unlink(self):
        backend = Backend(self.store, self.run)
        backend.storage = self.storage
        remove = self.storage.remove
        definitions = []

        def query(argv):
            with self.assertRaises(RunError), lock(self.store.root / ".storage-graph.lock", blocking=False):
                pass
            if "list" in argv:
                return self.guest["id"]
            if "dumpxml" in argv:
                definitions.append("--inactive" in argv)
                return ET.tostring(self.foreign, encoding="unicode")
            self.fail("Unexpected backend mutation")

        def unlink(record):
            with self.assertRaises(RunError), lock(self.store.root / ".storage-graph.lock", blocking=False):
                pass
            remove(record)

        with patch.object(backend, "check_context"), patch.object(backend, "owned_domain", return_value=None), \
                patch("isolated_runs.backends.command", side_effect=query), \
                patch.object(refs, "command", side_effect=AssertionError("no foreign header query")), \
                patch.object(self.storage, "remove", side_effect=unlink):
            backend.destroy_guests()
        self.assertEqual(sorted(definitions), [False, True])
        self.assertFalse(self.a_path.exists())
        self.assertTrue(self.b_path.exists())
