"""Concurrent-run graph evidence: metadata-only proof, no backend execution."""

import copy
import json
import os
from pathlib import Path
from unittest.mock import patch
import unittest
import uuid
import xml.etree.ElementTree as ET

from test_isolated_safety import Fixture
from isolated_runs import storage_references as refs
from isolated_runs.backends import Backend
from isolated_runs.state import RunError, lock
from isolated_runs.storage import Storage


class GraphFixture(Fixture):
    def setUp(self):
        super().setUp()
        self.context = {"libvirt": "qemu:///system", "podman": {"uid": os.getuid()}}
        self.run["context"] = self.context
        self.store.save(self.run)
        self.a_path = self.root / ("itr-" + uuid.uuid4().hex + ".qcow2")
        self.a_path.touch()
        snapshot = refs.member(self.a_path, "qcow2")
        self.a_disk = {key: value for key, value in snapshot.items() if key != "format"}
        self.b = self.store.allocate("kvm", self.context, lambda: [], self.root, "validation")
        self.b["status"] = "running"
        self.b_path = self.root / ("itr-" + uuid.uuid4().hex + ".qcow2")
        self.b_path.touch(mode=0o600)
        self.base = self.root / "completed-base.qcow2"
        self.base.touch()
        self.capture = {
            "version": 1, "complete": True, "provenance": "qemu-img-before-start",
            "members": [refs.member(self.b_path, "qcow2"), refs.member(self.base, "raw")],
        }
        self.b_disk = dict(self.capture["members"][0])
        self.b_disk.pop("format")
        self.b_disk.update(serial="itr-root", name="root", image_chain=self.capture)
        self.guest = {
            "name": "itr-" + uuid.uuid4().hex, "id": str(uuid.uuid4()),
            "logical": "node", "disks": [self.b_disk],
        }
        self.b["guests"] = [self.guest]
        self.store.save(self.b)

    def definition(self, backing=True):
        root = ET.Element("domain")
        ET.SubElement(root, "name").text = self.guest["name"]
        ET.SubElement(root, "uuid").text = self.guest["id"]
        ET.SubElement(root, "description").text = "idarsi-run:" + self.b["id"]
        devices = ET.SubElement(root, "devices")
        disk = ET.SubElement(devices, "disk", type="file", device="disk")
        ET.SubElement(disk, "driver", name="qemu", type="qcow2")
        ET.SubElement(disk, "source", file=str(self.b_path))
        ET.SubElement(disk, "target", dev="vda", bus="virtio")
        ET.SubElement(disk, "serial").text = "itr-root"
        if backing:
            chain = ET.SubElement(disk, "backingStore", type="file", index="1")
            ET.SubElement(chain, "format", type="raw")
            ET.SubElement(chain, "source", file=str(self.base))
            ET.SubElement(chain, "backingStore")
        return root

    def check(self, live=None, persistent=None):
        return refs.assert_domain_unused(
            live, persistent, self.a_disk, self.store, self.context, self.root,
        )


class LiveEvidenceTests(GraphFixture):
    def test_complete_live_chain_never_opens_foreign_images(self):
        live = self.definition()
        # Independent live proof does not require a private manifest.
        live.find("description").text = "legacy-but-explicit-live"
        with patch.object(refs, "command", side_effect=AssertionError("qemu-img forbidden")):
            refs.assert_domain_unused(live, None, self.a_disk)

    def test_raw_ordinary_file_omission_terminates_live_and_persistent(self):
        live = self.definition(False)
        live.find("description").text = "legacy"
        live.find("./devices/disk/driver").set("type", "raw")
        with patch.object(refs, "command", side_effect=AssertionError("qemu-img forbidden")):
            refs.assert_domain_unused(live, copy.deepcopy(live), self.a_disk)

    def test_explicit_empty_qcow2_terminal_is_complete(self):
        live = self.definition(False)
        live.find("description").text = "legacy"
        ET.SubElement(live.find("./devices/disk"), "backingStore")
        with patch.object(refs, "command", side_effect=AssertionError("qemu-img forbidden")):
            refs.assert_domain_unused(live, None, self.a_disk)

    def test_omitted_qcow2_chain_is_unknown_not_empty(self):
        live = self.definition(False)
        live.find("description").text = "legacy"
        with patch.object(refs, "command", side_effect=RunError("Permission denied")), \
                self.assertRaisesRegex(RunError, "Permission denied"):
            refs.assert_domain_unused(live, None, self.a_disk)

    def test_unknown_inactive_even_complete_xml_requires_readable_evidence(self):
        with patch.object(refs, "command", side_effect=RunError("Permission denied")), \
                self.assertRaisesRegex(RunError, "Permission denied"):
            self.check(None, self.definition())

    def test_explicit_persistent_reference_blocks_before_any_header_query(self):
        persistent = self.definition()
        persistent.find("./devices/disk/backingStore/source").set("file", str(self.a_path))
        with patch.object(refs, "command", side_effect=AssertionError("query must not bypass explicit ref")), \
                self.assertRaisesRegex(RunError, "storage graph"):
            self.check(self.definition(), persistent)

    def test_live_persistent_header_override_paths_are_checked_independently(self):
        live = self.definition()
        live.find("./devices/disk/backingStore/source").set("file", str(self.a_path))
        with patch.object(refs, "command", side_effect=AssertionError("qemu-img forbidden")), \
                self.assertRaisesRegex(RunError, "storage graph"):
            self.check(live, self.definition())

    def test_unknown_active_with_omitted_persistent_chain_cannot_use_live_as_bypass(self):
        live, persistent = self.definition(), self.definition(False)
        for root in (live, persistent):
            root.find("description").text = "legacy"
        with patch.object(refs, "command", side_effect=RunError("unreadable")), \
                self.assertRaisesRegex(RunError, "unreadable"):
            refs.assert_domain_unused(live, persistent, self.a_disk)


class ManagedEvidenceTests(GraphFixture):
    def test_matching_active_b_capture_supplements_omitted_persistent_chain(self):
        # Model qemu's 0600 ownership by forbidding all image opens. Stat remains
        # permitted, exactly as with the real directory/file permission model.
        with patch.object(refs, "command", side_effect=AssertionError("qemu-img forbidden")):
            self.check(self.definition(), self.definition(False))

    def test_backend_a_cleanup_succeeds_without_b_lifetime_lock_or_image_open(self):
        backend = Backend(self.store, self.run)
        backend.storage = Storage(self.root)
        backend.data["guests"] = [{"disks": [self.a_disk]}]
        backend.save()
        live, persistent = self.definition(), self.definition(False)

        def query(argv):
            with self.assertRaises(RunError), lock(self.store.root / ".storage-graph.lock", blocking=False):
                pass
            if "list" in argv:
                return self.guest["id"]
            if "dumpxml" in argv:
                return ET.tostring(persistent if "--inactive" in argv else live, encoding="unicode")
            self.fail("Unexpected backend mutation " + repr(argv))

        with lock(self.store.directory(self.b["id"]) / ".supervisor.lock"), \
                lock(self.store.directory(self.b["id"]) / ".resources.lock"), \
                patch.object(backend, "check_context"), patch.object(backend, "owned_domain", return_value=None), \
                patch("isolated_runs.backends.command", side_effect=query), \
                patch.object(refs, "command", side_effect=AssertionError("qemu-img forbidden")):
            backend.destroy_guests()
        self.assertFalse(self.a_path.exists())
        self.assertTrue(self.b_path.exists())
        self.assertEqual(self.store.load(self.b["id"]), self.b)

    def test_truncated_capture_does_not_match_complete_live_chain(self):
        self.capture["members"].pop()
        self.store.save(self.b)
        with self.assertRaises(RunError):
            self.check(self.definition(), self.definition(False))

    def test_complete_flag_or_provenance_cannot_be_forged_into_proof(self):
        for changes in ({"complete": False}, {"provenance": "assumed"}, {"version": 2}):
            with self.subTest(changes=changes):
                original = copy.deepcopy(self.capture)
                self.capture.update(changes)
                self.store.save(self.b)
                with self.assertRaises(RunError):
                    self.check(self.definition(), self.definition(False))
                self.capture.clear()
                self.capture.update(original)

    def test_wrong_backend_context_uuid_name_or_attachment_is_rejected(self):
        original = copy.deepcopy(self.b)
        for mutation in ("backend", "context", "uuid", "name", "serial"):
            with self.subTest(mutation=mutation):
                data = copy.deepcopy(original)
                if mutation == "backend":
                    data["backend"] = "podman"
                elif mutation == "context":
                    data["context"] = {"libvirt": "qemu:///session"}
                elif mutation == "uuid":
                    data["guests"][0]["id"] = str(uuid.uuid4())
                elif mutation == "name":
                    data["guests"][0]["name"] = "itr-" + uuid.uuid4().hex
                else:
                    data["guests"][0]["disks"][0]["serial"] = "itr-forged"
                self.store.save(data)
                with self.assertRaises(RunError):
                    self.check(self.definition(), self.definition(False))

    def test_stale_backing_inode_refuses_metadata_only_cleanup(self):
        self.base.rename(self.root / "preserve-old-inode")
        self.base.touch()
        with self.assertRaisesRegex(RunError, "inode"):
            self.check(self.definition(), self.definition(False))

    def test_legacy_manifest_without_chain_needs_fresh_readable_evidence(self):
        self.b_disk.pop("image_chain")
        self.store.save(self.b)
        with patch.object(refs, "command", side_effect=RunError("unreadable legacy disk")), \
                self.assertRaisesRegex(RunError, "unreadable"):
            self.check(self.definition(), self.definition(False))

    def test_private_manifest_and_run_directory_are_required(self):
        directory = self.store.directory(self.b["id"])
        manifest = directory / "manifest.json"
        manifest.chmod(0o644)
        with self.assertRaisesRegex(RunError, "private"):
            self.check(self.definition(), self.definition(False))
        manifest.chmod(0o600)
        directory.chmod(0o755)
        with self.assertRaisesRegex(RunError, "directory"):
            self.check(self.definition(), self.definition(False))
        directory.chmod(0o700)
        self.store.root.chmod(0o755)
        with self.assertRaisesRegex(RunError, "directory"):
            self.store.load(self.b["id"])
        self.store.root.chmod(0o700)

    def test_manifest_uid_and_symlink_are_rejected(self):
        self.b["uid"] = os.getuid() + 1
        self.store.save(self.b)
        with self.assertRaises(RunError):
            self.check(self.definition(), self.definition(False))
        directory = self.store.directory(self.b["id"])
        manifest = directory / "manifest.json"
        manifest.rename(directory / "other.json")
        manifest.symlink_to(directory / "other.json")
        with self.assertRaises(OSError):
            self.store.load(self.b["id"])

    def test_incomplete_live_chain_cannot_be_supplemented_by_manifest_alone(self):
        with patch.object(refs, "command", side_effect=RunError("unreadable incomplete chain")) as query, \
                self.assertRaisesRegex(RunError, "unreadable incomplete"):
            self.check(self.definition(False), self.definition(False))
        query.assert_called_once()

    def test_pending_source_dependency_blocks_unlink_before_domain_start(self):
        self.guest["source_chain"] = {
            "version": 1, "complete": True, "provenance": "qemu-img-before-start",
            "members": [refs.member(self.a_path, "qcow2")],
        }
        self.store.save(self.b)
        with self.assertRaisesRegex(RunError, "storage graph"):
            refs.assert_pending_unused(self.store, self.context, self.run["id"], self.a_disk)

    def test_qemu_capture_checks_complete_chain_without_force_share(self):
        chain = [
            {"filename": str(self.b_path), "format": "qcow2", "backing-filename": str(self.base)},
            {"filename": str(self.base), "format": "raw"},
        ]
        with patch.object(refs, "command", return_value=json.dumps(chain)) as query:
            result = refs.image_chain(self.b_path, before_start=True)
        self.assertEqual(result, self.capture)
        self.assertNotIn("--force-share", query.call_args.args[0])

    def test_capture_is_durable_before_bounded_start_and_waits_release_graph_lock(self):
        self.b["network"] = {"name": "fixture-network"}
        backend = Backend(self.store, self.b)
        backend.storage = Storage(self.root)
        template = self.root / "test.ks"
        template.write_text("@@SSH_USER@@\n@@SSH_PUBLIC_KEY@@\n@@NETWORK_CONFIGURATION@@\n")
        platform = {
            "install_source": "/fixture.iso", "kickstart": str(template),
            "ssh_user": "molecule", "disk_size_gb": 20, "memory_mb": 2048,
            "vcpus": 2, "install_timeout": 60,
        }
        chain = [
            {"filename": str(self.b_path), "format": "qcow2", "backing-filename": str(self.base)},
            {"filename": str(self.base), "format": "raw"},
        ]
        events = []
        guest_state = ["running"]

        def query(argv, **kwargs):
            if argv[0] == "ssh-keygen":
                Path(argv[-1]).touch()
                Path(argv[-1] + ".pub").write_text("fixture-public-key")
            elif argv[0] == "virt-install":
                events.append("start")
                with self.assertRaises(RunError), lock(self.store.root / ".storage-graph.lock", blocking=False):
                    pass
                self.assertEqual(
                    self.store.load(self.b["id"])["guests"][0]["disks"][0]["image_chain"],
                    self.capture,
                )
                self.assertNotIn("--wait", argv)
                self.assertEqual(kwargs["timeout"], 60)
            elif "domstate" in argv:
                return guest_state[0]
            elif "start" in argv:
                events.append("final-boot")
                with self.assertRaises(RunError), lock(self.store.root / ".storage-graph.lock", blocking=False):
                    pass
            elif argv[0] == "ssh":
                events.append("ssh")
                with lock(self.store.root / ".storage-graph.lock", blocking=False):
                    pass
            else:
                self.fail("Unexpected command: " + repr(argv))
            return ""

        def prepare(*args, **kwargs):
            events.append("prepare")
            with lock(self.store.root / ".storage-graph.lock", blocking=False):
                pass

        with patch.object(backend, "disk_command", side_effect=prepare), \
                patch.object(backend, "verify_disk"), patch.object(backend, "owned_domain", return_value=ET.Element("domain")), \
                patch("isolated_runs.backends.command", side_effect=query), \
                patch.object(refs, "command", return_value=json.dumps(chain)):
            for value in ("running", "shut off"):
                with self.subTest(guest_state=value):
                    events.clear()
                    guest_state[0] = value
                    backend.provision_domain(self.guest, platform, 0)
                    expected = ["prepare", "start"]
                    if value == "shut off":
                        expected.append("final-boot")
                    self.assertEqual(events, expected + ["ssh"])


if __name__ == "__main__":
    unittest.main()
