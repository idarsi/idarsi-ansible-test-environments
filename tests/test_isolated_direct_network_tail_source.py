"""Producing-source reader fixtures: temporary bytes only, never execute sources."""

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import direct_network_tail_source as source
from isolated_runs.state import RunError


class ApprovedMetadataTests(unittest.TestCase):
    def test_embedded_definition_has_exact_thirteen_paths_and_approved_digest(self):
        definition = source.approved_definition()
        self.assertEqual(len(definition), 13)
        self.assertTrue(all(not Path(name).is_absolute() for name in definition))
        self.assertEqual(
            source.composite(definition),
            "4f4af9b019ca41ea238b3c581ed8e6b80ab89eba97a27a556189fa9a790642c0",
        )


class ProducingSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.contents = {name: ("never execute: " + name).encode() for name in source.FILES}
        self.definition = {
            name: {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            for name, content in self.contents.items()
        }
        for name, content in self.contents.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o600)
        self.spec = {name: (item["bytes"], item["sha256"]) for name, item in self.definition.items()}
        self.digest = source.composite(self.definition)
        self.addCleanup(patch.stopall)
        patch.object(source, "FILES", self.spec).start()
        patch.object(source, "SUBSET_DIGEST", self.digest).start()

    def test_verified_raw_bytes_receipt_without_import_execution_or_configuration(self):
        with patch("subprocess.run") as command, patch("runpy.run_path") as execute:
            receipt = source.verify_source(self.root)
            command.assert_not_called()
            execute.assert_not_called()
        self.assertEqual(receipt["subset_digest"], self.digest)
        self.assertEqual(receipt["root"]["path"], str(self.root))
        self.assertEqual(receipt["root"]["inode"], self.root.stat().st_ino)
        self.assertIn("not-historical-execution-attestation", receipt["provenance"])

    def test_missing_relative_traversal_and_symlinked_root_are_refused(self):
        for value in (None, "relative", str(self.root / ".." / self.root.name), self.root / "missing"):
            with self.subTest(value=str(value)), self.assertRaises(RunError):
                source.verify_source(value)
        link = self.root / "linked"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(RunError):
            source.verify_source(link)

    def test_file_and_directory_symlinks_hardlinks_and_fifo_refuse(self):
        name = next(iter(self.contents))
        path = self.root / name
        original = path.read_bytes()
        path.unlink()
        path.symlink_to(self.root / "scripts/scenario-context")
        with self.assertRaises(RunError):
            source.verify_source(self.root)
        path.unlink()
        os.mkfifo(path, mode=0o600)
        with self.assertRaises(RunError):
            source.verify_source(self.root)
        path.unlink()
        path.write_bytes(original)
        path.chmod(0o600)
        os.link(path, self.root / "another-hardlink")
        with self.assertRaises(RunError):
            source.verify_source(self.root)
        (self.root / "another-hardlink").unlink()
        directory = self.root / "scripts/isolated_runs"
        directory.rename(self.root / "elsewhere")
        directory.symlink_to(self.root / "elsewhere", target_is_directory=True)
        with self.assertRaises(RunError):
            source.verify_source(self.root)

    def test_changed_bytes_length_perms_owner_and_definition_are_refused(self):
        path = self.root / next(iter(self.contents))
        original = path.read_bytes()
        for content in (original + b"extra", b"X" * len(original)):
            path.write_bytes(content)
            with self.subTest(content=len(content)), self.assertRaises(RunError):
                source.verify_source(self.root)
        path.write_bytes(original)
        for mode in (0o620, 0o602, 0o4600, 0o2600):
            path.chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(RunError):
                source.verify_source(self.root)
        path.chmod(0o600)
        self.root.chmod(0o770)
        with self.assertRaises(RunError):
            source.verify_source(self.root)
        self.root.chmod(0o700)
        real_fstat = source.os.fstat

        def foreign_owner(fd):
            info = real_fstat(fd)
            if info.st_ino == path.stat().st_ino:
                values = list(info)
                values[4] = os.getuid() + 1
                return os.stat_result(values)
            return info

        with patch.object(source.os, "fstat", side_effect=foreign_owner), self.assertRaises(RunError):
            source.verify_source(self.root)
        with patch.object(source, "SUBSET_DIGEST", "0" * 64), self.assertRaisesRegex(RunError, "definition_changed"):
            source.verify_source(self.root)

    def test_file_replacement_during_read_and_late_content_mutation_refuse(self):
        path = self.root / next(iter(self.contents))
        original_stat = source.os.stat
        changed = [False]

        def replace(name, *args, **kwargs):
            if name == path.name and kwargs.get("dir_fd") is not None and not changed[0]:
                changed[0] = True
                replacement = self.root / "replacement"
                replacement.write_bytes(path.read_bytes())
                replacement.chmod(0o600)
                replacement.replace(path)
            return original_stat(name, *args, **kwargs)

        with patch.object(source.os, "stat", side_effect=replace), self.assertRaisesRegex(RunError, "changed_during_read"):
            source.verify_source(self.root)
        changed[0] = False

        def mutate_earlier_file(name, *args, **kwargs):
            if name == "scenario-context" and kwargs.get("dir_fd") is not None and not changed[0]:
                changed[0] = True
                path.write_bytes(b"X" * len(path.read_bytes()))
            return original_stat(name, *args, **kwargs)

        with patch.object(source.os, "stat", side_effect=mutate_earlier_file), self.assertRaisesRegex(RunError, "changed_during_read"):
            source.verify_source(self.root)

if __name__ == "__main__":
    unittest.main()
