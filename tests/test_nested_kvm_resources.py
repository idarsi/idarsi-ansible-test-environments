#!/usr/bin/env python3
"""VM-free tests for the nested KVM resource assertion parser."""

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("resource_check", ROOT / "scripts/check-nested-kvm-resources.py")
assert SPEC and SPEC.loader
RESOURCE_CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESOURCE_CHECK)


class ResourceAssertionsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.info = "Max memory: 2097152 KiB\nCPU(s): 2\n"
        self.block = "Capacity: 10737418240\n"

    def test_accepts_expected_blueprint_resources(self) -> None:
        RESOURCE_CHECK.check(self.info, self.block, 2048, 2, 10)

    def test_rejects_mismatched_blueprint_resource(self) -> None:
        with self.assertRaisesRegex(ValueError, "resource mismatch"):
            RESOURCE_CHECK.check(self.info, self.block, 1024, 2, 10)

    def test_rejects_missing_libvirt_field(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing CPU"):
            RESOURCE_CHECK.check("Max memory: 2097152 KiB", self.block, 2048, 2, 10)


if __name__ == "__main__":
    unittest.main()
