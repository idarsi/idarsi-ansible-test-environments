"""Logical inventory names remain independent of physical resource identities."""

import argparse
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import cli, context
from isolated_runs.backends import kvm_instance, validate_platforms
from isolated_runs.state import RunError


class LogicalNamesTests(unittest.TestCase):
    @staticmethod
    def platform(backend, name):
        if backend == "podman":
            return {"name": name, "image": "test", "pre_build_image": True}
        return {"name": name, "image_path": __file__}

    def test_exact_ascii_names_one_through_63_characters(self):
        for backend in ("podman", "kvm"):
            for name in (
                "A", "A_b-" + "x" * 36, "A" * 41, "A" * 45, "A_b-" + "x" * 59,
                "podman-role-experimental-host-user-rocky10",
                "podman-role-experimental-rhel9-preset-rocky10",
            ):
                with self.subTest(backend=backend, name=name):
                    result = validate_platforms(backend, [self.platform(backend, name)], Path("/scenario"))
                    self.assertEqual(result[0]["name"], name)

    def test_invalid_names_keep_original_character_policy(self):
        for backend in ("podman", "kvm"):
            for name in (
                "A" * 64, None, 42, True, [], {}, "", "1node", "-node", "_node",
                "a/b", "a\\b", "a.b", "a\n", "a\nb", "a;id", "$(id)", "a b", "é", "aé", "Ａnode",
            ):
                with self.subTest(backend=backend, name=name), self.assertRaises(RunError):
                    validate_platforms(backend, [self.platform(backend, name)], Path("/scenario"))

    def test_counts_duplicates_and_backend_allowlists_unchanged(self):
        for backend in ("podman", "kvm"):
            platforms = [self.platform(backend, "node" + str(i)) for i in range(201)]
            for count in (1, 200):
                self.assertEqual(len(validate_platforms(backend, platforms[:count], Path("/scenario"))), count)
            for invalid in ([], platforms, [platforms[0], platforms[0]], {}, None):
                with self.subTest(backend=backend), self.assertRaises(RunError):
                    validate_platforms(backend, invalid, Path("/scenario"))
            wrong = {"vcpus": 2} if backend == "podman" else {"pre_build_image": True}
            with self.assertRaisesRegex(RunError, "Unsupported platform options"):
                validate_platforms(backend, [{**platforms[0], **wrong}], Path("/scenario"))

    def test_both_entrypoints_reject_before_allocation(self):
        args = argparse.Namespace(role=str(Path(__file__).parent), scenario="validation", backend="podman")
        config = {"platforms": [self.platform("podman", "A" * 64)]}
        store = Mock()
        with patch.object(cli, "parse_configuration", return_value=config), \
                patch.object(cli.shutil, "which", return_value="/fixture/tool"):
            with self.assertRaisesRegex(RunError, "Platform name"):
                cli.run(args, store)
        with patch.object(context, "parse_configuration", return_value=config):
            with self.assertRaisesRegex(RunError, "Platform name"):
                context.resolved(args, store)
        self.assertEqual(store.mock_calls, [])

    def test_authoritative_kvm_mapping_preserves_exact_logical_name_and_limits(self):
        name = "A_b-" + "x" * 59
        self.assertEqual(kvm_instance({"name": name, "ssh_user": "molecule"}, "10.0.0.0/24", 199, Path("/key")), {
            "instance": name, "address": "10.0.0.209", "user": "molecule",
            "port": "22", "identity_file": "/key",
        })
        for subnet, index in (("::/64", 0), ("10.0.0.0/16", 0), ("10.0.0.0/24", -1), ("10.0.0.0/24", 200)):
            with self.assertRaises(RunError):
                kvm_instance({"name": name, "ssh_user": "molecule"}, subnet, index, Path("/key"))


if __name__ == "__main__":
    unittest.main()
