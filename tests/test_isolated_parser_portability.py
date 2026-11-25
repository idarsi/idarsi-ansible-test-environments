"""CI-like real-parser checks without activation or an approved helper layout."""

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(importlib.util.find_spec("molecule"), "Requires installed Molecule, as in CI")
class PortableParserLayoutTests(unittest.TestCase):
    def test_real_parser_regressions_run_without_controller_and_production_still_refuses(self):
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="idarsi-portable-parser-") as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            shutil.copytree(
                repository / "scripts/isolated_runs", root / "scripts/isolated_runs",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            shutil.copytree(repository / "molecule/managed", root / "molecule/managed")
            for name in ("molecule-managed-podman", "molecule-managed-kvm"):
                destination = root / "examples" / name
                destination.mkdir(parents=True)
                shutil.copy2(repository / "examples" / name / "molecule.yml", destination)
            (root / "tests").mkdir()
            for name in ("config_bridge_fixture.py", "test_isolated_safety.py", "test_isolated_guest_control.py"):
                shutil.copy2(repository / "tests" / name, root / "tests" / name)
            environment = {
                key: value for key, value in os.environ.items()
                if key != "VIRTUAL_ENV" and not key.startswith(("IDARSI_", "MOLECULE_"))
            }
            environment.update(PYTHONPATH=str(root / "tests"), PYTHONDONTWRITEBYTECODE="1")
            result = subprocess.run(
                [sys.executable, "-B", "-m", "unittest",
                 "test_isolated_safety.EffectiveConfigTests",
                 "test_isolated_guest_control.GuestControlTests.test_real_supervisor_and_generation_configurations_compare_without_losing_binding",
                 "test_isolated_guest_control.GuestControlTests.test_real_quoted_dependency_command_relocates_only_ephemeral_arguments",
                 "-v"],
                cwd=root, env=environment, capture_output=True, timeout=60, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(b"Ran 5 tests", result.stderr)
            self.assertNotIn(b"skipped", result.stderr)
            # No production override: the same unmodified bridge and real
            # interpreter still reject missing controller authority.
            denied = subprocess.run(
                [sys.executable, "-B", str(root / "scripts/isolated_runs/molecule_config.py"),
                 "/unused/molecule.yml", "--supervised"],
                cwd=root, env=environment, capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(denied.returncode, 1)
            self.assertEqual(denied.stdout, b"")
            self.assertEqual(denied.stderr.strip(), b"controller_binding_missing")
            self.assertFalse((root / ".venv").exists())


if __name__ == "__main__":
    unittest.main()
