"""Production child bootstrap regressions with synthetic dependencies only."""

import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = "synthetic-confidential-chatter"
CHATTER = r'''
import atexit
import os
import subprocess
import sys

def extra_descriptors():
    result = []
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd > 2:
            try:
                os.fstat(fd)
            except OSError:
                continue
            result.append(fd)
    return result

assert all(not os.get_inheritable(fd) for fd in extra_descriptors())
subprocess.run([sys.executable, "-c", """
import os
for name in os.listdir('/proc/self/fd'):
    fd = int(name)
    if fd > 2:
        try:
            os.fstat(fd)
        except OSError:
            continue
        raise AssertionError('unexpected inherited descriptor')
"""], close_fds=False, check=True)

def chatter():
    text = "synthetic-confidential-chatter\n"
    if os.environ.get("FORCE_COLOR") == "1":
        text = "\x1b[31m" + text + "\x1b[0m"
    for stream in (sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__):
        stream.write(text)
    os.write(1, text.encode())
    os.write(2, text.encode())
    subprocess.run([sys.executable, "-c",
                    "print('synthetic-confidential-chatter')"], check=True)

chatter()
atexit.register(chatter)
# Model Molecule's stdout-backed console replacing both Python streams.
if os.environ.get("FIXTURE_REPLACE_STREAMS", "1") == "1":
    sys.stderr = sys.stdout
'''
CONFIG = r'''
class Config:
    def __init__(self, source, args, command_args):
        chatter()
        assert command_args == {"parallel": False}
        self.config_data = self._get_config()
        self.is_parallel = False
        self.env = {}
        self.project_directory = "/fixture/role"
        self.scenario = type("Scenario", (), {
            "name": "fixture", "ephemeral_directory": "/fixture/ephemeral",
        })()

    def _get_config(self):
        return {"scenario": {"test_sequence": ["test"]}}

    def _get_defaults(self):
        return self._get_config()
'''


class ConfigStdoutTests(unittest.TestCase):
    interpreter = sys.executable

    @contextlib.contextmanager
    def fixture(self, config=CONFIG, **environment):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "molecule"
            package.mkdir()
            (package / "__init__.py").write_text(CHATTER)
            (package / "config.py").write_text("from . import chatter\n" + config)
            (package / "shell.py").write_text("from . import chatter\nchatter()\nLOCAL_CONFIG = None\n")
            environment = dict(os.environ, PYTHONPATH=temporary, **environment)
            environment.pop("PYTHONUNBUFFERED", None)
            yield environment

    def arguments(self, *, unbuffered=False):
        return [str(self.interpreter), "-B"] + (["-u"] if unbuffered else []) + [
            str(ROOT / "scripts/isolated_runs/molecule_config.py"), "/fixture/source",
        ]

    def test_production_bootstrap_keeps_one_json_through_shutdown(self):
        for replaced_streams in ("0", "1"):
            for unbuffered in (False, True):
                for color in ("0", "1"):
                    with self.subTest(replaced_streams=replaced_streams, unbuffered=unbuffered, color=color), \
                            self.fixture(FORCE_COLOR=color, FIXTURE_REPLACE_STREAMS=replaced_streams) as environment:
                        child = subprocess.run(
                            self.arguments(unbuffered=unbuffered),
                            env=environment, capture_output=True, text=True, timeout=20,
                        )
                        self.assertEqual(child.returncode, 0, child.stderr)
                        data = json.loads(child.stdout)
                        self.assertEqual(data["_idarsi_effective_scenario"], "fixture")
                        self.assertTrue(child.stdout.endswith("\n"))
                        self.assertNotIn(PRIVATE, child.stdout + child.stderr)
                        self.assertEqual(child.stderr, "")

    def test_failures_are_finite_and_never_emit_partial_serialization(self):
        for config, reason in (
            (CONFIG.replace('self.env = {}', 'self.env = {"secret": object()}'), "config_bridge_failed"),
            ("raise RuntimeError(" + repr(PRIVATE) + ")", "config_bridge_failed"),
            (CONFIG.replace('self.is_parallel = False', 'self.is_parallel = True'),
             "Managed runs reject parallel/shared_state configuration"),
        ):
            with self.subTest(reason=reason), self.fixture(config) as environment:
                child = subprocess.run(
                    self.arguments(), env=environment, capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(child.returncode, 1)
                self.assertEqual(child.stdout, "")
                self.assertEqual(child.stderr, reason + "\n")
                self.assertNotIn(PRIVATE, child.stdout + child.stderr)

    def test_broken_response_pipe_exits_without_traceback_or_retry(self):
        with self.fixture() as environment:
            with subprocess.Popen(
                self.arguments(), env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ) as child:
                child.stdout.close()
                self.assertEqual(child.wait(timeout=20), 1)
                self.assertEqual(child.stderr.read(), "config_bridge_failed\n")

    def test_existing_only_dispatch_keeps_its_separate_finite_refusal(self):
        with self.fixture("raise AssertionError('unexpected import')") as environment:
            child = subprocess.run(
                self.arguments() + ["--existing-only"],
                env=environment, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(child.returncode, 1)
            self.assertEqual(child.stdout, "")
            self.assertIn("AUTHORITY_PARSE", child.stderr)
            self.assertNotIn(PRIVATE, child.stderr)
            self.assertNotIn("Traceback", child.stderr)

    def test_importing_bridge_does_not_import_molecule_or_redirect_parent(self):
        with self.fixture("raise AssertionError('unexpected import')") as environment:
            code = (
                "import importlib.util, os, sys; "
                "original = [os.readlink('/proc/self/fd/'+str(fd)) for fd in (1,2)]; "
                "spec = importlib.util.spec_from_file_location('bridge', sys.argv[1]); "
                "spec.loader.exec_module(importlib.util.module_from_spec(spec)); "
                "assert 'molecule' not in sys.modules; "
                "assert original == [os.readlink('/proc/self/fd/'+str(fd)) for fd in (1,2)]; "
                "print('unchanged')"
            )
            arguments = self.arguments()
            child = subprocess.run(
                arguments[:2] + ["-c", code, arguments[2]],
                env=environment, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(child.returncode, 0, child.stderr)
            self.assertEqual(child.stdout, "unchanged\n")
            self.assertEqual(child.stderr, "")


class InstalledCurrentConfigStdoutTests(ConfigStdoutTests):
    interpreter = ROOT / ".venv/ansible-current/bin/python"

    def setUp(self):
        if not self.interpreter.is_file():
            self.skipTest("optional approved controller unavailable: " + str(self.interpreter))


class InstalledNextConfigStdoutTests(InstalledCurrentConfigStdoutTests):
    interpreter = ROOT / ".venv/ansible-next/bin/python"


class PortableCheckoutTests(unittest.TestCase):
    def test_no_controller_layout_keeps_mandatory_current_python_coverage(self):
        cases = unittest.defaultTestLoader.loadTestsFromTestCase(ConfigStdoutTests)
        result = unittest.TestResult()
        with patch.object(Path, "is_file", return_value=False), \
                patch.object(subprocess, "run", wraps=subprocess.run) as run:
            cases.run(result)
            self.assertEqual(result.testsRun, 5)
            self.assertEqual(result.skipped, [])
            self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
            # Eight mandatory buffering/color/stream replacement combinations.
            matrix_calls = [call for call in run.call_args_list
                            if "FIXTURE_REPLACE_STREAMS" in call.kwargs["env"]]
            self.assertEqual(len(matrix_calls), 8)
            self.assertTrue(all(call.args[0][0] == sys.executable for call in run.call_args_list))
            for optional in (InstalledCurrentConfigStdoutTests, InstalledNextConfigStdoutTests):
                optional_result = unittest.TestResult()
                unittest.defaultTestLoader.loadTestsFromTestCase(optional).run(optional_result)
                self.assertEqual(len(optional_result.skipped), 5)
                self.assertTrue(optional_result.wasSuccessful())


if __name__ == "__main__":
    unittest.main()
