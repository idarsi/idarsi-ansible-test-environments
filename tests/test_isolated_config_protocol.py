"""Strict config-bridge protocol tests; no actual Molecule or backend execution."""

import argparse
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import cli, context
from isolated_runs.state import RunError

PRIVATE = "fixture-credential /private/fixture/config.yml"
INVALID = (
    "", " \n\t ", PRIVATE, "warning " + PRIVATE + "\n{}",
    "{}\ntrailing " + PRIVATE, '{"credential":"' + PRIVATE + '",',
)


class ConfigProtocolTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.role = Path(temporary.name)
        self.environment = {"FIXTURE": "value", "MOLECULE_EPHEMERAL_DIRECTORY": "/fixture/original"}
        self.valid = {
            "driver": {"name": "default", "options": {"managed": True}},
            "provisioner": {"playbooks": {
                action: str(cli.REPO / "molecule/managed" / (action + ".yml"))
                for action in ("create", "destroy")
            }},
            "_idarsi_effective_env": {"credential": PRIVATE},
        }

    def test_empty_and_malformed_responses_fail_once_without_payload_or_chain(self):
        for response in INVALID:
            with self.subTest(response=response), patch.object(cli, "command", return_value=response) as command:
                with self.assertRaises(RunError) as caught:
                    cli.parse_configuration(self.role, "kvm-fixture", self.environment)
                reason = "empty" if not response.strip() else "malformed"
                self.assertEqual(str(caught.exception), "Molecule config bridge returned " + reason + " JSON response")
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertIsNone(caught.exception.__cause__)
                self.assertNotIn(PRIVATE, str(caught.exception))
                command.assert_called_once()

    def test_warning_prefix_or_extra_json_document_is_not_salvaged(self):
        for response in ("warning\n" + json.dumps(self.valid), json.dumps(self.valid) + "\n{}"):
            with patch.object(cli, "command", return_value=response) as command, self.assertRaises(RunError):
                cli.parse_configuration(self.role, "kvm-fixture", self.environment)
            command.assert_called_once()

    def test_valid_mapping_and_environment_semantics_unchanged(self):
        for direct in (False, True):
            environment = copy.deepcopy(self.environment)
            with self.subTest(direct=direct), patch.object(cli, "command", return_value=json.dumps(self.valid)) as command:
                self.assertEqual(cli.parse_configuration(self.role, "kvm-fixture", environment, direct=direct), self.valid)
                command.assert_called_once()
                arguments, keywords = command.call_args
                self.assertEqual(arguments[0], [
                    "python3", str(cli.REPO / "scripts/isolated_runs/molecule_config.py"),
                    str(self.role / "molecule/kvm-fixture/molecule.yml"),
                ])
                self.assertEqual(keywords["cwd"], str(self.role))
                if direct:
                    self.assertEqual(keywords["env"], environment)
                else:
                    ephemeral = Path(keywords["env"]["MOLECULE_EPHEMERAL_DIRECTORY"])
                    self.assertEqual(ephemeral.name, "ephemeral")
                    self.assertNotEqual(str(ephemeral), environment["MOLECULE_EPHEMERAL_DIRECTORY"])
                    self.assertFalse(ephemeral.parent.exists())
                self.assertEqual(environment, self.environment)

    def test_nonmapping_json_keeps_existing_guard(self):
        for value in (None, [], "text", 7, True):
            with self.subTest(value=value), patch.object(cli, "command", return_value=json.dumps(value)):
                with self.assertRaisesRegex(RunError, "^Scenario config must be a mapping$"):
                    cli.parse_configuration(self.role, "kvm-fixture", self.environment)

    def test_child_failure_and_unrelated_exceptions_are_not_reclassified(self):
        for failure in (RunError("existing child failure"), KeyboardInterrupt()):
            with patch.object(cli, "command", side_effect=failure) as command:
                with self.assertRaises(type(failure)) as caught:
                    cli.parse_configuration(self.role, "kvm-fixture", self.environment)
                self.assertIs(caught.exception, failure)
                command.assert_called_once()

    def test_malformed_response_stops_real_run_before_allocation_or_lifecycle(self):
        args = argparse.Namespace(role=str(self.role), scenario="kvm-fixture", backend="kvm")
        for response in INVALID:
            store = Mock()
            with self.subTest(response=response), \
                    patch.object(cli.shutil, "which", return_value="/fixture/tool"), \
                    patch.object(cli, "managed_environment", return_value=self.environment), \
                    patch.object(cli, "command", return_value=response) as command, \
                    patch.object(cli, "validate_platforms") as platforms, \
                    patch.object(cli, "Backend") as backend, patch.object(cli, "spawn") as spawn:
                with self.assertRaises(RunError):
                    cli.run(args, store)
                command.assert_called_once()
                store.assert_not_called()
                self.assertEqual(store.mock_calls, [])
                platforms.assert_not_called()
                backend.assert_not_called()
                spawn.assert_not_called()

    def test_existing_cli_error_boundary_never_emits_raw_response_or_traceback(self):
        for response in INVALID:
            store = Mock()
            with self.subTest(response=response), patch.object(cli, "Store", return_value=store), \
                    patch.object(cli.shutil, "which", return_value="/fixture/tool"), \
                    patch.object(cli, "managed_environment", return_value=self.environment), \
                    patch.object(cli, "command", return_value=response) as command, \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    contextlib.redirect_stderr(io.StringIO()) as errors:
                code = cli.main(["run", "--backend", "kvm", "--scenario", "kvm-fixture", str(self.role)])
                self.assertEqual(code, 1)
                self.assertEqual(output.getvalue(), "")
                reason = "empty" if not response.strip() else "malformed"
                self.assertEqual(errors.getvalue(), "test-run: Molecule config bridge returned " + reason + " JSON response\n")
                self.assertNotIn(PRIVATE, errors.getvalue())
                self.assertNotIn("Traceback", errors.getvalue())
                self.assertEqual(store.mock_calls, [])
                command.assert_called_once()

    def test_context_resolution_fails_before_validation_or_store_use(self):
        args = argparse.Namespace(role=str(self.role), scenario="kvm-fixture", backend="kvm")
        for response in INVALID:
            store = Mock()
            with self.subTest(response=response), patch.dict(context.os.environ, self.environment, clear=True), \
                    patch.object(cli, "command", return_value=response) as command, \
                    patch.object(context, "validate_platforms") as platforms, \
                    patch.object(context, "Backend") as backend:
                with self.assertRaises(RunError):
                    context.resolved(args, store)
                command.assert_called_once()
                self.assertEqual(command.call_args.kwargs["env"], self.environment)
                platforms.assert_not_called()
                backend.assert_not_called()
                self.assertEqual(store.mock_calls, [])


if __name__ == "__main__":
    unittest.main()
