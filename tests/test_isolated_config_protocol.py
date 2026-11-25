"""Strict config-bridge protocol tests; no actual Molecule or backend execution."""

import argparse
import contextlib
import copy
import io
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
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
                ] + ([] if direct else ["--supervised"]))
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


class BridgeBindingTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "fixture_bridge", cli.REPO / "scripts/isolated_runs/molecule_config.py",
        )
        self.bridge = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {
            "molecule.config": SimpleNamespace(Config=object),
            "molecule.shell": SimpleNamespace(LOCAL_CONFIG=None),
        }):
            spec.loader.exec_module(self.bridge)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bridge.__file__ = str(self.root / "scripts/isolated_runs/molecule_config.py")

    def controller(self, lane):
        prefix = self.root / ".venv" / lane
        (prefix / "bin").mkdir(parents=True, exist_ok=True)
        (prefix / "bin/python3").symlink_to(sys.executable)
        return prefix

    def invoke(
        self, environment, prefix, *, supervised=True, config_env=None,
        base_prefix="/fixture/system", executable=None,
    ):
        config = Mock()
        config.config_data = {"scenario": {"test_sequence": ["test"]}}
        config._get_defaults.return_value = {"scenario": {"test_sequence": ["test"]}}
        config.is_parallel = False
        config.env = {"MOLECULE_FILE": "/fixture/molecule.yml", **(config_env or {})}
        config.scenario.name = "fixture"
        config.scenario.ephemeral_directory = "/fixture/ephemeral"
        config.project_directory = "/fixture/role"
        with patch.dict(self.bridge.os.environ, environment, clear=True), \
                patch.object(self.bridge.sys, "argv", ["bridge", "/fixture/source"] + (
                    ["--supervised"] if supervised else []
                )), \
                patch.object(self.bridge.sys, "prefix", str(prefix)), \
                patch.object(self.bridge.sys, "base_prefix", str(base_prefix)), \
                patch.object(self.bridge.sys, "executable", str(executable or prefix / "bin/python3")), \
                patch.object(self.bridge.sys, "__stdout__", io.StringIO()) as output, \
                patch.object(self.bridge.sys, "__stderr__", io.StringIO()), \
                patch.object(self.bridge, "ManagedConfig", return_value=config) as constructor:
            try:
                self.bridge.main()
            except SystemExit:
                constructor.assert_not_called()
                raise
        return json.loads(output.getvalue()), config

    def test_actual_current_next_bindings_override_config_without_environment_leak(self):
        for lane in ("ansible-current", "ansible-next"):
            prefix = self.controller(lane)
            environment = {
                "VIRTUAL_ENV": str(prefix), "IDARSI_TEST_ENVIRONMENT": str(self.root),
                "UNRELATED_SECRET": PRIVATE,
            }
            for config_env in ({}, {"VIRTUAL_ENV": "wrong", "IDARSI_TEST_ENVIRONMENT": "wrong"}):
                data, config = self.invoke(environment, prefix, config_env=config_env)
                self.assertEqual(data["_idarsi_effective_env"], {
                    "MOLECULE_FILE": "/fixture/molecule.yml",
                    "VIRTUAL_ENV": str(prefix), "IDARSI_TEST_ENVIRONMENT": str(self.root),
                })
                self.assertNotIn(PRIVATE, json.dumps(data))
                self.assertEqual(config.env.get("VIRTUAL_ENV"), config_env.get("VIRTUAL_ENV"))

    def test_approved_controller_alias_matches_real_prefix_for_each_lane(self):
        shared = self.root / "approved-controllers"
        shared.mkdir()
        (self.root / ".venv").symlink_to(shared, target_is_directory=True)
        for lane in ("ansible-min", "ansible-current", "ansible-next"):
            prefix = self.controller(lane).resolve(strict=True)
            for activation in (prefix, self.root / ".venv" / lane):
                with self.subTest(lane=lane, activation=activation):
                    environment = {
                        "VIRTUAL_ENV": str(activation), "IDARSI_TEST_ENVIRONMENT": str(self.root),
                    }
                    data, _ = self.invoke(environment, prefix)
                    self.assertEqual(data["_idarsi_effective_env"]["VIRTUAL_ENV"], str(activation))

    def test_alias_binding_still_refuses_unapproved_or_unbound_controller(self):
        shared = self.root / "approved-controllers"
        shared.mkdir()
        alias = self.root / ".venv"
        alias.symlink_to(shared, target_is_directory=True)
        prefix = self.controller("ansible-current").resolve(strict=True)
        valid = {"VIRTUAL_ENV": str(prefix), "IDARSI_TEST_ENVIRONMENT": str(self.root)}
        other = self.root / "unapproved"
        (other / "bin").mkdir(parents=True)
        (other / "bin/python3").symlink_to(sys.executable)
        wrong_root = self.root / "wrong-helper"
        wrong_root.mkdir()
        for environment, actual, base, executable in (
            ({**valid, "IDARSI_TEST_ENVIRONMENT": str(wrong_root)}, prefix, "/fixture/system", None),
            ({"IDARSI_TEST_ENVIRONMENT": str(self.root)}, prefix, "/fixture/system", None),
            (valid, other, "/fixture/system", None),
            ({**valid, "VIRTUAL_ENV": str(other)}, other, "/fixture/system", None),
            (valid, prefix, prefix, None),
            (valid, prefix, "/fixture/system", other / "bin/python3"),
            ({**valid, "VIRTUAL_ENV": "relative"}, prefix, "/fixture/system", None),
        ):
            with self.subTest(environment=environment, actual=actual), self.assertRaises(SystemExit):
                self.invoke(environment, actual, base_prefix=base, executable=executable)
        alias.unlink()
        with self.assertRaises(SystemExit):
            self.invoke(valid, prefix)
        alias.symlink_to(self.root / "missing-controllers", target_is_directory=True)
        with self.assertRaises(SystemExit):
            self.invoke(valid, prefix)

    def test_missing_or_broken_unrelated_lane_does_not_block_installed_lane(self):
        prefix = self.controller("ansible-current")
        (self.root / ".venv/ansible-next").symlink_to(self.root / "missing-lane")
        self.invoke({"VIRTUAL_ENV": str(prefix), "IDARSI_TEST_ENVIRONMENT": str(self.root)}, prefix)

    def test_supervised_missing_or_conflicting_actual_bindings_fail_before_config(self):
        prefix = self.controller("ansible-current")
        valid = {"VIRTUAL_ENV": str(prefix), "IDARSI_TEST_ENVIRONMENT": str(self.root)}
        for key in valid:
            for value in (None, "", "relative", str(self.root / "missing"), str(self.root)):
                environment = dict(valid)
                if value is None:
                    del environment[key]
                else:
                    environment[key] = value
                if environment == valid:
                    continue
                with self.subTest(key=key, value=value), self.assertRaises(SystemExit):
                    self.invoke(environment, prefix)
        wrong_prefix = self.controller("ansible-next")
        with self.assertRaises(SystemExit):
            self.invoke(valid, wrong_prefix)
        with self.assertRaises(SystemExit):
            self.invoke(valid, prefix, base_prefix=prefix)
        (prefix / "bin/python3").unlink()
        with self.assertRaises(SystemExit):
            self.invoke(valid, prefix)

    def test_direct_missing_activation_remains_compatible(self):
        data, _ = self.invoke({}, self.root, supervised=False)
        self.assertEqual(data["_idarsi_effective_env"], {"MOLECULE_FILE": "/fixture/molecule.yml"})

    def test_managed_environment_does_not_replace_conflicting_or_missing_helper(self):
        for environment in (
            {"IDARSI_TEST_ENVIRONMENT": ""}, {"IDARSI_TEST_ENVIRONMENT": "/fixture/wrong"},
        ):
            with patch.dict(cli.os.environ, environment, clear=True), self.assertRaises(RunError):
                cli.managed_environment()
        with patch.dict(cli.os.environ, {}, clear=True):
            self.assertNotIn("IDARSI_TEST_ENVIRONMENT", cli.managed_environment())

    def test_bridge_binding_failure_stops_run_before_allocation_and_workers(self):
        prefix = self.controller("ansible-current")
        args = SimpleNamespace(role=str(self.root), scenario="fixture", backend="kvm")
        for environment in (
            {}, {"VIRTUAL_ENV": str(prefix), "IDARSI_TEST_ENVIRONMENT": "/fixture/wrong"},
        ):
            store = Mock()

            def bridge_command(*args, **kwargs):
                try:
                    self.invoke(environment, prefix)
                except SystemExit:
                    raise RunError("bridge rejected") from None

            with patch.object(cli.shutil, "which", return_value="/fixture/tool"), \
                    patch.object(cli, "managed_environment", return_value=environment), \
                    patch.object(cli, "command", side_effect=bridge_command), \
                    patch.object(cli, "spawn") as spawn, \
                    patch.object(cli, "Backend") as backend, \
                    self.assertRaises(RunError):
                cli.run(args, store)
            self.assertEqual(store.mock_calls, [])
            spawn.assert_not_called()
            backend.assert_not_called()


if __name__ == "__main__":
    unittest.main()
