"""Resource-free installed-library fixtures for the existing-only config bridge."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import existing_config as existing
from isolated_runs import readonly
from isolated_runs.state import RunError
from isolated_runs.guest_refusal import GuestRefusal, CODES, SCHEMA, parse


class ScratchTests(unittest.TestCase):
    def test_audit_guard_refuses_traversal_and_symlink_writes_outside_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            outside = root / "outside"
            outside.write_text("unchanged")
            (scratch / "alias").symlink_to(outside)
            for candidate in (str(outside), str(scratch / "../outside"), str(scratch / "alias")):
                program = (
                    "import sys; from pathlib import Path; "
                    "from isolated_runs.existing_config import install_guard; "
                    "from isolated_runs.guest_refusal import GuestRefusal; "
                    "install_guard(Path(" + repr(str(scratch)) + "), []); "
                    "\ntry:\n Path(" + repr(candidate) + ").write_text('forbidden')"
                    "\nexcept GuestRefusal as error:\n"
                    " sys.exit(0 if error.code == 'READONLY_STATE' else 2)"
                    "\nelse:\n sys.exit(3)"
                )
                child = subprocess.run(
                    [sys.executable, "-B", "-c", program], capture_output=True, check=False,
                    env={**os.environ, "PYTHONPATH": str(existing.REPO / "scripts")},
                )
                self.assertEqual(child.returncode, 0, child.stderr.decode())
                self.assertEqual(outside.read_text(), "unchanged")

    def test_refusal_process_boundaries_and_strict_parent_envelope_propagation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = {**os.environ, "TMPDIR": str(root)}
            cases = [
                (OSError("CANARY launch"), "PROCESS_SUPERVISION"),
                (subprocess.TimeoutExpired("CANARY command", 1), "PROCESS_SUPERVISION"),
                (subprocess.CompletedProcess([], -15, b"", b"CANARY"), "PROCESS_SUPERVISION"),
                (subprocess.CompletedProcess([], 0, b"x" * (existing.LIMIT + 1), b""), "PROCESS_SUPERVISION"),
                (subprocess.CompletedProcess([], 0, b"", b"x" * (existing.LIMIT + 1)), "PROCESS_SUPERVISION"),
                (subprocess.CompletedProcess([], 1, b"", b"legacy CANARY"), "UNKNOWN_REFUSAL"),
                (subprocess.CompletedProcess([], 0, b"CANARY invalid JSON", b""), "AUTHORITY_PARSE"),
            ]
            for code in CODES:
                wire = json.dumps({"schema": SCHEMA, "code": code}).encode()
                cases.extend([
                    (subprocess.CompletedProcess([], 1, b"", wire), code),
                    (subprocess.CompletedProcess([], 1, b"CANARY stdout", wire), "UNKNOWN_REFUSAL"),
                    (subprocess.CompletedProcess([], 2, b"", wire), "UNKNOWN_REFUSAL"),
                    (subprocess.CompletedProcess([], True, b"", wire), "UNKNOWN_REFUSAL"),
                    (subprocess.CompletedProcess([], False, b"", wire), "UNKNOWN_REFUSAL"),
                ])
            for response, expected in cases:
                with self.subTest(expected=expected), \
                        patch.object(existing, "prevalidate"), \
                        patch.object(existing.shutil, "which", return_value=sys.executable), \
                        patch.object(existing.subprocess, "run",
                                     side_effect=response if isinstance(response, Exception) else None,
                                     return_value=response):
                    with self.assertRaises(GuestRefusal) as refused:
                        existing.parse_existing_configuration(root, "fixture", environment, root)
                    self.assertEqual(refused.exception.code, expected)
                self.assertEqual(list(root.iterdir()), [])

    def test_refusal_wire_rejects_unknown_boolean_duplicate_extra_and_private_text(self):
        valid = json.dumps({"schema": SCHEMA, "code": "LOCK_BUSY"})
        for value in (
            "CANARY", "prefix" + valid, valid + "suffix", valid + "é" * 256,
            json.dumps({"schema": SCHEMA, "code": True}),
            json.dumps({"schema": SCHEMA, "code": "CANARY"}),
            json.dumps({"schema": SCHEMA, "code": "LOCK_BUSY", "extra": "CANARY"}),
            '{"schema":' + json.dumps(SCHEMA) + ',"code":"LOCK_BUSY","code":"SSH_MAPPING"}',
        ):
            self.assertEqual(parse(value), "UNKNOWN_REFUSAL")

    def test_refusal_real_existing_only_child_survives_parent_roundtrip_without_writes(self):
        original_run = subprocess.run
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = {**os.environ, "TMPDIR": str(root), "CANARY_ENV": "private"}
            for malformed, expected in ((False, "READONLY_STATE"), (True, "AUTHORITY_PARSE"), ("arguments", "AUTHORITY_PARSE")):
                def child(argv, **kwargs):
                    protocol = Path(argv[-1])
                    if malformed == "arguments":
                        argv = argv[:-1]
                    elif malformed:
                        protocol.write_text('{"CANARY":"not a valid private protocol"}')
                    else:
                        protocol.unlink()
                    result = original_run(argv, **kwargs)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, b"")
                    self.assertNotIn(b"CANARY", result.stderr)
                    self.assertEqual(json.loads(result.stderr), {"schema": SCHEMA, "code": expected})
                    return result

                before = snapshot(existing.REPO / "scripts/isolated_runs")
                with patch.object(existing, "prevalidate"), \
                        patch.object(existing.shutil, "which", return_value=sys.executable), \
                        patch.object(existing.subprocess, "run", side_effect=child):
                    with self.assertRaises(GuestRefusal) as refused:
                        existing.parse_existing_configuration(root, "fixture", environment, root)
                    self.assertEqual(refused.exception.code, expected)
                self.assertEqual(list(root.iterdir()), [])
                self.assertEqual(before, snapshot(existing.REPO / "scripts/isolated_runs"))

    def test_portable_temp_parent_selection_without_probe_or_initialization(self):
        with patch.object(existing.tempfile, "gettempdir", side_effect=AssertionError("probe forbidden")), \
                patch.object(Path, "mkdir", side_effect=AssertionError("mkdir forbidden")):
            self.assertEqual(existing.scratch_parent({}), Path("/tmp"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "not-a-directory"
            regular.write_text("fixture")
            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            self.assertEqual(existing.scratch_parent({"TMPDIR": str(root)}), root)
            for value in ("", "relative", str(root / "missing"), str(regular), str(alias)):
                with self.subTest(value=value), \
                        patch.object(existing, "prevalidate"), \
                        patch.object(existing.shutil, "which", return_value=sys.executable), \
                        patch.object(existing.tempfile, "TemporaryDirectory") as create:
                    with self.assertRaises((RunError, OSError)):
                        existing.parse_existing_configuration(
                            root, "fixture", {"PATH": os.environ["PATH"], "TMPDIR": value}, root,
                        )
                    create.assert_not_called()
            with patch.object(existing.os, "access", return_value=False), self.assertRaises(RunError):
                existing.scratch_parent({"TMPDIR": str(root)})

    def test_interpolation_environment_presence_values_and_restoration(self):
        with patch.dict(os.environ, {
            "PATH": "processing", "TMPDIR": "scratch", "ANSIBLE_LOCAL_TEMP": "scratch-local",
            "ANSIBLE_LOG_PATH": "scratch-log",
        }, clear=True):
            with existing.invocation_environment({"PATH": "original", "TMPDIR": "invocation"}):
                self.assertEqual(dict(os.environ), {"PATH": "original", "TMPDIR": "invocation"})
            self.assertEqual(dict(os.environ), {
                "PATH": "processing", "TMPDIR": "scratch", "ANSIBLE_LOCAL_TEMP": "scratch-local",
                "ANSIBLE_LOG_PATH": "scratch-log",
            })
            with existing.invocation_environment({"ANSIBLE_LOG_PATH": "invocation-log"}):
                self.assertEqual(dict(os.environ), {"ANSIBLE_LOG_PATH": "invocation-log"})
            self.assertEqual(os.environ["ANSIBLE_LOG_PATH"], "scratch-log")

    def test_wrapper_rejects_unexpected_arguments_without_running_tool(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.write_text("#!" + sys.executable + "\nraise RuntimeError('must not execute')\n")
            real.chmod(0o700)
            wrapper = root / "ansible-config"
            wrapper.write_text(existing.wrapper_source(real, os.environ["PATH"], root))
            wrapper.chmod(0o700)
            for args in ([], ["dump", "--format", "json"], ["--version"], ["secret"]):
                result = subprocess.run([str(wrapper)] + args, capture_output=True, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertEqual((result.stdout, result.stderr), (b"", b""))

    def test_scratch_cleanup_on_success_and_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = {**os.environ, "TMPDIR": str(root)}
            for response in (
                subprocess.CompletedProcess([], 1, b"", b"private exception"),
                subprocess.CompletedProcess([], 0, b"malformed private config", b""),
                subprocess.TimeoutExpired("fixture", 60),
                subprocess.CompletedProcess([], 0, b"{}", b""),
            ):
                def child(argv, **kwargs):
                    log = Path(argv[-1]).parent / "dependency.log"
                    log.write_text("private fixture log")
                    log.chmod(0o600)
                    if isinstance(response, Exception):
                        raise response
                    return response

                with patch.object(existing, "prevalidate"), \
                        patch.object(existing.shutil, "which", return_value=sys.executable), \
                        patch.object(existing.subprocess, "run", side_effect=child), \
                        patch("isolated_runs.cli.validate_configuration", return_value={"fixture": True}):
                    if not isinstance(response, Exception) and response.returncode == 0 and response.stdout == b"{}":
                        self.assertEqual(existing.parse_existing_configuration(root, "fixture", environment, root), {"fixture": True})
                    else:
                        with self.assertRaises((RunError, ValueError, subprocess.TimeoutExpired)):
                            existing.parse_existing_configuration(root, "fixture", environment, root)
                self.assertEqual(list(root.iterdir()), [])

    def test_wrapper_confines_child_log_and_sets_private_creation_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sentinel = root / "outside.log"
            sentinel.write_text("unchanged sentinel")
            real = root / "real"
            real.write_text(
                "#!" + sys.executable + "\n"
                "import os\nfrom pathlib import Path\n"
                "Path(os.environ['ANSIBLE_LOG_PATH']).write_text('fixture dependency log')\n",
            )
            real.chmod(0o700)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            wrapper = scratch / "ansible-config"
            wrapper.write_text(existing.wrapper_source(real, os.environ["PATH"], scratch))
            wrapper.chmod(0o700)
            result = subprocess.run(
                [str(wrapper), "dump"], env={**os.environ, "ANSIBLE_LOG_PATH": str(sentinel)},
                capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(sentinel.read_text(), "unchanged sentinel")
            self.assertEqual((scratch / "dependency.log").stat().st_mode & 0o777, 0o600)
            self.assertEqual(result.stdout, b"")


def snapshot(root):
    return {
        str(path.relative_to(root)): (
            path.lstat().st_mode,
            path.read_bytes() if path.is_file() and not path.is_symlink() else None,
            path.lstat().st_mtime_ns if path.is_file() else None,
        )
        for path in [root, *root.rglob("*")]
    }


class CleanLayoutTests(unittest.TestCase):
    def test_portable_units_and_wire_protocol_without_repository_venvs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            shutil.copytree(
                existing.REPO / "scripts/isolated_runs", root / "scripts/isolated_runs",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            (root / "tests").mkdir()
            for name in ("test_isolated_existing_config.py", "test_isolated_guest_validation.py"):
                shutil.copy2(existing.REPO / "tests" / name, root / "tests" / name)
            environment = {**os.environ, "PYTHONPATH": str(root / "tests")}
            environment.pop("IDARSI_TEST_INSTALLED_CONTROLLERS", None)
            result = subprocess.run(
                [sys.executable, "-B", "-m", "unittest",
                 "test_isolated_existing_config.ScratchTests",
                 "test_isolated_existing_config.InstalledBridgeTests",
                 "test_isolated_guest_validation.WireTests", "-v"],
                cwd=root, env=environment, capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertFalse((root / ".venv").exists())
            self.assertIn(b"IDARSI_TEST_INSTALLED_CONTROLLERS=1", result.stderr)
            self.assertIn(b"skipped=2", result.stderr)
            requested = subprocess.run(
                [sys.executable, "-B", "-m", "unittest",
                 "test_isolated_existing_config.InstalledBridgeTests", "-v"],
                cwd=root, env={**environment, "IDARSI_TEST_INSTALLED_CONTROLLERS": "1"},
                capture_output=True, timeout=30, check=False,
            )
            self.assertNotEqual(requested.returncode, 0)
            self.assertIn(b"BLOCKER/MISSING", requested.stderr)


class MoleculeStateReadTests(unittest.TestCase):
    def test_safe_non_authoritative_modes_without_relaxing_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state.yml"
            state.write_text("created: true\n")
            for mode in (0o600, 0o640, 0o644):
                state.chmod(mode)
                self.assertEqual(readonly.read_molecule_state(state, 100), b"created: true\n")
                if mode != 0o600:
                    with self.assertRaises(RunError):
                        readonly.read_file(state, 100)
            for mode in (0o666, 0o664, 0o660, 0o602, 0o620, 0o700, 0o645, 0o400):
                state.chmod(mode)
                with self.subTest(mode=oct(mode)), self.assertRaises(RunError):
                    readonly.read_molecule_state(state, 100)

    def test_state_symlinks_hardlinks_foreign_owner_and_size_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state.yml"
            state.write_text("created: true\n")
            state.chmod(0o644)
            alias = root / "alias"
            alias.symlink_to(state)
            with self.assertRaises(RunError):
                readonly.read_molecule_state(alias, 100)
            linked = root / "linked"
            os.link(state, linked)
            with self.assertRaises(RunError):
                readonly.read_molecule_state(state, 100)
            linked.unlink()
            info = state.stat()
            foreign = SimpleNamespace(
                st_uid=os.getuid() + 1, st_mode=info.st_mode,
                st_nlink=info.st_nlink, st_size=info.st_size,
            )
            with patch.object(readonly.os, "fstat", return_value=foreign), self.assertRaises(RunError):
                readonly.read_molecule_state(state, 100)
            with self.assertRaises(RunError):
                readonly.read_molecule_state(state, 1)


@unittest.skipUnless(
    os.environ.get("IDARSI_TEST_INSTALLED_CONTROLLERS") == "1",
    "requires explicit IDARSI_TEST_INSTALLED_CONTROLLERS=1 and all three approved installed lanes",
)
class InstalledBridgeTests(unittest.TestCase):
    """Actual approved controllers; private role/cache/state fixtures, never a VM."""

    def test_refusal_amendment_preserves_active_installed_bridge_success_and_source(self):
        with tempfile.TemporaryDirectory(prefix="idarsi-refusal-bridge-") as temporary:
            root = Path(temporary)
            role = root / "role"
            scenario = role / "molecule/kvm-refusal"
            scenario.mkdir(parents=True, mode=0o700)
            (role / ".hg").mkdir(mode=0o700)
            ephemeral = root / "ephemeral"
            (ephemeral / "inventory").mkdir(parents=True, mode=0o700)
            cache = root / "cache"
            for path in (cache, cache / "roles", cache / "collections", root / "scratch"):
                path.mkdir(mode=0o700)
            source = scenario / "molecule.yml"
            source.write_text(
                "---\nscenario:\n  name: kvm-refusal\ndriver:\n  name: default\n"
                "  safe_files:\n    - ${MOLECULE_EPHEMERAL_DIRECTORY}/collections/*\n"
                "platforms:\n  - name: node\n    image_path: /fixture/base.qcow2\n"
                "provisioner:\n  name: ansible\n  playbooks:\n"
                "    create: " + str(existing.REPO / "molecule/managed/create.yml") + "\n"
                "    destroy: " + str(existing.REPO / "molecule/managed/destroy.yml") + "\n"
                "  env:\n    IDARSI_MOLECULE_BACKEND: kvm\n"
            )
            env = {
                **os.environ, "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
                "VIRTUAL_ENV": sys.prefix, "IDARSI_TEST_ENVIRONMENT": str(existing.REPO),
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(existing.REPO / "scripts"),
                "ANSIBLE_HOME": str(cache), "TMPDIR": str(root / "scratch"),
                "MOLECULE_PROJECT_DIRECTORY": str(role), "MOLECULE_SCENARIO_DIRECTORY": str(scenario),
                "MOLECULE_SCENARIO_NAME": "kvm-refusal", "MOLECULE_EPHEMERAL_DIRECTORY": str(ephemeral),
                "MOLECULE_INSTANCE_CONFIG": str(ephemeral / "instance_config.yml"),
                "MOLECULE_FILE": str(ephemeral / "molecule.yml"),
            }
            common = "import os,json; from pathlib import Path; role=Path(" + repr(str(role)) + "); "
            normal = subprocess.run(
                [sys.executable, "-B", "-c", common +
                 "from isolated_runs.cli import parse_configuration; "
                 "print(json.dumps(parse_configuration(role,'kvm-refusal',dict(os.environ),direct=True)))"],
                cwd=role, env=env, capture_output=True, timeout=60, check=False,
            )
            self.assertEqual(normal.returncode, 0, "Ordinary fixture config parsing failed")
            before = snapshot(root)
            sources = snapshot(existing.REPO / "scripts/isolated_runs")
            actual = subprocess.run(
                [sys.executable, "-B", "-c", common +
                 "from isolated_runs.existing_config import parse_existing_configuration; "
                 "print(json.dumps(parse_existing_configuration(role,'kvm-refusal',dict(os.environ),Path("
                 + repr(str(ephemeral)) + "))))"],
                cwd=role, env=env, capture_output=True, timeout=60, check=False,
            )
            self.assertEqual(actual.returncode, 0, "Existing-only fixture config parsing failed")
            self.assertEqual(json.loads(actual.stdout), json.loads(normal.stdout))
            self.assertEqual(before, snapshot(root))
            self.assertEqual(sources, snapshot(existing.REPO / "scripts/isolated_runs"))

    def test_installed_lanes_equal_normal_parser_without_non_scratch_writes(self):
        for lane in ("ansible-min", "ansible-current", "ansible-next"):
            with self.subTest(lane=lane), tempfile.TemporaryDirectory(prefix="idarsi-existing-fixture-") as temporary:
                root = Path(temporary)
                try:
                    prefix = (existing.REPO / ".venv" / lane).resolve(strict=True)
                except (OSError, RuntimeError):
                    self.fail("BLOCKER/MISSING: explicitly requested installed controller " + lane)
                interpreter = prefix / "bin/python"
                if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
                    self.fail("BLOCKER/MISSING: installed controller interpreter " + lane)
                from isolated_runs.recovery import CONTROLLERS

                python, core, molecule = CONTROLLERS[lane]
                versions = subprocess.run(
                    [str(interpreter), "-B", "-c",
                     "import importlib.metadata as m,json,sys; "
                     "print(json.dumps([list(sys.version_info[:2]),m.version('ansible-core'),m.version('molecule')]))"],
                    capture_output=True, timeout=30, check=False,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                )
                if versions.returncode:
                    self.fail("BLOCKER/MISSING: installed controller packages " + lane)
                self.assertEqual(
                    json.loads(versions.stdout), [list(python), core, molecule],
                    "BLOCKER/INCOMPATIBLE: explicitly requested installed controller " + lane,
                )
                role = root / "role"
                scenario = role / "molecule/kvm-existing"
                scenario.mkdir(parents=True, mode=0o700)
                # Upstream local-base lookup starts at the discovered VCS root.
                (role / ".hg").mkdir(mode=0o700)
                ephemeral = root / "ephemeral"
                (ephemeral / "inventory").mkdir(parents=True, mode=0o700)
                state = ephemeral / "state.yml"
                for name in ("external.log", "dotenv.log"):
                    (root / name).write_text("fixture sentinel\n")
                    (root / name).chmod(0o600)
                cache = root / "ansible-cache"
                for path in (cache, cache / "roles", cache / "collections", root / "scratch-parent", root / "original-tmp"):
                    path.mkdir(mode=0o700)
                source = scenario / "molecule.yml"
                base = role / ".config/molecule/config.yml"
                base.parent.mkdir(parents=True, mode=0o700)
                base.write_text("provisioner:\n  env:\n    FIXTURE_BASE: original\n")
                source.write_text(
                    "---\nscenario:\n  name: kvm-existing\ndriver:\n  name: default\n"
                    "  safe_files:\n    - ${MOLECULE_EPHEMERAL_DIRECTORY}/collections/*\n"
                    "platforms:\n  - name: node\n    image_path: /fixture/base.qcow2\n"
                    "provisioner:\n  name: ansible\n  playbooks:\n"
                    "    create: " + str(existing.REPO / "molecule/managed/create.yml") + "\n"
                    "    destroy: " + str(existing.REPO / "molecule/managed/destroy.yml") + "\n"
                    "  env:\n    IDARSI_MOLECULE_BACKEND: kvm\n"
                    "    FIXTURE_PATH: ${PATH}\n    FIXTURE_TMP: ${TMPDIR}\n"
                    "    FIXTURE_LOCAL: ${ANSIBLE_LOCAL_TEMP}\n"
                    "    FIXTURE_LOG: ${ANSIBLE_LOG_PATH}\n"
                )
                env = {
                    **os.environ, "PATH": str(prefix / "bin") + os.pathsep + os.environ["PATH"],
                    "VIRTUAL_ENV": str(prefix), "IDARSI_TEST_ENVIRONMENT": str(existing.REPO),
                    "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(existing.REPO / "scripts"),
                    "ANSIBLE_HOME": str(cache), "TMPDIR": str(root / "scratch-parent"),
                    "ANSIBLE_LOCAL_TEMP": str(root / "original-tmp"),
                    "ANSIBLE_LOG_PATH": str(root / "external.log"),
                    "MOLECULE_PROJECT_DIRECTORY": str(role),
                    "MOLECULE_SCENARIO_DIRECTORY": str(scenario),
                    "MOLECULE_SCENARIO_NAME": "kvm-existing",
                    "MOLECULE_EPHEMERAL_DIRECTORY": str(ephemeral),
                    "MOLECULE_INSTANCE_CONFIG": str(ephemeral / "instance_config.yml"),
                    "MOLECULE_FILE": str(ephemeral / "molecule.yml"),
                    "MOLECULE_ENV_FILE": str(root / "fixture.env"),
                }
                # Exercise .env overrides before interpolation, not result rewriting.
                (root / "fixture.env").write_text(
                    "PATH: " + env["PATH"] + os.pathsep + str(root / "dotenv-path")
                    + "\nTMPDIR: " + str(root / "original-tmp")
                    + "\nANSIBLE_LOCAL_TEMP: " + str(root / "original-tmp")
                    + "\nANSIBLE_LOG_PATH: " + str(root / "dotenv.log") + "\n",
                )
                common = (
                    "import json, os; from pathlib import Path; os.umask(0o022); "
                    "from isolated_runs.cli import parse_configuration; "
                    "from isolated_runs.existing_config import parse_existing_configuration; "
                    "role=Path(" + repr(str(role)) + "); ephemeral=Path(" + repr(str(ephemeral)) + "); "
                )
                normal = subprocess.run(
                    [str(interpreter), "-B", "-c", common + "print(json.dumps(parse_configuration(role, 'kvm-existing', dict(os.environ), direct=True)))"],
                    env=env, cwd=role, capture_output=True, timeout=60, check=False,
                )
                self.assertEqual(normal.returncode, 0, normal.stderr.decode())
                # Unlike portable parser units, exercise the real supervised
                # controller policy with this actual installed lane/prefix.
                supervised = subprocess.run(
                    [str(interpreter), "-B", "-c", common
                     + "print(json.dumps(parse_configuration(role, 'kvm-existing', dict(os.environ))))"],
                    env=env, cwd=role, capture_output=True, timeout=60, check=False,
                )
                self.assertEqual(supervised.returncode, 0, supervised.stderr.decode())
                binding = json.loads(supervised.stdout)["_idarsi_effective_env"]
                self.assertEqual(binding["VIRTUAL_ENV"], str(prefix))
                self.assertEqual(binding["IDARSI_TEST_ENVIRONMENT"], str(existing.REPO))
                unbound = dict(env)
                unbound.pop("VIRTUAL_ENV")
                denied = subprocess.run(
                    [str(interpreter), "-B", "-c", common
                     + "parse_configuration(role, 'kvm-existing', dict(os.environ))"],
                    env=unbound, cwd=role, capture_output=True, timeout=60, check=False,
                )
                self.assertNotEqual(denied.returncode, 0)
                self.assertIn(b"controller_binding_missing", denied.stderr)
                if lane == "ansible-min":
                    self.assertEqual(state.stat().st_mode & 0o777, 0o644)
                expected = json.loads(normal.stdout)
                scenario_environment = expected.get("ansible", expected["provisioner"])["env"]
                self.assertEqual(scenario_environment["FIXTURE_LOG"], str(root / "dotenv.log"))
                before = snapshot(root)
                actual = subprocess.run(
                    [str(interpreter), "-B", "-c", common + "print(json.dumps(parse_existing_configuration(role, 'kvm-existing', dict(os.environ), ephemeral)))"],
                    env=env, cwd=role, capture_output=True, timeout=60, check=False,
                )
                self.assertEqual(actual.returncode, 0, actual.stderr.decode())
                self.assertEqual(json.loads(actual.stdout), expected)
                self.assertEqual(snapshot(root), before)
                # Installed merge/interpolation must observe current sources,
                # not a generated MOLECULE_FILE or cached manifest config.
                for changed in (source, base, root / "fixture.env"):
                    original = changed.read_text()
                    if changed == source:
                        modified = original.replace("name: node", "name: changed")
                    elif changed == base:
                        modified = original.replace("original", "changed")
                    else:
                        modified = original.replace("dotenv-path", "changed-dotenv-path")
                    changed.write_text(modified)
                    before = snapshot(root)
                    observed = subprocess.run(
                        [str(interpreter), "-B", "-c", common + "print(json.dumps(parse_existing_configuration(role, 'kvm-existing', dict(os.environ), ephemeral)))"],
                        env=env, cwd=role, capture_output=True, timeout=60, check=False,
                    )
                    self.assertEqual(observed.returncode, 0, observed.stderr.decode())
                    self.assertNotEqual(json.loads(observed.stdout), expected)
                    self.assertEqual(snapshot(root), before)
                    changed.write_text(original)
                for selector in ("MOLECULE_EPHEMERAL_DIRECTORY", "MOLECULE_FILE", "MOLECULE_SCENARIO_NAME"):
                    before = snapshot(root)
                    mismatch = subprocess.run(
                        [str(interpreter), "-B", "-c", common + "parse_existing_configuration(role, 'kvm-existing', dict(os.environ), ephemeral)"],
                        env={**env, selector: str(root / "wrong-selector")},
                        cwd=role, capture_output=True, timeout=60, check=False,
                    )
                    self.assertNotEqual(mismatch.returncode, 0)
                    self.assertEqual(snapshot(root), before)
                # Existing-only path must refuse missing state without initialization.
                state.unlink()
                before = snapshot(root)
                missing = subprocess.run(
                    [str(interpreter), "-B", "-c", common + "parse_existing_configuration(role, 'kvm-existing', dict(os.environ), ephemeral)"],
                    env=env, cwd=role, capture_output=True, timeout=60, check=False,
                )
                self.assertNotEqual(missing.returncode, 0)
                self.assertEqual(snapshot(root), before)
                # Missing inventory is not repaired.
                state.write_text("{}")
                state.chmod(0o600)
                (ephemeral / "inventory").rmdir()
                before = snapshot(root)
                missing = subprocess.run(
                    [str(interpreter), "-B", "-c", common + "parse_existing_configuration(role, 'kvm-existing', dict(os.environ), ephemeral)"],
                    env=env, cwd=role, capture_output=True, timeout=60, check=False,
                )
                self.assertNotEqual(missing.returncode, 0)
                self.assertEqual(snapshot(root), before)
                if lane != "ansible-min":
                    (ephemeral / "inventory").mkdir(mode=0o700)
                    (cache / "roles").rmdir()
                    before = snapshot(root)
                    missing = subprocess.run(
                        [str(interpreter), "-B", "-c", common + "parse_existing_configuration(role, 'kvm-existing', dict(os.environ), ephemeral)"],
                        env=env, cwd=role, capture_output=True, timeout=60, check=False,
                    )
                    self.assertNotEqual(missing.returncode, 0)
                    self.assertEqual(snapshot(root), before)


if __name__ == "__main__":
    unittest.main()
