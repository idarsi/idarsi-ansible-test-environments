"""Owned guest control guards; backend mutations are always mocked."""

import argparse
import contextlib
import copy
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import cli, context, guest_control
from isolated_runs.backends import Backend
from isolated_runs.state import RunError, Store, atomic_json


class WorkerDispatchTests(unittest.TestCase):
    def test_unknown_action_never_falls_through_to_destroy(self):
        for action in ("", "stop", "start", "guest-unknown", "DESTROY"):
            with self.subTest(action=action), patch.object(context, "Backend") as backend:
                store = Mock()
                with self.assertRaisesRegex(RunError, "Unsupported mutation worker action"):
                    context.worker(store, "run", "operation", action)
                backend.assert_not_called()
                store.assert_not_called()
                self.assertEqual(store.mock_calls, [])


class GuestControlTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = Store(self.root / "state")
        self.data = self.store.allocate("kvm", {"libvirt": "qemu:///system"}, lambda: [], self.root, "kvm")
        self.worker = {"pid": 987654, "start": "1", "boot": "fixture"}
        self.config = {"platforms": [{"name": "database"}]}
        self.guest = {"logical": "database", "name": "itr-" + "a" * 32, "id": str(uuid.uuid4())}
        self.data.update(
            mode="direct", status="running", config=self.config,
            guests=[self.guest], workers=[self.worker],
            instances_ready=[{"instance": "database"}],
            operations=[{"id": "create", "action": "create", "completion": "create", "worker": self.worker}],
        )
        self.store.save(self.data)
        self.result = {
            key: self.data[key] for key in ("role", "scenario", "backend")
        }
        self.result.update(mode="direct", generation=self.data["id"], ephemeral_directory=str(self.root / "ephemeral"))
        self.args = argparse.Namespace(action="guest-stop", guest="database")

    def operation(self):
        return guest_control.intent(self.args, self.guest, self.worker)

    def test_target_requires_exact_config_and_successful_create(self):
        self.assertEqual(guest_control.target(self.data, self.result, self.config, "database"), self.guest)
        for field, value in (("status", "cleaning"), ("config", {}), ("operations", [])):
            with self.subTest(field=field):
                changed = dict(self.data, **{field: value})
                with self.assertRaises(RunError):
                    guest_control.target(changed, self.result, self.config, "database")
        with self.assertRaises(RunError):
            guest_control.target(self.data, self.result, self.config, "missing")
        self.data["guests"].append(dict(self.guest))
        with self.assertRaises(RunError):
            guest_control.target(self.data, self.result, self.config, "database")

    @unittest.skipUnless(importlib.util.find_spec("molecule"), "Activate existing pinned Molecule")
    def test_real_supervisor_and_generation_configurations_compare_without_losing_binding(self):
        source = self.root / "molecule" / self.data["scenario"] / "molecule.yml"
        source.parent.mkdir(parents=True)
        source.write_text(
            (context.REPO / "examples/molecule-managed-kvm/molecule.yml").read_text().replace(
                'name: "node"', 'name: "database"',
            ),
        )
        environment = dict(
            os.environ, PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
            HOME=str(self.root), IDARSI_TEST_ENVIRONMENT=str(context.REPO),
            MOLECULE_EPHEMERAL_DIRECTORY=self.result["ephemeral_directory"],
        )
        original = cli.parse_configuration(self.root, self.data["scenario"], environment)
        current = cli.parse_configuration(self.root, self.data["scenario"], environment, direct=True)
        self.assertNotEqual(original, current)
        self.assertNotEqual(original["_idarsi_effective_env"], current["_idarsi_effective_env"])
        self.data["config"] = original
        self.assertEqual(guest_control.target(self.data, self.result, current, "database"), self.guest)
        for field, value in (
            ("platforms", [dict(current["platforms"][0], vcpus=9)]),
            ("_idarsi_effective_role", "/different-role"),
            ("_idarsi_effective_ephemeral", str(self.root / "foreign-generation")),
        ):
            with self.subTest(field=field), self.assertRaises(RunError):
                guest_control.target(self.data, self.result, dict(current, **{field: value}), "database")
        changed = copy.deepcopy(current)
        changed["_idarsi_effective_env"]["MOLECULE_SCENARIO_NAME"] = "foreign"
        with self.assertRaises(RunError):
            guest_control.target(self.data, self.result, changed, "database")

    @unittest.skipUnless(importlib.util.find_spec("molecule"), "Activate existing pinned Molecule")
    def test_real_quoted_dependency_command_relocates_only_ephemeral_arguments(self):
        source = self.root / "molecule" / self.data["scenario"] / "molecule.yml"
        source.parent.mkdir(parents=True)
        source.write_text(
            (context.REPO / "examples/molecule-managed-kvm/molecule.yml").read_text().replace(
                'name: "node"', 'name: "database"',
            ) + """
dependency:
  name: shell
  env:
    KEEP_CONTEXT: unchanged
  command: >-
    python3 "${MOLECULE_PROJECT_DIRECTORY}/tests/dependency.py"
    --scenario-directory "${MOLECULE_SCENARIO_DIRECTORY}"
    --ephemeral-directory "${MOLECULE_EPHEMERAL_DIRECTORY}"
    --molecule-file "${MOLECULE_FILE}"
    --env-file "${MOLECULE_ENV_FILE}"
    --helper-directory "${IDARSI_TEST_ENVIRONMENT}"
""",
        )
        actual = self.root / "execution root with spaces" / "ephemeral"
        planning = self.root / "planning root with spaces"
        planning.mkdir()
        self.result["ephemeral_directory"] = str(actual)
        environment = dict(
            os.environ, PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
            HOME=str(self.root), IDARSI_TEST_ENVIRONMENT=str(context.REPO),
            MOLECULE_EPHEMERAL_DIRECTORY=str(actual),
        )
        temporary_directory = tempfile.TemporaryDirectory
        with patch.object(cli.tempfile, "TemporaryDirectory", side_effect=lambda **kwargs: temporary_directory(
            dir=planning, **kwargs,
        )):
            original = cli.parse_configuration(self.root, self.data["scenario"], environment)
            current = cli.parse_configuration(self.root, self.data["scenario"], environment, direct=True)
        original_root = original["_idarsi_effective_ephemeral"]
        self.assertIn("planning root with spaces", original_root)
        self.assertIn('--ephemeral-directory "' + original_root + '"', original["dependency"]["command"])
        self.assertIn('--ephemeral-directory "' + str(actual) + '"', current["dependency"]["command"])
        self.assertNotEqual(original["_idarsi_effective_env"], current["_idarsi_effective_env"])
        self.assertEqual(
            guest_control.comparable_configuration(original), guest_control.comparable_configuration(current),
        )
        self.data["config"] = original
        self.assertEqual(guest_control.target(self.data, self.result, current, "database"), self.guest)
        for old, new in (
            ('--ephemeral-directory "' + str(actual) + '"', '--ephemeral-directory "' + str(actual) + '-foreign"'),
            ('--ephemeral-directory "' + str(actual) + '"', '--ephemeral-directory "/foreign' + str(actual) + '"'),
            ('--scenario-directory "', '--scenario-directory "/foreign'),
            ('--env-file "', '--env-file "/foreign'),
        ):
            changed = copy.deepcopy(current)
            changed["dependency"]["command"] = changed["dependency"]["command"].replace(old, new)
            with self.subTest(change=new), self.assertRaises(RunError):
                guest_control.target(self.data, self.result, changed, "database")
        for key in ("KEEP_CONTEXT", "NEW_CONTEXT"):
            changed = copy.deepcopy(current)
            changed["dependency"]["env"][key] = "changed"
            with self.subTest(env=key), self.assertRaises(RunError):
                guest_control.target(self.data, self.result, changed, "database")
        changed = copy.deepcopy(current)
        changed["_idarsi_effective_env"]["MOLECULE_FILE"] = "/foreign" + str(actual) + "/molecule.yml"
        with self.assertRaises(RunError):
            guest_control.target(self.data, self.result, changed, "database")

    def test_missing_direct_generation_never_allocates(self):
        with patch.object(self.store, "allocate") as allocate, patch.object(guest_control, "execute") as execute:
            with self.assertRaises(FileNotFoundError):
                guest_control.control(self.args, self.store, self.result, self.config)
            allocate.assert_not_called()
            execute.assert_not_called()

    def test_incomplete_guest_operation_blocks_cleanup_even_if_domain_absent(self):
        self.data["operations"].append(self.operation())
        with self.assertRaisesRegex(RunError, "Incomplete mutation"):
            context.require_completed(self.data, quiescent=False)

    def test_completed_history_checks_target_protocol_result_and_worker(self):
        operation = self.operation()
        outcome = {
            "action": "guest-stop", "guest": "database", "operation": operation["id"],
            "changed": True, "state": "shut-off",
        }
        operation.update(result=outcome, completion=operation["id"])
        self.data["operations"].append(operation)
        context.require_completed(self.data, quiescent=False)
        for key, value in (
            ("protocol", "unknown"), ("domain_uuid", "invalid"), ("guest", "unknown"),
            ("worker", {"pid": 1}), ("result", dict(outcome, state="running")),
            ("result", dict(outcome, changed=1)),
        ):
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(self.data)
                changed["operations"][-1][key] = value
                with self.assertRaises((RunError, ValueError)):
                    context.require_completed(changed, quiescent=False)
        # Destroy removes manifest guests, not the immutable operation history.
        self.data["guests"] = []
        context.require_completed(self.data, quiescent=False)

    def test_backend_noop_and_exact_uuid_transition(self):
        for action, before, desired, rpc in (
            ("guest-stop", "running", "shut-off", "destroy"),
            ("guest-start", "shut-off", "running", "start"),
            ("guest-stop", "shut-off", "shut-off", None),
            ("guest-start", "running", "running", None),
        ):
            with self.subTest(action=action):
                self.args.action = action
                with patch.object(guest_control, "inspect_domain", side_effect=[before, desired]), \
                        patch.object(guest_control, "assert_exclusive"), \
                        patch.object(guest_control, "command") as command:
                    result = guest_control.execute(self.store, self.data, self.operation())
                    self.assertEqual(result["changed"], rpc is not None)
                    self.assertEqual(result["state"], desired)
                    if rpc:
                        command.assert_called_once_with(guest_control.VIRSH + [rpc, self.guest["id"]], timeout=60)
                    else:
                        command.assert_not_called()

    def test_timeout_and_failed_postcheck_never_seal(self):
        operation = self.operation()
        self.data["operations"].append(operation)
        self.store.save(self.data)
        for error in (RunError("timeout"), OSError("query failed")):
            with self.subTest(error=error), \
                    patch.object(guest_control, "inspect_domain", return_value="running"), \
                    patch.object(guest_control, "assert_exclusive"), \
                    patch.object(guest_control, "command", side_effect=error):
                with self.assertRaises(type(error)):
                    guest_control.execute(self.store, self.data, operation)
                self.assertNotIn("completion", self.store.load(self.data["id"])["operations"][-1])
        with patch.object(guest_control, "inspect_domain", return_value="running"), \
                patch.object(guest_control, "assert_exclusive"), \
                patch.object(guest_control, "command"):
            with self.assertRaisesRegex(RunError, "not confirmed"):
                guest_control.execute(self.store, self.data, operation)

    def test_seal_reloads_and_rejects_substituted_intent_and_write_failure(self):
        operation = self.operation()
        self.data["operations"].append(operation)
        self.store.save(self.data)
        outcome = dict(action="guest-stop", guest="database", operation=operation["id"], changed=True, state="shut-off")
        with patch.object(self.store, "save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                guest_control.seal(self.store, self.data["id"], operation, outcome)
        self.assertNotIn("completion", self.store.load(self.data["id"])["operations"][-1])
        with self.assertRaisesRegex(RunError, "journal changed"):
            guest_control.seal(self.store, self.data["id"], dict(operation, guest="other"), outcome)
        guest_control.seal(self.store, self.data["id"], operation, outcome)
        context.require_completed(self.store.load(self.data["id"]), quiescent=False)

    def test_cli_rejects_missing_guest_non_kvm_and_guest_on_other_actions(self):
        for args in (
            ["guest-stop", "--backend", "kvm", "--scenario", "kvm"],
            ["guest-start", "--backend", "podman", "--scenario", "kvm", "--guest", "database"],
            ["resolve", "--backend", "kvm", "--scenario", "kvm", "--guest", "database"],
        ):
            with self.subTest(args=args), patch.object(context, "Store", return_value=self.store), \
                    patch.object(context, "resolved") as resolved:
                self.assertEqual(context.main(args), 1)
                resolved.assert_not_called()

    def test_supervised_intent_is_saved_before_backend_and_failure_unsealed(self):
        self.result["mode"] = "supervised"
        self.data["mode"] = "supervised"
        self.store.save(self.data)

        @contextlib.contextmanager
        def boundary(*_):
            yield self.store.load(self.data["id"]), self.worker

        def execute(store, data, operation):
            self.assertEqual(store.load(data["id"])["operations"][-1], operation)
            self.assertNotIn("completion", operation)
            raise RunError("interrupted RPC")

        with patch.object(guest_control.admission, "mutation_boundary", side_effect=boundary), \
                patch.object(guest_control, "execute", side_effect=execute):
            with self.assertRaisesRegex(RunError, "interrupted RPC"):
                guest_control.control(self.args, self.store, self.result, self.config)
        self.assertNotIn("completion", self.store.load(self.data["id"])["operations"][-1])

    def test_closed_supervised_admission_never_mutates(self):
        self.result["mode"] = "supervised"
        with patch.object(guest_control.admission, "mutation_boundary", side_effect=RunError("closed")), \
                patch.object(guest_control, "execute") as execute:
            with self.assertRaisesRegex(RunError, "closed"):
                guest_control.control(self.args, self.store, self.result, self.config)
            execute.assert_not_called()
        self.assertEqual(len(self.store.load(self.data["id"])["operations"]), 1)

    def test_direct_gated_worker_persists_target_before_mutation_without_mapping(self):
        path, identity = context.pointer_path(self.store, self.result)
        self.data.update(direct_identity=identity, direct_context=self.result)
        self.store.save(self.data)
        atomic_json(path, {"identity": identity, "generation": self.data["id"]})
        outer = self

        def spawn(store, data, argv, env, cwd, operation):
            operation["worker"] = outer.worker
            store.save(data)
            outer.assertEqual(store.load(data["id"])["operations"][-1], operation)
            outer.assertNotIn("completion", operation)

            class Child:
                def wait(self):
                    with patch.object(context, "members", return_value=[{"session": os.getsid(0)}]):
                        context.worker(store, data["id"], operation["id"], operation["action"])
                    return 0

            return Child()

        def execute(store, data, operation):
            self.assertEqual(store.load(data["id"])["operations"][-1], operation)
            return dict(
                action=operation["action"], guest=operation["guest"], operation=operation["id"],
                changed=True, state="shut-off",
            )

        with patch.object(guest_control, "spawn", side_effect=spawn), \
                patch.object(guest_control, "stop_workers"), \
                patch.object(context, "members", return_value=[]), \
                patch.object(guest_control, "execute", side_effect=execute), \
                patch.object(context, "mapping") as mapping, \
                patch.object(self.store, "allocate") as allocate:
            result = guest_control.control(self.args, self.store, dict(self.result), self.config)
            self.assertEqual(result["state"], "shut-off")
            mapping.assert_not_called()
            allocate.assert_not_called()
        data = self.store.load(self.data["id"])
        context.require_completed(data, quiescent=False)
        self.assertEqual(data["status"], "running")
        self.assertEqual(data["guests"], [self.guest])

    def test_invalid_intent_refused_before_backend(self):
        for key, value in (
            ("action", "destroy"), ("protocol", "unknown"), ("domain_uuid", "wrong"),
            ("worker", {}), ("id", "wrong"),
        ):
            with self.subTest(key=key), patch.object(guest_control, "Backend") as backend:
                with self.assertRaises((RunError, ValueError)):
                    guest_control.execute(self.store, self.data, dict(self.operation(), **{key: value}))
                backend.assert_not_called()


class ConfigurationNormalizationTests(unittest.TestCase):
    def config(self, root, quote='"'):
        return {
            "_idarsi_effective_ephemeral": root,
            "_idarsi_effective_env": {
                "MOLECULE_EPHEMERAL_DIRECTORY": root, "MOLECULE_FILE": root + "/molecule.yml",
            },
            "driver": {"safe_files": [root + "/collections/*"]},
            "dependency": {"name": "shell", "command": (
                'python3 "/example/role/tests/dependency.py" --ephemeral-directory '
                + quote + root + quote + " --molecule-file " + quote + root + "/molecule.yml" + quote
            )},
        }

    def test_single_double_and_unquoted_tokens_preserve_command_spelling(self):
        for quote in ('"', "'", ""):
            roots = ("/planning space/ephemeral", "/execution space/ephemeral") if quote else (
                "/planning/ephemeral", "/execution/ephemeral",
            )
            before, after = [self.config(root, quote) for root in roots]
            with self.subTest(quote=quote):
                self.assertEqual(
                    guest_control.comparable_configuration(before), guest_control.comparable_configuration(after),
                )
                after["dependency"]["command"] += " --different-option"
                self.assertNotEqual(
                    guest_control.comparable_configuration(before), guest_control.comparable_configuration(after),
                )

    def test_suffix_foreign_prefix_and_literal_placeholder_never_collide(self):
        for spelling in (
            lambda root: root + "-foreign",
            lambda root: "/foreign" + root,
            lambda root: 'literal "' + root + '"',
        ):
            before, after = self.config("/planning/ephemeral"), self.config("/execution/ephemeral")
            before["unrelated"] = spelling("/planning/ephemeral")
            after["unrelated"] = spelling("/execution/ephemeral")
            with self.subTest(spelling=before["unrelated"]):
                self.assertNotEqual(
                    guest_control.comparable_configuration(before), guest_control.comparable_configuration(after),
                )
        before, after = self.config("/planning/ephemeral"), self.config("/execution/ephemeral")
        after["dependency"]["command"] = after["dependency"]["command"].replace(
            '"/execution/ephemeral"', '"<MOLECULE_EPHEMERAL>"',
        )
        self.assertNotEqual(
            guest_control.comparable_configuration(before), guest_control.comparable_configuration(after),
        )

    def test_quoted_literal_option_and_escaped_forms_are_not_reinterpreted(self):
        for template in (
            """python3 --note "literal --ephemeral-directory '{root}'" """,
            r'python3 --ephemeral-directory \"{root}\"',
            """python3 --unrelated "{root}" """,
        ):
            before, after = self.config("/planning/ephemeral"), self.config("/execution/ephemeral")
            before["dependency"]["command"] = template.format(root="/planning/ephemeral")
            after["dependency"]["command"] = template.format(root="/execution/ephemeral")
            with self.subTest(template=template):
                self.assertNotEqual(
                    guest_control.comparable_configuration(before), guest_control.comparable_configuration(after),
                )

    def test_traversal_paths_remain_literal_standalone_and_in_both_dependency_arguments(self):
        roots = ("/planning space/ephemeral", "/execution space/ephemeral")
        for suffix in (
            "/../foreign.yml", "/child/../../foreign.yml",
            "/child/../inside.yml", "//../foreign.yml",
        ):
            before, after = [self.config(root) for root in roots]
            for config, root in zip((before, after), roots):
                config["unrelated"] = root + suffix
            with self.subTest(location="standalone", suffix=suffix):
                normalized = guest_control.comparable_configuration(before)
                self.assertEqual(normalized["unrelated"], roots[0] + suffix)
                self.assertNotEqual(normalized, guest_control.comparable_configuration(after))
            for option in ("--ephemeral-directory", "--molecule-file"):
                before, after = [self.config(root) for root in roots]
                for config, root in zip((before, after), roots):
                    config["dependency"]["command"] = (
                        'python3 "/example/role/tests/dependency.py" ' + option + ' "' + root + suffix + '"'
                    )
                with self.subTest(option=option, suffix=suffix):
                    normalized = guest_control.comparable_configuration(before)
                    self.assertEqual(normalized["dependency"]["command"], before["dependency"]["command"])
                    self.assertNotEqual(normalized, guest_control.comparable_configuration(after))


class DomainValidationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "owned.qcow2"
        self.path.write_bytes(b"fixture")
        info = self.path.stat()
        self.chain = [{"path": str(self.path), "device": info.st_dev, "inode": info.st_ino, "format": "qcow2"}]
        self.disk = dict(self.chain[0], serial="itr-root", image_chain={
            "version": 1, "complete": True, "provenance": "qemu-img-before-start", "members": self.chain,
        })
        self.guest = {"id": str(uuid.uuid4()), "name": "itr-" + "a" * 32, "disks": [self.disk]}
        self.backend = Mock()
        self.backend.data = {
            "id": "generation", "network": {"id": "network", "name": "owned-net"}, "subnet": "10.0.0.0/24",
        }
        self.backend.disks.return_value = [self.disk]
        self.backend.storage.directory.return_value = contextlib.nullcontext(123)
        self.backend.storage.verify.return_value = info
        self.xml = (
            f"<domain><uuid>{self.guest['id']}</uuid><name>{self.guest['name']}</name>"
            f"<description>idarsi-run:generation</description><devices>"
            f"<disk type='file' device='disk'><driver type='qcow2'/><source file='{self.path}'/>"
            "<target bus='virtio'/><serial>itr-root</serial><backingStore/></disk>"
            "<interface type='network'><source network='owned-net'/></interface></devices></domain>"
        )
        self.state = "running"
        self.managed_save = "no"
        self.persistent = self.xml
        self.addCleanup(patch.stopall)
        patch.object(guest_control, "command", side_effect=self.command).start()
        patch.object(guest_control, "libvirt_networks", return_value=[
            ET.fromstring("<network><uuid>network</uuid><name>owned-net</name></network>"),
        ]).start()
        patch.object(guest_control, "owned_bridge", return_value="owned-bridge").start()

    def command(self, argv, **_):
        if "list" in argv:
            return self.guest["id"]
        if "domstate" in argv:
            return self.state
        if "dominfo" in argv:
            return "Managed save: " + self.managed_save
        if "dumpxml" in argv:
            return self.persistent if "--inactive" in argv else self.xml
        raise AssertionError(argv)

    def test_running_validation_never_opens_active_image(self):
        with patch.object(guest_control, "image_chain") as image:
            self.assertEqual(guest_control.inspect_domain(self.backend, self.guest), "running")
            image.assert_not_called()

    def test_managed_save_or_uncertain_query_blocks_before_any_power_rpc(self):
        for value in ("yes", "", "unknown", "no\nManaged save: yes"):
            self.managed_save = value
            with self.subTest(value=value), patch.object(guest_control, "image_chain") as image:
                with self.assertRaisesRegex(RunError, "managed-save"):
                    guest_control.inspect_domain(self.backend, self.guest)
                image.assert_not_called()

    def test_unsupported_storage_devices_in_either_definition_are_rejected(self):
        original = self.xml
        for device in (
            "<filesystem type='mount'><source dir='/export'/><target dir='export'/></filesystem>",
            "<hostdev mode='subsystem' type='scsi'><source/></hostdev>",
            "<hostdev mode='capabilities' type='storage'><source><block>/dev/foreign</block></source></hostdev>",
            "<memory model='nvdimm'><source><path>/foreign</path></source></memory>",
        ):
            for definition in ("live", "persistent"):
                with self.subTest(device=device, definition=definition):
                    self.xml = original.replace("</devices>", device + "</devices>") if definition == "live" else original
                    self.persistent = original.replace("</devices>", device + "</devices>") if definition == "persistent" else original
                    with self.assertRaisesRegex(RunError, "storage-bearing"):
                        guest_control.inspect_domain(self.backend, self.guest)
        self.xml = self.persistent = original

    def test_all_interface_source_evidence_in_either_definition_is_checked(self):
        original = self.xml
        for source in (
            "<source network='owned-net'/><source network='foreign'/>",
            "<source network='owned-net' bridge='foreign'/>",
            "<source network='owned-net'/><actual type='bridge'><source bridge='foreign'/></actual>",
            "<source network='owned-net'/><actual type='direct'><source dev='foreign'/></actual>",
            "<source network='owned-net'/><actual type='bridge'><source bridge='owned-bridge'/><source bridge='foreign'/></actual>",
            "<source network='owned-net' dev='foreign'/>",
        ):
            for definition in ("live", "persistent"):
                with self.subTest(source=source, definition=definition):
                    changed = original.replace("<source network='owned-net'/>", source)
                    self.xml = changed if definition == "live" else original
                    self.persistent = changed if definition == "persistent" else original
                    with self.assertRaises(RunError):
                        guest_control.inspect_domain(self.backend, self.guest)
        self.xml = self.persistent = original.replace(
            "<source network='owned-net'/>",
            f"<source network='owned-net' bridge='owned-bridge' portid='{uuid.uuid4()}'/>"
            "<actual type='bridge'><source bridge='owned-bridge'/></actual>",
        )
        self.assertEqual(guest_control.inspect_domain(self.backend, self.guest), "running")

    def test_real_backend_attachment_guard_rejects_bus_serial_format_and_extra_disk(self):
        backend = Backend.__new__(Backend)
        backend.data = self.backend.data
        for old, new in (
            ("bus='virtio'", "bus='scsi'"),
            ("itr-root", "foreign-serial"),
            ("type='qcow2'", "type='raw'"),
            ("</devices>", f"<disk device='disk'><source file='{self.path}'/></disk></devices>"),
        ):
            with self.subTest(change=new), self.assertRaises(RunError):
                backend.verify_attachments(self.guest, ET.fromstring(self.xml.replace(old, new)))
        backend.verify_attachments(self.guest, ET.fromstring(self.xml))

    def test_inactive_fresh_chain_must_match_capture(self):
        self.state = "shut off"
        with patch.object(guest_control, "image_chain", return_value={"members": self.chain}):
            self.assertEqual(guest_control.inspect_domain(self.backend, self.guest), "shut-off")
        with patch.object(guest_control, "image_chain", return_value={"members": []}):
            with self.assertRaisesRegex(RunError, "headers changed"):
                guest_control.inspect_domain(self.backend, self.guest)

    def test_live_and_persistent_identity_network_storage_and_state_refusals(self):
        for old, new in (
            ("idarsi-run:generation", "idarsi-run:foreign"),
            (self.guest["id"], str(uuid.uuid4())),
            ("owned-net", "foreign-net"),
            ("<backingStore/>", ""),
            ("<backingStore/>", "<mirror/>"),
            ("</devices>", "<disk type='file' device='disk'><source file='/foreign'/></disk></devices>"),
        ):
            with self.subTest(change=new):
                self.persistent = self.xml.replace(old, new)
                # Missing persistent backing XML is allowed only when the
                # active graph independently agrees with the durable capture.
                if new == "":
                    self.xml, original = self.persistent, self.xml
                else:
                    original = self.xml
                with self.assertRaises((RunError, OSError)):
                    guest_control.inspect_domain(self.backend, self.guest)
                self.xml = original
        self.persistent = self.xml
        self.state = "paused"
        with self.assertRaisesRegex(RunError, "power state"):
            guest_control.inspect_domain(self.backend, self.guest)


if __name__ == "__main__":
    unittest.main()
