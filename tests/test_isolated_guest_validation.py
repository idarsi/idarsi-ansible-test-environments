"""Private synthetic generations and mocked native observations; no real backend."""

import argparse
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import admission, context, existing_config, guest_validation as guest
from isolated_runs.backends import Backend, kvm_instance
from isolated_runs.state import RunError, Store, atomic_json, existing_lock
from isolated_runs.guest_refusal import GuestRefusal, SCHEMA as REFUSAL_SCHEMA, emit, proof_lock


class WireTests(unittest.TestCase):
    def test_strict_bounded_input(self):
        with tempfile.TemporaryDirectory() as value:
            key = Path(value) / "key"
            key.touch(mode=0o600)
            valid = {"address": "10.0.0.10", "port": 22, "user": "molecule", "identity_file": str(key)}
            self.assertEqual(guest.connection(io.BytesIO(json.dumps(valid).encode())), valid)
            for value in (
                b"x" * (guest.INPUT_LIMIT + 1), b"{}", b"[]",
                (json.dumps(valid) + "{}").encode(),
                (json.dumps(valid)[:-1] + ',"port":22}').encode(),
                json.dumps({**valid, "port": True}).encode(),
                json.dumps({**valid, "port": "22"}).encode(),
                json.dumps({**valid, "port": 2222}).encode(),
                json.dumps({**valid, "user": ""}).encode(),
                json.dumps({**valid, "address": "localhost"}).encode(),
                json.dumps({**valid, "address": " 10.0.0.10"}).encode(),
                json.dumps({**valid, "address": "010.0.0.10"}).encode(),
                json.dumps({**valid, "identity_file": "~/key"}).encode(),
                json.dumps({**valid, "extra": "secret"}).encode(),
                json.dumps({key: item for key, item in valid.items() if key != "user"}).encode(),
            ):
                with self.subTest(value=value), self.assertRaises((RunError, ValueError)):
                    guest.connection(io.BytesIO(value))

    def test_cli_failures_are_bounded_without_private_values(self):
        for args in (
            [], ["--help"], ["--backend", "podman"], ["--backend", "kvm", "--role", "/secret"],
            ["--backend", "kvm", "--role", "/", "--scenario", "s", "--platform", "p", "--secret"],
        ):
            with patch.object(guest, "validate") as validate, \
                    patch.object(guest.ExistingStore, "open_existing") as store, \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(guest.main(args), 1)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(json.loads(errors.getvalue()), {"schema": REFUSAL_SCHEMA, "code": "AUTHORITY_PARSE"})
            validate.assert_not_called()
            store.assert_not_called()


class EntrypointTests(unittest.TestCase):
    def test_public_executable_never_caches_modules_on_refusal_or_mock_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "helper"
            (repository / "scripts").mkdir(parents=True)
            source = Path(context.__file__).resolve().parents[2]
            shutil.copytree(
                source / "scripts/isolated_runs", repository / "scripts/isolated_runs",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            entry = repository / "scripts/scenario-context"
            shutil.copy2(source / "scripts/scenario-context", entry)
            role, ephemeral, store = (root / name for name in ("role", "ephemeral", "state"))
            role.mkdir(mode=0o700)
            ephemeral.mkdir(mode=0o700)
            image = root / "fixture-image"
            image.write_text("not a real image")
            config = {
                "platforms": [{"name": "node", "image_path": str(image)}],
                "provisioner": {"env": {"IDARSI_MOLECULE_BACKEND": "kvm"}},
                "driver": {"safe_files": [str(ephemeral / "collections/*")]},
                "_idarsi_effective_role": str(role), "_idarsi_effective_scenario": "kvm-bytecode",
                "_idarsi_effective_ephemeral": str(ephemeral), "_idarsi_effective_env": {},
            }
            # Test-only source-copy doubles. Public entrypoint and imports are real;
            # ordinary capabilities use a private Store/config, never user state.
            module = repository / "scripts/isolated_runs/context.py"
            with module.open("a") as stream:
                stream.write(
                    "\n_FixtureStore = Store\n"
                    "def Store():\n    return _FixtureStore(Path(" + repr(str(store)) + "))\n"
                    "def parse_configuration(*args, **kwargs):\n    return " + repr(config) + "\n",
                )
            environment = {
                key: value for key, value in os.environ.items()
                if key not in ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX")
                and not key.startswith(("MOLECULE_", "IDARSI_"))
            }
            environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + environment["PATH"]
            for arguments, expected in (
                (["validate-guest", "--backend", "podman"], 1),
                (["capabilities", "--backend", "kvm", "--scenario", "kvm-bytecode", "--role", str(role)], 0),
            ):
                result = subprocess.run(
                    [str(entry)] + arguments, env=environment, cwd=repository,
                    input=b"", capture_output=True, timeout=30, check=False,
                )
                self.assertEqual(result.returncode, expected, result.stderr.decode())
                if expected == 0:
                    self.assertEqual(json.loads(result.stdout)["schema"], context.SCHEMA)
                self.assertEqual(list(repository.rglob("__pycache__")), [])
                self.assertEqual(list(repository.rglob("*.pyc")), [])


class GuestTests(unittest.TestCase):
    def relocate_config(self, ephemeral):
        """Rebuild this fixture's explicit Molecule-generated path fields."""
        config = copy.deepcopy(self.config)
        config["_idarsi_effective_ephemeral"] = str(ephemeral)
        config["driver"]["safe_files"] = [str(ephemeral / "collections" / "*")]
        config["_idarsi_effective_env"]["MOLECULE_FILE"] = str(ephemeral / "molecule.yml")
        return config

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.role = self.root / "role"
        self.role.mkdir(mode=0o700)
        self.store = Store(self.root / "state")
        self.data = self.store.allocate(
            "kvm", {"libvirt": "qemu:///system"}, lambda: [], self.role, "kvm-test",
        )
        self.run_id = self.data["id"]
        self.ephemeral = self.root / "ephemeral"
        self.ephemeral.mkdir(mode=0o700)
        (self.ephemeral / "inventory").mkdir(mode=0o700)
        (self.ephemeral / "state.yml").write_text("{}")
        (self.ephemeral / "state.yml").chmod(0o600)
        self.key = self.store.directory(self.run_id) / "kvm_ed25519"
        self.key.write_text("fixture key never published")
        self.key.chmod(0o600)
        self.args = argparse.Namespace(role=str(self.role), scenario="kvm-test", backend="kvm", platform="node")
        self.config = {
            "platforms": [{
                "name": "node", "image_path": str(self.key), "ssh_user": "molecule",
                "memory_mb": 4096, "vcpus": 2, "disk_size_gb": 30, "install_timeout": 3600,
            }],
            "provisioner": {"env": {"IDARSI_MOLECULE_BACKEND": "kvm"}},
            "driver": {"safe_files": [str(self.ephemeral / "collections" / "*")]},
            "_idarsi_effective_scenario": "kvm-test", "_idarsi_effective_role": str(self.role),
            "_idarsi_effective_ephemeral": str(self.ephemeral),
            "_idarsi_effective_env": {"MOLECULE_FILE": str(self.ephemeral / "molecule.yml")},
        }
        self.result = {
            "role": str(self.role), "scenario": "kvm-test", "backend": "kvm",
            "ephemeral_directory": str(self.ephemeral), "generation": self.run_id,
        }
        path, identity = context.pointer_path(self.store, self.result)
        self.pointer = path
        atomic_json(path, {"identity": identity, "generation": self.run_id})
        for lock_path in (
            path.with_suffix(".lock"), self.store.directory(self.run_id) / ".resources.lock",
            self.store.directory(self.run_id) / ".admission.lock",
        ):
            lock_path.touch(mode=0o600)
        worker = {"pid": 123, "boot": "fixture", "start": "1"}
        network_id = str(uuid.uuid4())
        self.data.update(
            status="running", mode="direct", context_publication="published",
            direct_identity=identity, direct_context=self.result, config=self.config,
            workers=[worker], operations=[{
                "id": "op", "action": "create", "completion": "op", "worker": worker,
            }],
            network={"id": network_id, "name": "itr-" + network_id.replace("-", "")[:24]},
            guests=[{
                "logical": "node", "name": "itr-" + uuid.uuid4().hex, "id": str(uuid.uuid4()),
                "disks": [{"name": "root", "path": "/owned/disk.qcow2", "serial": "itr-root", "device": 1, "inode": 2}],
            }],
        )
        self.instances = [kvm_instance(self.config["platforms"][0], self.data["subnet"], 0, self.key)]
        self.data["instances_ready"] = self.instances
        self.artifact = self.ephemeral / "instance_config.yml"
        atomic_json(self.artifact, self.instances)
        self.store.save(self.data)
        self.supplied = {
            "address": self.instances[0]["address"], "port": 22,
            "user": "molecule", "identity_file": str(self.key),
        }
        self.environment = {
            "MOLECULE_EPHEMERAL_DIRECTORY": str(self.ephemeral),
            "MOLECULE_INSTANCE_CONFIG": str(self.artifact),
        }
        self.bridge = patch.object(existing_config, "parse_existing_configuration", side_effect=lambda *a: copy.deepcopy(self.config))
        self.bridge_mock = self.bridge.start()
        self.addCleanup(self.bridge.stop)
        self.env = patch.dict(os.environ, self.environment, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.domain = ET.fromstring(
            "<domain><name>" + self.data["guests"][0]["name"] + "</name>"
            "<uuid>" + self.data["guests"][0]["id"] + "</uuid>"
            "<description>idarsi-run:" + self.run_id + "</description><devices>"
            "<disk device='disk'><source file='/owned/disk.qcow2'/>"
            "<serial>itr-root</serial><target bus='virtio'/><driver type='qcow2'/></disk>"
            "<interface type='network'><source network='" + self.data["network"]["name"]
            + "' bridge='it" + network_id.replace("-", "")[:12] + "'/></interface></devices></domain>",
        )
        self.network = ET.fromstring(
            "<network><name>" + self.data["network"]["name"] + "</name><uuid>" + network_id
            + "</uuid><bridge name='it" + network_id.replace("-", "")[:12]
            + "'/><forward mode='nat'/><domain name='" + self.data["network"]["name"]
            + ".test' localOnly='yes'/><ip address='10.0.0.1' netmask='255.255.255.0'>"
            "<dhcp><range start='10.0.0.210' end='10.0.0.250'/></dhcp></ip></network>",
        )
        self.state = "running"
        self.addresses = [{"addr_info": [{"family": "inet", "local": "127.0.0.1"}]}]
        # Ordinary ip -j output does not include linkinfo on the qualified host.
        self.normal_link = {
            "ifindex": 1, "ifname": self.network.find("bridge").get("name"),
            "address": "52:54:00:12:34:56",
        }
        self.detailed_links = [{
            **self.normal_link, "linkinfo": {
                "info_kind": "bridge", "info_data": {"hello_timer": 1.0},
            },
        }]
        self.queries = []

    def query(self, argv, **kwargs):
        self.queries.append(list(argv))
        operation = argv[3] if argv[0] == "virsh" else None
        if operation == "list":
            return self.data["guests"][0]["name"] if "--name" in argv else self.data["guests"][0]["id"]
        if operation == "dumpxml":
            return ET.tostring(self.domain, encoding="unicode")
        if operation == "domstate":
            return self.state
        if operation == "net-list":
            return self.data["network"]["id"]
        if operation == "net-dumpxml":
            return ET.tostring(self.network, encoding="unicode")
        if argv == ["ip", "-j", "address", "show"]:
            return json.dumps(self.addresses)
        if argv == ["ip", "-j", "link", "show"]:
            return json.dumps([self.normal_link])
        if argv == ["ip", "-d", "-j", "link", "show", "dev", self.normal_link["ifname"]]:
            return json.dumps(self.detailed_links)
        self.fail("Unexpected resource command: " + repr(argv))

    def invoke(self):
        with contextlib.ExitStack() as stack:
            for module in ("guest_validation", "backends", "discovery", "network_references"):
                stack.enter_context(patch("isolated_runs." + module + ".command", side_effect=self.query))
            stack.enter_context(patch.object(Backend, "verify_disk", return_value=True))
            stack.enter_context(patch.object(Store, "save", side_effect=AssertionError("save forbidden")))
            stack.enter_context(patch.object(Store, "allocate", side_effect=AssertionError("allocation forbidden")))
            stack.enter_context(patch.object(Path, "mkdir", side_effect=AssertionError("mkdir forbidden")))
            stack.enter_context(patch.object(Backend, "create", side_effect=AssertionError("create forbidden")))
            stack.enter_context(patch.object(Backend, "destroy_guests", side_effect=AssertionError("destroy forbidden")))
            stack.enter_context(patch.object(context, "stop_workers", side_effect=AssertionError("signals forbidden")))
            return guest.validate(copy.copy(self.args), self.supplied, guest.ExistingStore.open_existing(self.store.root))

    def test_direct_read_only_success_and_fixed_wire(self):
        before = {path: path.read_bytes() for path in self.store.root.rglob("*") if path.is_file()}
        result = self.invoke()
        self.assertEqual(result, {
            "schema": guest.SCHEMA, "role": str(self.role), "scenario": "kvm-test",
            "generation": self.run_id, "platform": "node", "backend": "kvm", "validated": True,
        })
        self.assertEqual(before, {path: path.read_bytes() for path in self.store.root.rglob("*") if path.is_file()})

    def test_safe_molecule_state_modes_do_not_change_ownership_checks(self):
        for mode in (0o600, 0o640, 0o644):
            (self.ephemeral / "state.yml").chmod(mode)
            self.assertTrue(self.invoke()["validated"])

    def test_bridge_kind_uses_targeted_details_bound_to_ordinary_identity(self):
        self.assertNotIn("linkinfo", self.normal_link)
        self.assertTrue(self.invoke()["validated"])
        self.assertIn(["ip", "-j", "link", "show"], self.queries)
        self.assertIn([
            "ip", "-d", "-j", "link", "show", "dev", self.normal_link["ifname"],
        ], self.queries)

    def test_unknown_or_mismatched_detailed_bridge_is_refused(self):
        valid = copy.deepcopy(self.detailed_links[0])
        for details in (
            None, {}, [], [valid, valid], ["not-a-link"], [{}],
            [{**valid, "ifname": "foreign"}],
            [{**valid, "ifindex": 2}], [{**valid, "ifindex": True}],
            [{**valid, "ifindex": 1.0}],
            [{**valid, "address": "52:54:00:aa:bb:cc"}],
            [{key: value for key, value in valid.items() if key != "address"}],
            [{**valid, "linkinfo": None}], [{**valid, "linkinfo": {}}],
            [{key: value for key, value in valid.items() if key != "linkinfo"}],
            [{**valid, "linkinfo": {"info_kind": "tun"}}],
        ):
            self.detailed_links = details
            with self.subTest(details=details), self.assertRaises(RunError):
                self.invoke()

    def test_supported_resolved_bridge_evidence_and_canonical_port_ids_pass(self):
        interface = self.domain.find("./devices/interface")
        source = interface.find("source")
        bridge = source.get("bridge")
        source.set("portid", str(uuid.uuid4()))
        actual = ET.SubElement(interface, "actual", {"type": "bridge"})
        resolved = ET.SubElement(actual, "source", {"bridge": bridge, "portid": str(uuid.uuid4())})
        self.assertTrue(self.invoke()["validated"])
        # Main also supports the normal declared-network/resolved-bridge split.
        del source.attrib["bridge"]
        self.assertTrue(self.invoke()["validated"])
        resolved.set("network", self.data["network"]["name"])
        self.assertTrue(self.invoke()["validated"])

    def test_resolved_or_declared_source_contradictions_have_finite_refusal(self):
        original = copy.deepcopy(self.domain)
        bridge = self.normal_link["ifname"]
        network = self.data["network"]["name"]
        cases = [
            "<source network='" + network + "' portid='CANARY-not-a-uuid'/>",
            "<source network='" + network + "' portid='A1234567-89AB-4CDE-8F01-23456789ABCD'/>",
            "<source network='" + network + "'/><actual type='bridge'><source bridge='" + bridge + "' portid='CANARY'/></actual>",
            "<source network='" + network + "'/><actual type='bridge'><source bridge='CANARY-foreign'/></actual>",
            "<source network='" + network + "'/><actual type='direct'><source bridge='" + bridge + "'/></actual>",
            "<source network='" + network + "'/><actual type='bridge'><source bridge='" + bridge + "' network='CANARY-foreign'/></actual>",
            "<source network='" + network + "'/><actual type='bridge'><source bridge='" + bridge + "'/><source bridge='" + bridge + "'/></actual>",
            "<source network='" + network + "'/><actual type='bridge'><source bridge='" + bridge + "'/><extra/></actual>",
            "<source network='" + network + "'/><actual type='bridge'><source bridge='" + bridge + "'/></actual><actual type='bridge'><source bridge='" + bridge + "'/></actual>",
        ]
        for xml in cases:
            self.domain = copy.deepcopy(original)
            interface = self.domain.find("./devices/interface")
            interface.remove(interface.find("source"))
            for node in ET.fromstring("<evidence>" + xml + "</evidence>"):
                interface.append(node)
            with self.subTest(xml=xml):
                self.refusal("NETWORK_OBSERVATION")

    def test_missing_or_malformed_ordinary_bridge_address_is_refused(self):
        for address in (None, "", 42, "not-a-mac"):
            self.normal_link["address"] = address
            with self.subTest(address=address), self.assertRaises(RunError):
                self.invoke()

    def test_connection_overrides_and_unknown_platform_refused(self):
        for key, value in (("address", "192.0.2.1"), ("port", 2222), ("user", "root"), ("identity_file", str(self.artifact))):
            original = self.supplied
            self.supplied = {**original, key: value}
            with self.subTest(key=key), self.assertRaises(RunError):
                self.invoke()
            self.supplied = original
        self.args.platform = "unknown"
        with self.assertRaises(RunError):
            self.invoke()

    def test_manifest_identity_history_mapping_and_config_refused(self):
        original = copy.deepcopy(self.data)
        for changes in (
            {"role": "/foreign"}, {"scenario": "other"}, {"status": "cleaned"},
            {"backend": "podman"}, {"context_publication": "pending"}, {"operations": []},
            {"operations": [{**original["operations"][0], "completion": "wrong"}]},
            {"guests": []}, {"instances_ready": []},
            {"direct_context": {**self.result, "generation": str(uuid.uuid4())}},
            {"config": {**self.config, "extra_source_change": "changed"}},
        ):
            self.store.save({**copy.deepcopy(original), **changes})
            with self.subTest(changes=changes), self.assertRaises((RunError, KeyError)):
                self.invoke()
        self.store.save(original)

    def test_missing_pointer_partial_handoff_and_busy_resource_fail_before_bridge(self):
        with existing_lock(self.store.directory(self.run_id) / ".resources.lock"):
            with self.assertRaises(RunError):
                self.invoke()
        self.bridge_mock.assert_not_called()
        self.pointer.unlink()
        with self.assertRaises(GuestRefusal) as refused:
            self.invoke()
        self.assertEqual(refused.exception.code, "READONLY_STATE")
        self.bridge_mock.assert_not_called()
        os.environ["IDARSI_HANDOFF"] = "v1"
        with self.assertRaises(RunError):
            self.invoke()
        self.bridge_mock.assert_not_called()

    def test_instance_and_key_safety(self):
        for record in ([], self.instances * 2, [{**self.instances[0], "user": "root"}]):
            atomic_json(self.artifact, record)
            with self.assertRaises(RunError):
                self.invoke()
        atomic_json(self.artifact, self.instances)
        self.key.chmod(0o644)
        with self.assertRaises(RunError):
            self.invoke()
        self.key.chmod(0o600)
        self.artifact.unlink()
        self.artifact.symlink_to(self.key)
        with self.assertRaises(RunError):
            self.invoke()

    def test_pointer_alias_key_hardlink_and_missing_inventory_refused(self):
        pointer_bytes = self.pointer.read_bytes()
        self.pointer.unlink()
        substitute = self.root / "substitute"
        substitute.write_bytes(pointer_bytes)
        substitute.chmod(0o600)
        self.pointer.symlink_to(substitute)
        with self.assertRaises(RunError):
            self.invoke()
        self.bridge_mock.assert_not_called()
        self.pointer.unlink()
        self.pointer.write_bytes(pointer_bytes)
        self.pointer.chmod(0o600)
        os.link(self.key, self.root / "linked-key")
        with self.assertRaises(RunError):
            self.invoke()
        (self.root / "linked-key").unlink()
        (self.ephemeral / "inventory").rmdir()
        self.bridge_mock.reset_mock()
        with self.assertRaises(GuestRefusal) as refused:
            self.invoke()
        self.assertEqual(refused.exception.code, "READONLY_STATE")
        self.bridge_mock.assert_not_called()

    def test_cli_success_is_only_fixed_seven_key_receipt(self):
        result = self.invoke()
        with patch.object(guest, "validate", return_value=result), \
                patch.object(guest.ExistingStore, "open_existing", return_value=self.store), \
                patch.object(sys, "stdin", type("Input", (), {"buffer": io.BytesIO(json.dumps(self.supplied).encode())})()), \
                contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(context.main([
                "validate-guest", "--backend", "kvm", "--role", str(self.role),
                "--scenario", "kvm-test", "--platform", "node",
            ]), 0)
        self.assertEqual(json.loads(output.getvalue()), result)
        self.assertEqual(len(json.loads(output.getvalue())), 7)
        self.assertEqual(errors.getvalue(), "")
        self.assertNotIn(self.key.read_text(), output.getvalue())

    def test_foreign_replaced_domain_network_and_interfaces(self):
        domain = copy.deepcopy(self.domain)
        network = copy.deepcopy(self.network)
        for tag in ("name", "uuid", "description"):
            self.domain = copy.deepcopy(domain)
            self.domain.find(tag).text = "foreign"
            with self.subTest(tag=tag), self.assertRaises(RunError):
                self.invoke()
        self.domain = domain
        self.state = "shut off"
        with self.assertRaises(RunError):
            self.invoke()
        self.state = "running"
        self.network.find("uuid").text = str(uuid.uuid4())
        with self.assertRaises(RunError):
            self.invoke()
        self.network = network
        self.domain.find("./devices/interface/source").set("network", "foreign")
        with self.assertRaises(RunError):
            self.invoke()
        self.domain = copy.deepcopy(domain)
        self.domain.find("devices").append(ET.fromstring("<interface type='user'/>"))
        with self.assertRaises(RunError):
            self.invoke()

    def test_controller_alias_rejected(self):
        self.addresses.append({"addr_info": [{"family": "inet", "local": self.supplied["address"]}]})
        with self.assertRaises(RunError):
            self.invoke()

    def test_supervised_live_worker_new_child_session_never_registers(self):
        self.ephemeral = self.store.ephemeral(self.run_id)
        (self.ephemeral / "inventory").mkdir(mode=0o700)
        (self.ephemeral / "state.yml").write_text("{}")
        (self.ephemeral / "state.yml").chmod(0o600)
        self.config = self.relocate_config(self.ephemeral)
        self.artifact = self.ephemeral / "instance_config.yml"
        atomic_json(self.artifact, self.instances)
        os.environ.update(
            MOLECULE_EPHEMERAL_DIRECTORY=str(self.ephemeral), MOLECULE_INSTANCE_CONFIG=str(self.artifact),
            IDARSI_RUN_ID=self.run_id, IDARSI_HANDOFF="v1",
        )
        self.data.update(
            mode="supervised", mutation_protocol="sealed-v1", admission_protocol=admission.PROTOCOL,
            config=self.config,
        )
        self.store.save(self.data)
        atomic_json(self.store.directory(self.run_id) / "admission.json", {"version": 1, "id": self.run_id, "state": "open"})
        new = {"pid": 456, "boot": "fixture", "start": "2"}
        with patch.object(admission, "prove_sessions", return_value=contextlib.nullcontext([self.data["workers"][0], new])), \
                patch.object(admission, "registered_current", side_effect=AssertionError("registration forbidden")), \
                patch.object(context, "lock", side_effect=AssertionError("creating lock forbidden")):
            self.assertTrue(self.invoke()["validated"])
        self.assertEqual(self.store.load(self.run_id)["workers"], self.data["workers"])
        stale = {**self.data["workers"][0], "start": "reused"}
        with patch.object(admission, "prove_sessions", return_value=contextlib.nullcontext([stale])):
            with self.assertRaises(RunError):
                self.invoke()
        with patch.object(admission, "prove_sessions", side_effect=RunError("foreign ancestry")):
            with self.assertRaises(RunError):
                self.invoke()
        atomic_json(self.store.directory(self.run_id) / "admission.json", {"version": 1, "id": self.run_id, "state": "closed"})
        with self.assertRaises(RunError):
            self.invoke()

    def refusal(self, expected):
        try:
            self.invoke()
        except Exception as error:
            with contextlib.redirect_stderr(io.StringIO()) as output:
                emit(error)
            self.assertEqual(json.loads(output.getvalue()), {"schema": REFUSAL_SCHEMA, "code": expected})
            self.assertEqual(len(output.getvalue().splitlines()), 1)
            self.assertNotIn("fixture key", output.getvalue())
            self.assertNotIn(str(self.root), output.getvalue())
        else:
            self.fail("Expected a refusal at the real owning boundary")

    def test_refusal_codes_from_native_network_mapping_state_and_authority_boundaries(self):
        original = self.domain.find("uuid").text
        self.domain.find("uuid").text = str(uuid.uuid4())
        self.refusal("NATIVE_IDENTITY")
        self.domain.find("uuid").text = original
        links = self.detailed_links
        self.detailed_links = []
        self.refusal("NETWORK_OBSERVATION")
        self.detailed_links = links
        original = self.supplied
        self.supplied = {**original, "user": "foreign"}
        self.refusal("SSH_MAPPING")
        self.supplied = original
        self.key.chmod(0o644)
        self.refusal("READONLY_STATE")
        self.key.chmod(0o600)
        self.bridge_mock.side_effect = lambda *args: {**copy.deepcopy(self.config), "CANARY": "changed"}
        self.refusal("AUTHORITY_PARSE")

    def test_refusal_actual_private_existing_lock_busy_and_unsafe_are_distinct(self):
        path = self.store.directory(self.run_id) / ".resources.lock"
        with existing_lock(path):
            self.refusal("LOCK_BUSY")
        self.bridge_mock.assert_not_called()
        path.chmod(0o644)
        self.refusal("READONLY_STATE")
        path.chmod(0o600)
        # Inode replacement at exit remains a state refusal, never busy.
        with self.assertRaises(GuestRefusal) as refused:
            with proof_lock(path):
                path.unlink()
                path.touch(mode=0o600)
        self.assertEqual(refused.exception.code, "READONLY_STATE")
        # A body error that happens to use the same text is NOT lock acquisition.
        with self.assertRaises(RunError) as body:
            with proof_lock(path):
                raise RunError("recovery_lock_busy")
        self.assertNotIsInstance(body.exception, GuestRefusal)

    def test_refusal_unexpected_error_never_stringifies_or_emits_canaries(self):
        class Unsafe(Exception):
            def __str__(self):
                raise AssertionError("CANARY stringification forbidden")

        with patch.object(Backend, "owned_domain", side_effect=Unsafe("CANARY secret")):
            self.refusal("UNKNOWN_REFUSAL")

    def test_refusal_supervised_category_and_success_do_not_mutate_existing_state(self):
        self.ephemeral = self.store.ephemeral(self.run_id)
        (self.ephemeral / "inventory").mkdir(mode=0o700)
        (self.ephemeral / "state.yml").write_text("{}")
        (self.ephemeral / "state.yml").chmod(0o600)
        self.config = self.relocate_config(self.ephemeral)
        self.artifact = self.ephemeral / "instance_config.yml"
        atomic_json(self.artifact, self.instances)
        os.environ.update(
            MOLECULE_EPHEMERAL_DIRECTORY=str(self.ephemeral), MOLECULE_INSTANCE_CONFIG=str(self.artifact),
            IDARSI_RUN_ID=self.run_id, IDARSI_HANDOFF="v1",
        )
        self.data.update(mode="supervised", mutation_protocol="sealed-v1",
                         admission_protocol=admission.PROTOCOL, config=self.config)
        self.store.save(self.data)
        atomic_json(self.store.directory(self.run_id) / "admission.json",
                    {"version": 1, "id": self.run_id, "state": "open"})
        before = {str(path): path.read_bytes() for path in self.store.root.rglob("*") if path.is_file()}
        with patch.object(admission, "prove_sessions", return_value=contextlib.nullcontext([self.data["workers"][0]])):
            self.assertEqual(len(self.invoke()), 7)
            with existing_lock(self.store.directory(self.run_id) / ".resources.lock"):
                self.refusal("LOCK_BUSY")
            admission_lock = self.store.directory(self.run_id) / ".admission.lock"
            with existing_lock(admission_lock):
                self.refusal("LOCK_BUSY")
            admission_lock.chmod(0o644)
            self.refusal("READONLY_STATE")
            admission_lock.chmod(0o600)
        after = {str(path): path.read_bytes() for path in self.store.root.rglob("*") if path.is_file()}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
