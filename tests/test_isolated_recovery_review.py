"""Direct regressions for the five first-review blockers; all host I/O is fake."""

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import test_isolated_recovery as fixtures
from isolated_runs import cli, network_recovery as network, recovery, recovery_system as system
from isolated_runs.state import RunError, Store

REAL_CONTEXT = fixtures.REAL_CONTEXT
REAL_VERIFY = network.verify_absent
REAL_HELPERS = network.helpers_absent
REAL_BACKEND_SOURCE = recovery.BACKEND_SOURCE
PROC_MOUNT = "1 0 0:1 / /proc rw,nosuid,nodev,noexec - proc proc rw\n"


class NamespaceContextTests(unittest.TestCase):
    def setUp(self):
        self.links = {}
        self.stats = {}
        for number, namespace in enumerate(("net", "mnt", "pid", "user"), start=100):
            for process in ("self", "1"):
                path = Path("/proc") / process / "ns" / namespace
                self.links[path] = f"{namespace}:[{number}]"
                self.stats[path] = SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o444, st_dev=4, st_ino=number,
                )

        def readlink(path):
            return self.links[path]

        def namespace_stat(path):
            return self.stats[path]

        links = patch.object(recovery.os, "readlink", side_effect=readlink)
        stats = patch.object(Path, "stat", autospec=True, side_effect=namespace_stat)
        self.readlink = links.start()
        self.addCleanup(links.stop)
        self.namespace_stat = stats.start()
        self.addCleanup(stats.stop)

    def test_equal_valid_identities_pass(self):
        self.assertIsNone(recovery.namespace_context())
        self.assertEqual(self.readlink.call_count, 8)
        self.assertEqual(self.namespace_stat.call_count, 8)

    def test_valid_different_identities_are_unsupported(self):
        for path, original in self.stats.items():
            with self.subTest(path=path):
                self.stats[path] = SimpleNamespace(
                    st_mode=original.st_mode, st_dev=original.st_dev, st_ino=999,
                )
                self.links[path] = f"{path.name}:[999]"
                with self.assertRaisesRegex(RunError, "^unsupported_controller_namespace$"):
                    recovery.namespace_context()
                self.stats[path] = original
                self.links[path] = f"{path.name}:[{original.st_ino}]"

    def test_invalid_identity_is_unproven_not_a_namespace_mismatch(self):
        for path, original in self.stats.items():
            for link, mode, inode in (
                ("", stat.S_IFDIR | 0o555, 1),
                ("", original.st_mode, original.st_ino),
                (self.links[path], stat.S_IFDIR | 0o555, original.st_ino),
                ("not-a-namespace", original.st_mode, original.st_ino),
                (f"unknown:[{original.st_ino}]", original.st_mode, original.st_ino),
                (f"{path.name}:[0]", original.st_mode, 0),
                (f"{path.name}:[999]", original.st_mode, original.st_ino),
            ):
                with self.subTest(path=path, link=link, mode=mode, inode=inode):
                    self.links[path] = link
                    self.stats[path] = SimpleNamespace(
                        st_mode=mode, st_dev=original.st_dev, st_ino=inode,
                    )
                    with self.assertRaisesRegex(RunError, "^controller_namespace_unproven$"):
                        recovery.namespace_context()
            self.stats[path] = original
            self.links[path] = f"{path.name}:[{original.st_ino}]"

    def test_unreadable_or_missing_identity_is_unproven(self):
        for boundary in (self.readlink, self.namespace_stat):
            original = boundary.side_effect
            for error in (PermissionError, FileNotFoundError):
                for target in self.links:
                    def inaccessible(path):
                        if path == target:
                            raise error("private procfs details")
                        return original(path)

                    with self.subTest(boundary=boundary, error=error, path=target):
                        boundary.side_effect = inaccessible
                        with self.assertRaisesRegex(RunError, "^controller_namespace_unproven$"):
                            recovery.namespace_context()
            boundary.side_effect = original

    def test_invalid_identity_takes_precedence_over_valid_mismatch(self):
        self.stats[Path("/proc/1/ns/net")].st_dev = 5
        self.links[Path("/proc/1/ns/user")] = ""
        with self.assertRaisesRegex(RunError, "^controller_namespace_unproven$"):
            recovery.namespace_context()

    def test_valid_different_devices_are_unsupported(self):
        self.stats[Path("/proc/1/ns/net")].st_dev = 5
        with self.assertRaisesRegex(RunError, "^unsupported_controller_namespace$"):
            recovery.namespace_context()


class ReviewStateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RecoveryTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def nft_boundary(self, expressions):
        fixture = self.fixture
        rules = {"nftables": [{"rule": {
            "family": "ip", "table": "filter", "chain": "forward", "expr": expressions,
        }}]}

        def command(argv):
            if argv[:3] == ["ip", "-j", "address"]:
                return '[{"ifname":"lo","ifindex":1,"addr_info":[]}]'
            if argv[0] == "ip":
                return "[]"
            if argv[0] == "nft":
                return json.dumps(rules)
            if argv[0] in ("iptables-save", "ip6tables-save"):
                return ""
            raise AssertionError(argv)

        return [
            patch.object(network, "command", side_effect=command),
            patch.object(network, "libvirt_networks", return_value=[]),
            patch.object(network, "assert_network_unused"),
            patch.object(network, "helpers_absent"),
            patch.object(network, "verify_absent", side_effect=REAL_VERIFY),
        ]

    def test_nft_bitmask_and_unknown_expressions_never_release_lease(self):
        fixture = self.fixture
        fixture.data["subnet"] = "10.1.0.0/24"
        fixture.store.save(fixture.data)
        fixture.new_boot()
        expressions = (
            {"match": {"op": "==", "left": {"&": [
                {"payload": {"protocol": "ip", "field": "saddr"}}, "255.0.0.0",
            ]}, "right": "10.0.0.0"}},
            {"unknown_future_selector": {"encoded_scope": 167837696}},
            {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "foreign"}},
        )
        for expression in expressions:
            with self.subTest(expression=expression), contextlib.ExitStack() as stack:
                for boundary in self.nft_boundary([expression, {"accept": None}]):
                    stack.enter_context(boundary)
                with self.assertRaisesRegex(RunError, "firewall_expression_unproven"):
                    fixture.apply()
                self.assertNotEqual(fixture.store.load(fixture.run_id)["status"], "cleaned")
                self.assertEqual(fixture.store.load(fixture.run_id)["network"], fixture.data["network"])

    def test_supported_nft_selectors_are_semantic_and_unknown_forms_block(self):
        import ipaddress

        subnet = ipaddress.ip_network("10.1.0.0/24")
        left = {"payload": {"protocol": "ip", "field": "saddr"}}
        for value in (
            "192.0.2.0/24", {"prefix": {"addr": "192.0.2.0", "len": 24}},
            {"range": ["192.0.2.1", "192.0.2.254"]}, {"set": ["192.0.2.1", "198.51.100.0/24"]},
        ):
            with self.subTest(disjoint=value):
                network.nft_expressions([{"match": {"op": "==", "left": left, "right": value}}], subnet, "itfixture")
        for value in (
            "10.0.0.0/8", {"prefix": {"addr": "10.0.0.0", "len": 8}},
            {"range": ["9.0.0.0", "11.0.0.0"]}, {"set": ["192.0.2.0/24", "10.1.0.1"]},
        ):
            with self.subTest(overlapping=value), self.assertRaisesRegex(RunError, "firewall_footprint_remains"):
                network.nft_expressions([{"match": {"op": "==", "left": left, "right": value}}], subnet, "itfixture")
        with self.assertRaisesRegex(RunError, "firewall_expression_unproven"):
            network.nft_expressions([{"match": {"op": "==", "left": left, "right": "@unknown"}}], subnet, "itfixture")

    def test_both_malformed_inventory_passes_have_bounded_cli_json(self):
        fixture = self.fixture
        fixture.new_boot()
        for malformed_pass in (1, 2):
            values = [ET.ParseError("private /secret/inventory.xml payload")] if malformed_pass == 1 else [
                [], ET.ParseError("private /secret/inventory.xml payload"),
            ]
            with self.subTest(pass_number=malformed_pass), \
                    patch.object(network, "verify_absent", side_effect=REAL_VERIFY), \
                    patch.object(network, "libvirt_networks", side_effect=values), \
                    patch.object(network, "kernel_absent"), \
                    patch.object(network, "helpers_absent"), \
                    patch.object(network, "assert_network_unused"), \
                    patch.object(Store, "open_existing", return_value=fixture.store), \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    contextlib.redirect_stderr(io.StringIO()) as errors:
                code = cli.main([
                    "recover-destroy", fixture.run_id, "--operation", fixture.operation, "--apply",
                ])
                self.assertEqual(code, 1)
                self.assertEqual(len(output.getvalue().splitlines()), 1)
                report = json.loads(output.getvalue())
                self.assertEqual(report["blockers"], ["network_inventory_xml_invalid"])
                self.assertEqual(errors.getvalue(), "")
                self.assertNotIn("secret", output.getvalue())
                self.assertNotEqual(fixture.store.load(fixture.run_id)["status"], "cleaned")

    def test_cli_also_bounds_direct_parse_error(self):
        fixture = self.fixture
        with patch.object(Store, "open_existing", return_value=fixture.store), \
                patch.object(recovery, "inspect", side_effect=ET.ParseError("secret private path")), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main([
                "recover-destroy", fixture.run_id, "--operation", fixture.operation, "--dry-run",
            ]), 1)
        self.assertEqual(json.loads(output.getvalue())["blockers"], ["network_inventory_xml_invalid"])
        self.assertNotIn("secret", output.getvalue())

    def test_second_inventory_structural_corruption_cannot_release(self):
        fixture = self.fixture
        fixture.new_boot()
        with patch.object(network, "verify_absent", side_effect=REAL_VERIFY), \
                patch.object(network, "libvirt_networks", side_effect=[[], [ET.Element("network")]]), \
                patch.object(network, "kernel_absent"), patch.object(network, "helpers_absent"), \
                patch.object(network, "assert_network_unused"), \
                self.assertRaisesRegex(RunError, "network_inventory_incomplete"):
            fixture.apply()
        self.assertNotEqual(fixture.store.load(fixture.run_id)["status"], "cleaned")


class MountAndProcessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.proc = self.root / "proc"
        self.proc.mkdir()

    def helper(self, name="dnsmasq", arguments=b"dnsmasq\0--conf-file=/unknown/current.conf\0"):
        process = self.proc / "123"
        process.mkdir()
        (process / "comm").write_text(name)
        (process / "stat").write_text("123 (" + name + ") " + " ".join(["S"] + ["0"] * 18 + ["1234"]))
        (process / "cmdline").write_bytes(arguments)
        (process / "exe").symlink_to("/usr/sbin/" + name)
        return process

    def scan(self, metadata=PROC_MOUNT):
        records = system.parse_mountinfo(metadata)
        with patch.object(system, "mounts", return_value=records), patch.object(network, "Path", return_value=self.proc):
            REAL_HELPERS({"network": {"id": fixtures.OLD_BOOT, "name": "fixture"}, "subnet": "10.1.0.0/24"}, "itfixture")

    def test_empty_full_proc_view_supported(self):
        self.scan()

    def test_any_helper_unproven_config_or_includes_blocks_even_unrelated(self):
        process = self.helper()
        for arguments in (
            b"dnsmasq\0--conf-file=/unknown/current.conf\0",
            b"dnsmasq\0--conf-dir=/unknown/includes\0",
            b"dnsmasq\0--conf-file=/var/lib/libvirt/dnsmasq/other.conf\0",
            b"dnsmasq\0--interface=foreign0\0",
        ):
            (process / "cmdline").write_bytes(arguments)
            with self.subTest(arguments=arguments), self.assertRaisesRegex(RunError, "network_helper_association_unproven"):
                self.scan()

    def test_radvd_also_requires_supported_association(self):
        self.helper("radvd", b"radvd\0-C\0/unknown/other.conf\0")
        with self.assertRaisesRegex(RunError, "network_helper_association_unproven"):
            self.scan()

    def test_hidepid_or_unknown_options_cannot_certify_empty_view(self):
        for option in ("hidepid=1", "hidepid=2", "hidepid=4", "hidepid=ptraceable", "hidepid=garbage", "subset=pid", "future=on"):
            metadata = PROC_MOUNT.replace("proc proc rw", "proc proc rw," + option)
            with self.subTest(option=option), self.assertRaisesRegex(RunError, "process_visibility_unproven"):
                self.scan(metadata)
        with self.assertRaises(RunError):
            self.scan("malformed metadata")

    def test_missing_or_restricted_proc_mount_blocks(self):
        for metadata in (
            "1 0 8:1 / / rw - ext4 /dev/fake rw",
            PROC_MOUNT.replace(" / /proc ", " /subtree /proc "),
            PROC_MOUNT + "2 1 0:2 / /proc/123 ro - tmpfs tmpfs ro\n",
        ):
            with self.subTest(metadata=metadata), self.assertRaises(RunError):
                self.scan(metadata)
        with patch.object(system, "mounts", side_effect=PermissionError("fake kernel metadata unavailable")), \
                patch.object(network, "Path", return_value=self.proc), self.assertRaises(OSError):
            REAL_HELPERS({}, "")

    def test_unreadable_comm_stat_cmdline_exe_never_means_unrelated(self):
        process = self.helper("python", b"python\0fixture\0")
        real_read_text, real_read_bytes, real_readlink = Path.read_text, Path.read_bytes, Path.readlink
        for name in ("comm", "stat", "cmdline", "exe"):
            def text(path, *args, **kwargs):
                if path == process / name:
                    raise PermissionError("fixture")
                return real_read_text(path, *args, **kwargs)

            def binary(path, *args, **kwargs):
                if path == process / name:
                    raise PermissionError("fixture")
                return real_read_bytes(path, *args, **kwargs)

            def link(path, *args, **kwargs):
                if path == process / name:
                    raise PermissionError("fixture")
                return real_readlink(path, *args, **kwargs)

            with self.subTest(name=name), patch.object(Path, "read_text", text), \
                    patch.object(Path, "read_bytes", binary), patch.object(Path, "readlink", link), \
                    self.assertRaisesRegex(RunError, "network_helper_identity_unknown"):
                self.scan()
        (process / "exe").unlink()
        with self.assertRaisesRegex(RunError, "network_helper_identity_unknown"):
            self.scan()

    def test_nested_escaped_tmpfs_never_falls_through_to_ext4(self):
        for escaped, decoded in (
            (r"user\040name", "user name"), (r"user\011name", "user\tname"),
            (r"user\012name", "user\nname"), (r"user\134name", "user\\name"),
        ):
            store = SimpleNamespace(root=Path("/home") / decoded / ".idarsi-test-runs")
            metadata = "1 0 8:1 / / rw - ext4 /dev/fake rw\n2 1 0:99 / /home/" + escaped + " rw - tmpfs tmpfs rw\n"
            with self.subTest(path=escaped), patch.object(Path, "resolve", return_value=store.root), \
                    patch.object(Path, "read_text", return_value=metadata), \
                    self.assertRaisesRegex(RunError, "state_persistence_unproven"):
                recovery.persistent_store(store)

    def test_unknown_mount_escape_and_prefix_not_component(self):
        with self.assertRaisesRegex(RunError, "mount_metadata_unproven"):
            system.parse_mountinfo(r"1 0 8:1 / /home/user\041name rw - ext4 /dev/fake rw")
        records = system.parse_mountinfo(
            "1 0 8:1 / / rw - ext4 /dev/fake rw\n2 1 0:99 / /home/user rw - tmpfs tmpfs rw",
        )
        self.assertEqual(system.containing(records, Path("/home/username/store"))["filesystem"], "ext4")


class LegacyBindingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RecoveryTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root / "helper"
        self.prefix = self.root / ".venv/ansible-current"
        self.current = {
            "root": str(self.root), "prefix": str(self.prefix), "lane": "ansible-current",
            "sources": {"fixture": "reviewed"}, "executable": str(self.prefix / "bin/python"),
            "interpreter_target": "/trusted/python",
        }
        self.data = copy.deepcopy(self.fixture.data)
        self.data["config"] = {
            "_idarsi_effective_env": {},
            "_idarsi_effective_role": self.data["role"],
            "_idarsi_effective_scenario": self.data["scenario"],
            "provisioner": {"playbooks": {
                "create": str(self.root / "molecule/managed/create.yml"),
                "destroy": str(self.root / "molecule/managed/destroy.yml"),
            }},
        }
        self.fixture.store.save(self.data)
        self.addCleanup(patch.stopall)
        patch.object(recovery, "REPO", self.root).start()
        patch.object(recovery, "trusted_path", side_effect=lambda path: path).start()
        self.measure = patch.object(recovery, "executing_context", side_effect=lambda: copy.deepcopy(self.current)).start()
        patch.object(recovery, "trusted_context", side_effect=REAL_CONTEXT).start()
        patch.dict(os.environ, {}, clear=True).start()

    def test_real_legacy_shape_dryrun_prepare_postboot_without_backfill(self):
        before = copy.deepcopy(self.data)
        result = recovery.inspect(self.fixture.store, self.fixture.run_id, self.fixture.operation)
        self.assertEqual(result["blockers"][0], "same_boot_not_fenced")
        self.assertEqual(result["binding_mode"], "legacy_runtime_measured")
        self.assertIn("historical_controller_environment_unrecorded", result["warnings"])
        self.fixture.prepare()
        data = self.fixture.store.load(self.fixture.run_id)
        record = data.pop("recoveries")
        self.assertEqual(data, before)
        self.assertEqual(record["current_context"]["mode"], "legacy_runtime_measured")
        self.assertEqual(set(record["current_context"]["missing"]), {"VIRTUAL_ENV", "IDARSI_TEST_ENVIRONMENT"})
        self.assertEqual(record["host_observation"]["context_digest"], recovery.digest(record["current_context"]))
        self.fixture.boot.return_value = fixtures.NEW_BOOT
        self.assertEqual(self.fixture.apply()["outcome"], "reconciled")
        self.assertEqual(self.fixture.store.load(self.fixture.run_id)["config"], before["config"])

    def test_each_optional_field_independently_missing_or_matching(self):
        for environment, missing in (
            ({}, 2), ({"VIRTUAL_ENV": str(self.prefix)}, 1),
            ({"IDARSI_TEST_ENVIRONMENT": str(self.root)}, 1),
            ({"VIRTUAL_ENV": str(self.prefix), "IDARSI_TEST_ENVIRONMENT": str(self.root)}, 0),
        ):
            self.data["config"]["_idarsi_effective_env"] = environment
            with self.subTest(environment=environment):
                self.assertEqual(len(REAL_CONTEXT(self.data)["missing"]), missing)

    def test_present_conflicting_malformed_fields_never_fall_back(self):
        for key in ("VIRTUAL_ENV", "IDARSI_TEST_ENVIRONMENT"):
            for value in ("", None, 7, [], "/different/canonical"):
                self.data["config"]["_idarsi_effective_env"] = {key: value}
                with self.subTest(key=key, value=value), self.assertRaises(RunError):
                    REAL_CONTEXT(self.data)

    def test_mixed_missing_playbooks_wrong_role_scenario_and_caller_spoof(self):
        baseline = copy.deepcopy(self.data)
        for mutate in (
            lambda data: data["config"]["provisioner"]["playbooks"].pop("create"),
            lambda data: data["config"]["provisioner"]["playbooks"].update(destroy="/foreign/molecule/managed/destroy.yml"),
            lambda data: data["config"].update(_idarsi_effective_role="/other/role"),
            lambda data: data["config"].update(_idarsi_effective_scenario="other"),
        ):
            data = copy.deepcopy(baseline)
            mutate(data)
            with self.assertRaises(RunError):
                REAL_CONTEXT(data)
        with patch.dict(os.environ, {"VIRTUAL_ENV": "/spoof"}), self.assertRaisesRegex(RunError, "unsupported_controller_override"):
            REAL_CONTEXT(baseline)

    def test_changed_measured_context_or_receipt_invalidates_postboot(self):
        self.fixture.prepare()
        self.fixture.boot.return_value = fixtures.NEW_BOOT
        baseline = copy.deepcopy(self.current)
        for key, value in (
            ("prefix", "/changed/controller"), ("root", "/changed/helper"),
            ("sources", {"fixture": "changed"}), ("interpreter_sha256", "changed-binary"),
        ):
            self.current = {**baseline, key: value}
            with self.subTest(key=key), self.assertRaises(RunError):
                self.fixture.apply()
        self.current = baseline
        data = self.fixture.store.load(self.fixture.run_id)
        data["recoveries"]["host_observation"]["context_digest"] = "tampered"
        self.fixture.store.save(data)
        with self.assertRaisesRegex(RunError, "invalid_host_observation"):
            self.fixture.apply()

    def test_missing_historical_environment_does_not_authorize_other_lanes_or_survivors(self):
        self.current["lane"] = "ansible-next"
        with self.assertRaisesRegex(RunError, "unsupported_legacy_controller_lane"):
            self.fixture.prepare()
        self.current["lane"] = "ansible-current"
        self.fixture.prepare()
        with self.assertRaisesRegex(RunError, "same_boot_not_fenced"):
            self.fixture.apply()
        self.fixture.boot.return_value = fixtures.NEW_BOOT
        self.fixture.verify.side_effect = RunError("current_mutation_profile_unavailable")
        with self.assertRaisesRegex(RunError, "current_mutation_profile_unavailable"):
            self.fixture.apply()
        self.assertEqual(self.fixture.store.load(self.fixture.run_id)["config"]["_idarsi_effective_env"], {})


class ExecutingContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.prefix = self.root / ".venv/ansible-current"
        self.bin = self.prefix / "bin"
        self.bin.mkdir(parents=True)
        (self.bin / "activate").write_text("# fixture activation\n")
        self.target = self.root / "system/python3"
        self.target.parent.mkdir()
        self.target.write_text("# fixture interpreter, never executed\n")
        self.target.chmod(0o755)
        self.executable = self.bin / "python3"
        self.executable.symlink_to(self.target)
        self.entry = self.root / "scripts/test-run"
        self.entry.parent.mkdir()
        self.entry.write_text("# fixture helper\n")
        managed = self.root / "molecule/managed"
        managed.mkdir(parents=True)
        for action in ("create", "destroy"):
            (managed / (action + ".yml")).write_text("---\n")
        self.site = self.prefix / "lib/python3.12/site-packages"
        self.site.mkdir(parents=True)
        modules = {}
        # Package/controller tests use a deterministic synthetic source profile,
        # not today's backend bytes as evidence for a frozen legacy approval.
        backend_source = b"# synthetic backend profile fixture; never executed\n"
        self.backend_digest = hashlib.sha256(backend_source).hexdigest()
        for name in (
            "recovery", "recovery_host", "recovery_system", "recovery_commands", "recovery_routes",
            "network_recovery", "network_references",
            "cli", "backends", "discovery", "processes", "admission", "state", "storage", "storage_references",
        ):
            source = self.root / "scripts/isolated_runs" / (name + ".py")
            source.parent.mkdir(exist_ok=True)
            source.write_bytes(backend_source if name == "backends" else b"# fixture source\n")
            modules["isolated_runs." + name] = SimpleNamespace(__file__=str(source))
        package = self.root / "scripts/isolated_runs"
        (package / "__init__.py").write_text("")
        modules["isolated_runs"] = SimpleNamespace(
            __file__=str(package / "__init__.py"), __path__=[str(package)],
        )
        self.modules = modules
        self.addCleanup(patch.stopall)
        patch.dict(sys.modules, modules).start()
        patch.object(recovery, "REPO", self.root).start()
        patch.object(recovery, "BACKEND_SOURCE", self.backend_digest).start()
        patch.object(sys, "prefix", str(self.prefix)).start()
        patch.object(sys, "executable", str(self.executable)).start()
        patch.object(sys, "version_info", (3, 12, 0)).start()
        patch.object(sys, "argv", [str(self.entry)]).start()
        patch.object(recovery, "namespace_context").start()
        patch.object(recovery, "trusted_path", side_effect=self.fixture_path).start()
        self.distribution = patch.object(recovery.importlib.metadata, "distribution", side_effect=self.package).start()

    def fixture_path(self, path, *, interpreter_entry=False):
        # Unit fixture trust boundary only; real trusted_path is tested below.
        if self.root not in path.parents and path != self.root:
            raise RunError("untrusted_controller_path")
        if path.is_symlink() and not interpreter_entry:
            raise RunError("original_context_path_changed")
        target = path.resolve(strict=True)
        if target.stat().st_mode & 0o022:
            raise RunError("untrusted_controller_path")
        return target

    def package(self, name):
        return SimpleNamespace(
            version={"ansible-core": "2.20.8", "molecule": "26.8.0"}[name],
            locate_file=lambda value: self.site,
        )

    def test_measures_actual_modules_prefix_and_normal_venv_symlink(self):
        result = recovery.executing_context()
        self.assertEqual(result["prefix"], str(self.prefix))
        self.assertEqual(result["executable"], str(self.executable))
        self.assertEqual(result["interpreter_target"], str(self.target))
        self.assertEqual(result["sources"]["backends"], self.backend_digest)
        self.target.write_text("# replacement fixture interpreter\n")
        self.assertNotEqual(result["interpreter_sha256"], recovery.executing_context()["interpreter_sha256"])

    def test_arbitrary_prefix_wrong_lane_python_or_interpreter_refuse(self):
        for attribute, value in (
            ("prefix", str(self.root / "arbitrary")),
            ("prefix", str(self.root / ".venv/unknown")),
            ("executable", str(self.target)),
            ("version_info", (3, 14, 0)),
        ):
            with self.subTest(attribute=attribute), patch.object(sys, attribute, value), self.assertRaises(RunError):
                recovery.executing_context()
        # Supported other lanes require their actual matching interpreter/profile,
        # not merely a lane-shaped pathname.
        with patch.object(sys, "prefix", str(self.root / ".venv/ansible-next")), self.assertRaises((RunError, OSError)):
            recovery.executing_context()

    def test_foreign_module_entry_and_writable_interpreter_target_refuse(self):
        module = self.modules["isolated_runs.recovery_host"]
        original = module.__file__
        module.__file__ = "/foreign/import/recovery_host.py"
        with self.assertRaisesRegex(RunError, "executing_module_root_mismatch"):
            recovery.executing_context()
        module.__file__ = original
        with patch.object(sys, "argv", [str(self.root / "foreign-helper")]), self.assertRaises((RunError, OSError)):
            recovery.executing_context()
        self.target.chmod(0o777)
        with self.assertRaisesRegex(RunError, "untrusted_controller_path"):
            recovery.executing_context()

    def test_source_profile_or_package_import_root_mismatch_refuses(self):
        package = self.modules["isolated_runs"]
        package.__path__ = ["/foreign/package"]
        with self.assertRaisesRegex(RunError, "executing_module_root_mismatch"):
            recovery.executing_context()
        package.__path__ = [str(self.root / "scripts/isolated_runs")]
        (self.root / "scripts/isolated_runs/backends.py").write_text("# unknown cleanup semantics\n")
        with self.assertRaisesRegex(RunError, "unsupported_original_source_profile"):
            recovery.executing_context()

    def test_real_legacy_profile_still_rejects_synthetic_source_before_tooling_checks(self):
        self.assertNotEqual(self.backend_digest, REAL_BACKEND_SOURCE)
        with patch.object(recovery, "BACKEND_SOURCE", REAL_BACKEND_SOURCE):
            with self.assertRaisesRegex(RunError, "unsupported_original_source_profile"):
                recovery.executing_context()
            self.distribution.assert_not_called()
        self.assertEqual(recovery.executing_context()["sources"]["backends"], self.backend_digest)

    def test_combined_backend_source_is_not_automatically_approved_for_recovery(self):
        actual = Path(__file__).resolve().parents[1] / "scripts/isolated_runs/backends.py"
        source = actual.read_bytes()
        self.assertNotEqual(hashlib.sha256(source).hexdigest(), REAL_BACKEND_SOURCE)
        (self.root / "scripts/isolated_runs/backends.py").write_bytes(source)
        with patch.object(recovery, "BACKEND_SOURCE", REAL_BACKEND_SOURCE):
            with self.assertRaisesRegex(RunError, "unsupported_original_source_profile"):
                recovery.executing_context()
            self.distribution.assert_not_called()

    def test_wrong_tooling_versions_or_import_location_refuse(self):
        for version, location in (("0", self.site), ("26.8.0", self.root)):
            self.distribution.side_effect = lambda name: SimpleNamespace(
                version=version, locate_file=lambda value: location,
            )
            with self.subTest(version=version), self.assertRaisesRegex(RunError, "approved_controller_tooling_unproven"):
                recovery.executing_context()


REAL_TRUSTED_PATH = recovery.trusted_path


class TrustedInterpreterPathTests(unittest.TestCase):
    def test_real_path_validator_allows_safe_link_and_checks_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("fixture")
            target.chmod(0o755)
            link = root / "python3"
            link.symlink_to(target)
            original = Path.lstat

            def metadata(path, *args, **kwargs):
                # Only external ancestors are a fake root-controlled fixture.
                # Entry, symlink and target all use actual temporary metadata.
                if path in root.parents:
                    return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
                return original(path, *args, **kwargs)

            with patch.object(Path, "lstat", metadata):
                self.assertEqual(REAL_TRUSTED_PATH(link, interpreter_entry=True), target)
                target.chmod(0o777)
                with self.assertRaisesRegex(RunError, "untrusted_controller_path"):
                    REAL_TRUSTED_PATH(link, interpreter_entry=True)
                with self.assertRaisesRegex(RunError, "original_context_path_changed"):
                    REAL_TRUSTED_PATH(link)


if __name__ == "__main__":
    unittest.main()
