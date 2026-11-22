"""Security regressions: fake root tools/routes, no live process/backend probes."""

import contextlib
import copy
import io
import ipaddress
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import test_isolated_recovery as fixtures
from isolated_runs import (
    cli, discovery, network_recovery as network, network_references as references,
    recovery_commands as commands, recovery_routes as routes,
)
from isolated_runs.state import RunError, Store

REAL_VERIFY = network.verify_absent
DOMAIN = fixtures.NEW_BOOT


class RootToolTests(unittest.TestCase):
    def setUp(self):
        self.metadata = {
            name: SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
            for name in ("/", "/usr", "/usr/bin", "/usr/sbin")
        }
        for name in commands.TOOLS.values():
            self.metadata[name] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
        self.links = {}
        self.writable = set()
        self.addCleanup(patch.stopall)
        patch.object(commands.os, "geteuid", return_value=1000).start()

        def metadata(path):
            try:
                return self.metadata[str(path)]
            except KeyError as exc:
                raise FileNotFoundError from exc

        patch.object(Path, "lstat", metadata).start()
        patch.object(Path, "readlink", lambda path: Path(self.links[str(path)])).start()
        patch.object(Path, "resolve", lambda path, strict=True: Path(os.path.normpath(str(path)))).start()
        patch.object(commands.os, "access", side_effect=lambda path, mode, **kwargs: (
            str(path) in self.writable if mode == os.W_OK else True
        )).start()
        self.calls = []

        def run(argv, **kwargs):
            self.calls.append((argv, kwargs))
            kwargs["stdout"].write(b"[]")
            return SimpleNamespace(returncode=0)

        self.run = patch.object(commands.subprocess, "run", side_effect=run).start()

    def test_malicious_path_and_loader_environment_never_reach_child(self):
        hostile = {
            "PATH": "/untrusted-fixture:/usr/bin", "LD_PRELOAD": "/private/loader.so",
            "LD_LIBRARY_PATH": "/untrusted", "PYTHONPATH": "/untrusted",
            "HOME": "/private/home", "XDG_CONFIG_HOME": "/private/config",
            "LIBVIRT_DEFAULT_URI": "qemu+ssh://foreign/system",
            "LIBVIRT_AUTH_FILE": "/private/auth", "BASH_ENV": "/private/script",
            "VIRSH_DEFAULT_CONNECT_URI": "test:///default",
            "BASH_FUNC_ip%%": "() { malicious; }",
        }
        with patch.dict(os.environ, hostile, clear=True):
            self.assertEqual(commands.command(["ip", "-j", "address", "show"]), "[]")
        argv, options = self.calls[-1]
        self.assertEqual(argv[0], "/usr/sbin/ip")
        self.assertEqual(options["executable"], "/usr/sbin/ip")
        self.assertEqual(options["env"], commands.ENVIRONMENT)
        self.assertEqual(options["cwd"], "/")
        self.assertEqual(options["stdin"], commands.subprocess.DEVNULL)
        self.assertEqual(options["stderr"], commands.subprocess.DEVNULL)
        self.assertFalse(any("untrusted" in str(value) or "private" in str(value) for value in options["env"].values()))

    def test_root_owned_merged_usr_and_alternatives_links_validated(self):
        self.metadata["/usr/sbin"] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o777)
        self.links["/usr/sbin"] = "bin"
        self.metadata["/usr/bin/ip"] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
        commands.command(["ip", "-j", "address", "show"])
        self.assertEqual(self.calls[-1][0][0], "/usr/sbin/ip")
        self.assertEqual(self.calls[-1][1]["executable"], "/usr/bin/ip")
        self.metadata["/usr/bin/ip"] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o777)
        self.links["/usr/bin/ip"] = "/usr/bin/ip.real"
        self.metadata["/usr/bin/ip.real"] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
        commands.command(["ip", "-j", "address", "show"])
        self.assertEqual(self.calls[-1][0][0], "/usr/sbin/ip")
        self.assertEqual(self.calls[-1][1]["executable"], "/usr/bin/ip.real")

    def test_insecure_substituted_or_writable_tool_components_never_execute(self):
        baseline = copy.deepcopy(self.metadata)
        for name, uid, mode in (
            ("/usr/sbin/ip", 1000, stat.S_IFREG | 0o755),
            ("/usr", 1000, stat.S_IFDIR | 0o755),
            ("/usr/sbin/ip", 0, stat.S_IFREG | 0o775),
            ("/usr/sbin/ip", 0, stat.S_IFREG | stat.S_ISUID | 0o755),
            ("/usr/bin", 0, stat.S_IFDIR | 0o777),
            ("/usr/sbin/ip", 1000, stat.S_IFLNK | 0o777),
        ):
            self.metadata = copy.deepcopy(baseline)
            self.metadata[name] = SimpleNamespace(st_uid=uid, st_mode=mode)
            with self.subTest(name=name, uid=uid, mode=mode), self.assertRaises(RunError):
                commands.command(["ip", "-j", "address", "show"])
        self.metadata = baseline
        self.writable.add("/usr/sbin/ip")  # POSIX ACL grants current UID write.
        with self.assertRaisesRegex(RunError, "recovery_tool_untrusted"):
            commands.command(["ip", "-j", "address", "show"])
        self.run.assert_not_called()

    def test_missing_tool_or_untrusted_symlink_target_never_falls_back_to_path(self):
        self.metadata.pop("/usr/sbin/ip")
        with self.assertRaisesRegex(RunError, "recovery_query_failed"):
            commands.command(["ip", "-j", "address", "show"])
        self.metadata["/usr/sbin/ip"] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o777)
        self.links["/usr/sbin/ip"] = "/foreign/ip"
        self.metadata["/foreign"] = SimpleNamespace(st_uid=1000, st_mode=stat.S_IFDIR | 0o755)
        with self.assertRaisesRegex(RunError, "recovery_tool_untrusted"):
            commands.command(["ip", "-j", "address", "show"])
        self.run.assert_not_called()

    def test_multicall_save_alias_preserved_but_authenticated_target_executed(self):
        self.metadata["/usr/sbin/iptables-save"] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o777)
        self.links["/usr/sbin/iptables-save"] = "/usr/sbin/xtables-nft-multi"
        self.metadata["/usr/sbin/xtables-nft-multi"] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
        commands.command(["iptables-save"])
        argv, options = self.calls[-1]
        self.assertEqual(argv, ["/usr/sbin/iptables-save"])
        self.assertEqual(options["executable"], "/usr/sbin/xtables-nft-multi")

    def test_unsupported_or_mutating_arguments_are_rejected_before_exec(self):
        for argv in (
            ["ip", "link", "delete", "bridge0"], ["nft", "flush", "ruleset"],
            ["virsh", "--connect", "qemu:///system", "net-destroy", DOMAIN],
            ["virsh", "--connect", "qemu+ssh://foreign/system", "list", "--uuid"],
            ["virsh", "--connect", "qemu:///system", "dumpxml", "/private/file"],
            ["iptables-save", "--file", "/private/file"], ["/untrusted/ip", "-j", "address", "show"],
        ):
            with self.subTest(argv=argv), self.assertRaisesRegex(RunError, "recovery_query_unsupported"):
                commands.command(argv)
        self.run.assert_not_called()

    def test_process_failures_are_bounded_without_echoing_private_payload(self):
        for failure in (OSError("private /secret/tool"), commands.subprocess.TimeoutExpired("private", 60)):
            self.run.side_effect = failure
            with self.subTest(failure=type(failure).__name__), self.assertRaisesRegex(RunError, "^recovery_query_failed$"):
                commands.command(["ip", "-j", "address", "show"])
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(returncode=1)
        with self.assertRaisesRegex(RunError, "^recovery_query_failed$"):
            commands.command(["ip", "-j", "address", "show"])

    def test_reused_inventory_and_foreign_domain_guard_use_protected_runner(self):
        # A complete fake read-only libvirt/domain/interface inventory, routed
        # through the actual runner subprocess boundary and its explicit env.
        seen = []
        def run(argv, **kwargs):
            seen.append(argv)
            if argv[0] == "/usr/bin/virsh":
                self.assertIn("--readonly", argv)
                verb = argv[4]
                if verb in ("net-list", "list"):
                    value = DOMAIN
                elif verb == "net-dumpxml":
                    value = "<network><name>foreign</name><uuid>" + DOMAIN + "</uuid><bridge name='other0'/></network>"
                else:
                    value = "<domain><uuid>" + DOMAIN + "</uuid><devices><interface type='bridge'><source bridge='other0'/></interface></devices></domain>"
            else:
                self.assertEqual(argv, ["/usr/sbin/ip", "-j", "link", "show"])
                value = '[{"ifindex":1,"ifname":"other0"}]'
            self.assertEqual(kwargs["env"], commands.ENVIRONMENT)
            kwargs["stdout"].write(value.encode())
            return SimpleNamespace(returncode=0)
        self.run.side_effect = run
        networks = discovery.libvirt_networks(runner=commands.command)
        data = {"network": {"id": fixtures.OLD_BOOT, "name": "itr-" + fixtures.OLD_BOOT.replace("-", "")[:24]}, "subnet": "10.1.0.0/24"}
        references.assert_network_unused(
            network.expected_network(data), data["network"], data["subnet"], networks,
            bridge_absent=True, runner=commands.command,
        )
        self.assertTrue(any("dumpxml" in argv for argv in seen))
        self.assertTrue(any("--inactive" in argv for argv in seen))
        self.assertTrue(any(argv[0] == "/usr/sbin/ip" for argv in seen))
        self.assertTrue(all(Path(argv[0]).is_absolute() for argv in seen))

    def test_ordinary_inventory_default_still_uses_existing_command_policy(self):
        with patch.object(discovery, "command", side_effect=[
            DOMAIN, "<network><uuid>" + DOMAIN + "</uuid></network>",
        ]) as query:
            self.assertEqual(len(discovery.libvirt_networks()), 1)
        self.assertEqual(query.call_args_list[0].args[0], discovery.VIRSH + ["net-list", "--all", "--uuid"])


class RouteSchemaTests(unittest.TestCase):
    def verify(self, route, version=4):
        routes.verify([route], ipaddress.ip_network("10.1.0.0/24"), "itfixture", version)

    def test_gateway_source_and_cross_family_via_association_refuse(self):
        for key, value in (
            ("gateway", "10.1.0.1"), ("prefsrc", "10.1.0.2"), ("src", "10.0.0.0/8"),
            ("from", "10.1.0.0/24"), ("via", {"family": "inet", "host": "10.1.0.1"}),
        ):
            with self.subTest(key=key), self.assertRaisesRegex(RunError, "subnet_route_remains"):
                self.verify({"dst": "198.51.100.0/24", "dev": "eth0", key: value, "flags": ["onlink"]})
        with self.assertRaisesRegex(RunError, "subnet_route_remains"):
            self.verify({"dst": "2001:db8::/32", "via": {"family": "inet", "addr": "10.1.0.1"}}, version=6)

    def test_invalid_or_unresolved_route_fields_are_unknown_not_absent(self):
        for route in (
            {"dst": "unrecognized-encoding"}, {"dst": "default", "gateway": "not-an-address"},
            {"dst": "default", "src": "0x0A010001"}, {"dst": "default", "nhid": 5},
            {"dst": "default", "encap": {"type": "opaque"}},
            {"dst": "default", "via": "10.1.0.1"},
            {"dst": "default", "via": {"family": "unknown", "host": "10.1.0.1"}},
            {"dst": "default", "nexthops": [{"nhid": 5}]},
            {"dst": "default", "multipath": [{"gateway": "invalid"}]},
            {"dst": "default", "flags": ["opaque"]},
        ):
            with self.subTest(route=route), self.assertRaises(RunError):
                self.verify(route)

    def test_explicit_multipath_gateway_and_interface_association_refuse(self):
        for key in ("nexthops", "multipath"):
            for hop in ({"gateway": "10.1.0.1", "dev": "eth0"}, {"dev": "itfixture", "weight": 1}):
                with self.subTest(key=key, hop=hop), self.assertRaises(RunError):
                    self.verify({"dst": "198.51.100.0/24", key: [hop]})

    def test_ordinary_default_and_disjoint_typed_routes_are_supported(self):
        for route in (
            {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "protocol": "dhcp", "metric": 100},
            {"dst": "198.51.100.0/24", "prefsrc": "192.0.2.2", "src": "192.0.2.0/24", "from": "all"},
            {"dst": "198.51.100.0/24", "nexthops": [{"gateway": "192.0.2.1", "dev": "eth0", "weight": 1}]},
        ):
            self.verify(route)
        self.verify({"dst": "default", "gateway": "2001:db8::1", "dev": "eth0", "pref": "medium"}, version=6)


class RouteRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RecoveryTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.data["subnet"] = "10.1.0.0/24"
        self.fixture.store.save(self.fixture.data)
        self.fixture.new_boot()

    def boundaries(self, route, corrupt_after_first=False):
        count = [0]
        def command(argv):
            if argv[:3] == ["ip", "-j", "address"]:
                return '[{"ifindex":1,"ifname":"lo","addr_info":[]}]'
            if argv[:3] == ["ip", "-j", "-4"]:
                count[0] += 1
                return json.dumps([] if corrupt_after_first and count[0] <= 2 else [route])
            if argv[:3] == ["ip", "-j", "-6"]:
                return "[]"
            if argv[0] == "nft":
                return '{"nftables":[]}'
            if argv[0] in ("iptables-save", "ip6tables-save"):
                return ""
            raise AssertionError(argv)
        return (
            patch.object(network, "verify_absent", side_effect=REAL_VERIFY),
            patch.object(network, "command", side_effect=command),
            patch.object(network, "libvirt_networks", return_value=[]),
            patch.object(network, "assert_network_unused"),
            patch.object(network, "helpers_absent"),
        )

    def test_gateway_or_invalid_destination_never_seals_or_releases(self):
        fixture = self.fixture
        for route in (
            {"dst": "198.51.100.0/24", "gateway": "10.1.0.1", "dev": "eth0", "flags": ["onlink"]},
            {"dst": "unrecognized-encoding"},
        ):
            with self.subTest(route=route), contextlib.ExitStack() as stack:
                for boundary in self.boundaries(route):
                    stack.enter_context(boundary)
                with self.assertRaises(RunError):
                    fixture.apply()
                data = fixture.store.load(fixture.run_id)
                self.assertEqual(data["network"], fixture.data["network"])
                self.assertNotEqual(data["status"], "cleaned")
                self.assertNotIn("completion", data["operations"][-1])
                self.assertTrue(all(attempt["phase"] == "intent" for attempt in data["recoveries"]["attempts"]))

    def test_route_corruption_in_repeated_verification_still_retains_lease(self):
        fixture = self.fixture
        with contextlib.ExitStack() as stack:
            for boundary in self.boundaries({"dst": "malformed"}, corrupt_after_first=True):
                stack.enter_context(boundary)
            with self.assertRaisesRegex(RunError, "route_query_incomplete"):
                fixture.apply()
        data = fixture.store.load(fixture.run_id)
        self.assertNotEqual(data["status"], "cleaned")
        self.assertEqual(data["recoveries"]["attempts"][-1]["phase"], "resources_verified")
        self.assertNotIn("completion", data["operations"][-1])

    def test_invalid_route_cli_output_is_bounded(self):
        fixture = self.fixture
        with contextlib.ExitStack() as stack:
            for boundary in self.boundaries({"dst": "private /secret/route-data"}):
                stack.enter_context(boundary)
            stack.enter_context(patch.object(Store, "open_existing", return_value=fixture.store))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            errors = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            code = cli.main(["recover-destroy", fixture.run_id, "--operation", fixture.operation, "--apply"])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue())["blockers"], ["route_query_incomplete"])
            self.assertNotIn("secret", output.getvalue())
            self.assertEqual(errors.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
