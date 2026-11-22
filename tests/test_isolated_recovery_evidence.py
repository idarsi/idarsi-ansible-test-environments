"""Fake journal/kernel evidence; no real daemon, journal, proc or backend probes."""

import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import network_recovery as network, recovery, recovery_host as host, recovery_system as system
from isolated_runs.state import RunError, Store

OLD = "11111111-1111-4111-8111-111111111111"
NEW = "22222222-2222-4222-8222-222222222222"
MACHINE = "1234567890abcdef1234567890abcdef"


class NetworkEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = Store(self.root / "state")
        self.data = self.store.allocate("kvm", {}, lambda: [], self.root, "fixture")
        self.data["network"] = {"id": OLD, "name": "itr-" + OLD.replace("-", "")[:24]}
        self.bridge = "it" + OLD.replace("-", "")[:12]
        (self.store.root / ".storage-graph.lock").touch(mode=0o600)
        self.addresses = [{"ifindex": 1, "ifname": "lo", "addr_info": [
            {"family": "inet", "local": "127.0.0.1", "prefixlen": 8},
        ]}]
        self.routes = [{"dst": "default", "dev": "eth0"}]
        self.rules = {"nftables": [{"metainfo": {"json_schema_version": 1}}]}
        self.iptables = ""
        self.calls = []
        self.addCleanup(patch.stopall)
        self.networks = patch.object(network, "libvirt_networks", return_value=[]).start()
        self.references = patch.object(network, "assert_network_unused").start()
        self.helpers = patch.object(network, "helpers_absent").start()
        patch.object(network, "command", side_effect=self.command).start()

    def command(self, argv):
        self.calls.append(argv)
        if argv[:3] == ["ip", "-j", "address"]:
            return json.dumps(self.addresses)
        if argv[:3] in (["ip", "-j", "-4"], ["ip", "-j", "-6"]):
            return json.dumps(self.routes)
        if argv[0] == "nft":
            return json.dumps(self.rules)
        if argv[0] in ("iptables-save", "ip6tables-save"):
            return self.iptables
        self.fail("Unexpected command: " + repr(argv))

    def verify(self):
        return network.verify_absent(self.store, self.data)

    def test_absence_checks_os_helpers_and_canonical_references_twice(self):
        self.assertFalse(self.verify()["mutation"])
        self.assertEqual(self.networks.call_count, 2)
        self.helpers.assert_called_once()
        self.references.assert_called_once()
        self.assertTrue(self.references.call_args.kwargs["bridge_absent"])
        self.assertEqual(sum(argv[0] == "nft" for argv in self.calls), 2)
        self.assertFalse(any("net-destroy" in argv or "net-undefine" in argv for argv in self.calls))

    def test_present_exact_network_requires_reviewed_profile_no_delete(self):
        root = network.expected_network(self.data)
        self.networks.return_value = [root]
        with self.assertRaisesRegex(RunError, "current_mutation_profile_unavailable"):
            self.verify()
        self.assertEqual(self.calls, [])
        self.networks.return_value = [ET.fromstring(ET.tostring(root))]
        self.networks.return_value[0].find("uuid").text = NEW
        with self.assertRaisesRegex(RunError, "network_replaced"):
            self.verify()

    def test_bridge_collision_and_configuration_change_refuse(self):
        root = network.expected_network(self.data)
        root.find("name").text = "unrelated"
        root.find("uuid").text = NEW
        self.networks.return_value = [root]
        with self.assertRaisesRegex(RunError, "bridge_identity_collision"):
            self.verify()
        root.find("name").text = self.data["network"]["name"]
        root.find("uuid").text = OLD
        root.find("forward").set("mode", "route")
        with self.assertRaisesRegex(RunError, "bridge/NAT configuration changed"):
            self.verify()

    def test_queries_fail_closed(self):
        with patch.object(network, "command", side_effect=RunError("query unavailable")):
            with self.assertRaises(RunError):
                self.verify()
        self.networks.return_value = [ET.Element("network")]
        with self.assertRaisesRegex(RunError, "network_inventory_incomplete"):
            self.verify()

    def test_bridge_address_route_and_firewall_leftovers_refuse(self):
        baseline = (copy.deepcopy(self.addresses), copy.deepcopy(self.routes), copy.deepcopy(self.rules), "")
        for kind in ("bridge", "alias", "address", "route", "nft", "prefix", "range", "iptables", "wildcard"):
            self.addresses, self.routes, self.rules, self.iptables = copy.deepcopy(baseline)
            if kind == "bridge":
                self.addresses[0]["ifname"] = self.bridge
            elif kind == "alias":
                self.addresses[0]["altnames"] = [self.bridge]
            elif kind == "address":
                self.addresses[0]["addr_info"][0]["local"] = "10.0.0.1"
                self.addresses[0]["addr_info"][0]["prefixlen"] = 24
            elif kind == "route":
                self.routes = [{"dst": self.data["subnet"]}]
            elif kind == "nft":
                self.rules["nftables"].append({"rule": {
                    "family": "ip", "table": "fixture", "chain": "forward",
                    "expr": [{"match": {
                        "op": "==", "left": {"meta": {"key": "iifname"}}, "right": self.bridge,
                    }}],
                }})
            elif kind == "prefix":
                self.rules["nftables"].append({"set": {
                    "family": "ip", "table": "fixture", "name": "fixture",
                    "type": "ipv4_addr",
                    "elem": [{"prefix": {"addr": "10.0.0.0", "len": 8}}],
                }})
            elif kind == "range":
                self.rules["nftables"].append({"set": {
                    "family": "ip", "table": "fixture", "name": "fixture",
                    "type": "ipv4_addr",
                    "elem": [{"range": ["9.0.0.0", "11.0.0.0"]}],
                }})
            elif kind == "iptables":
                self.iptables = "*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s " + self.data["subnet"] + " -j MASQUERADE\nCOMMIT"
            elif kind == "wildcard":
                self.iptables = "*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -i it+ -j ACCEPT\nCOMMIT"
            reason = "firewall_footprint_remains" if kind in ("nft", "prefix", "range", "iptables", "wildcard") else "remains"
            with self.subTest(kind=kind), self.assertRaisesRegex(RunError, reason):
                self.verify()

    def test_foreign_consumer_preserves_intent(self):
        before = copy.deepcopy(self.data)
        self.references.side_effect = RunError("foreign consumer")
        with self.assertRaises(RunError):
            self.verify()
        self.assertEqual(before, self.data)

    def test_changed_backend_after_initial_absence_refuses(self):
        self.networks.side_effect = [[], [network.expected_network(self.data)]]
        with self.assertRaisesRegex(RunError, "network_changed_during_verification"):
            self.verify()

    def test_current_helper_even_after_term_is_not_absent(self):
        # A fake proc tree only. No real process inspection or signalling.
        proc = self.root / "proc"
        process = proc / "123"
        process.mkdir(parents=True)
        (process / "comm").write_text("dnsmasq\n")
        fields = ["S"] + ["0"] * 18 + ["1234"]
        (process / "stat").write_text("123 (dnsmasq) " + " ".join(fields))
        (process / "exe").symlink_to("/usr/sbin/dnsmasq")
        (process / "cmdline").write_bytes(
            b"dnsmasq\0--conf-file=/var/lib/libvirt/dnsmasq/" + self.data["network"]["name"].encode() + b".conf\0",
        )
        # Use the original callable saved before setUp's patch installation.
        mounts = system.parse_mountinfo("1 0 0:1 / /proc rw,nosuid,nodev,noexec - proc proc rw\n")
        with patch.object(system, "mounts", return_value=mounts), \
                patch.object(network, "Path", return_value=proc), \
                self.assertRaisesRegex(RunError, "network_helper_association_unproven"):
            REAL_HELPERS(self.data, self.bridge)
        (process / "cmdline").write_bytes(b"")
        with patch.object(system, "mounts", return_value=mounts), \
                patch.object(network, "Path", return_value=proc), self.assertRaisesRegex(RunError, "network_helper_identity_unknown"):
            REAL_HELPERS(self.data, self.bridge)


REAL_HELPERS = network.helpers_absent


class HostEvidenceTests(unittest.TestCase):
    def test_same_boot_block_precedes_any_host_journal_reads(self):
        with patch.object(host, "trusted_root_path") as trusted:
            with self.assertRaisesRegex(RunError, "same_boot_not_fenced"):
                host.boot_fence([{"boot": OLD}], OLD)
            trusted.assert_not_called()

    def test_trusted_paths_reject_nonroot_writable_hardlinked_or_symlink(self):
        for uid, mode, links in (
            (1, 0o100644, 1), (0, 0o100666, 1), (0, 0o100644, 2), (0, 0o120777, 1),
        ):
            info = SimpleNamespace(
                st_uid=uid, st_mode=mode, st_nlink=links,
                st_dev=1, st_ino=1, st_size=1, st_mtime_ns=1, st_ctime_ns=1,
            )
            with self.subTest(uid=uid, mode=mode, links=links), \
                    patch.object(Path, "lstat", return_value=info), self.assertRaises(RunError):
                host.trusted_root_path(Path("/fake"))

    def test_journal_matches_all_exact_boots_and_all_unique_machine_ids(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        machine = root / "machine"
        machine.write_text(MACHINE + "\n")
        executable = root / "journalctl"
        executable.touch()
        journal = root / "journal"
        journal.mkdir()
        (journal / "system.journal").touch()
        real_path = Path

        def path(value):
            return {
                "/etc/machine-id": machine, "/usr/bin/journalctl": executable,
                "/var/log/journal": journal.parent,
                "/var/log/journal/" + MACHINE: journal,
            }.get(value, real_path(value))

        # MagicMock supplies context manager protocol, no process is launched.
        with patch.object(host, "Path", side_effect=path), \
                patch.object(host, "trusted_root_path", return_value=(1, 2, 3, 4, 5)), \
                patch.object(host.subprocess, "Popen") as popen, \
                patch.object(host, "journal_command", return_value=MACHINE + "\n") as query:
            popen.return_value.__enter__.return_value.wait.return_value = 0
            # Constructing /var/log/journal / machine must map into fixture.
            with patch.object(host, "machine_identity", return_value=MACHINE):
                # Path("/var/log/journal") is joined inside the implementation.
                # Provide the expected child directory in this fake root.
                actual = journal.parent / MACHINE
                actual.mkdir()
                (actual / "system.journal").touch()
                result = host.boot_fence([{"boot": OLD}], NEW)
            self.assertEqual(result["route"], "host-boot")
            arguments = query.call_args.args[0]
            self.assertIn("--field=_MACHINE_ID", arguments)
            self.assertIn("_BOOT_ID=" + OLD.replace("-", ""), arguments)
            self.assertFalse(any("MESSAGE" in argument for argument in arguments))
            query.return_value = MACHINE + "\n" + "0" * 32 + "\n"
            with self.assertRaisesRegex(RunError, "historical_host_identity_unproven"):
                host.boot_fence([{"boot": OLD}], NEW)
            query.return_value = ""
            with self.assertRaisesRegex(RunError, "historical_host_identity_unproven"):
                host.boot_fence([{"boot": OLD}], NEW)

    def test_persistent_mount_allowlist_rejects_volatile_remote_and_readonly(self):
        store = SimpleNamespace(root=Path("/fake/store"))
        for filesystem, options, accepted in (
            ("xfs", "rw", True), ("ext4", "rw", True), ("btrfs", "rw", True),
            ("tmpfs", "rw", False), ("nfs", "rw", False), ("ext4", "ro", False),
        ):
            mountinfo = "1 0 8:1 / / " + options + " - " + filesystem + " /dev/fake rw\n"
            with self.subTest(filesystem=filesystem, options=options), \
                    patch.object(Path, "resolve", return_value=store.root), \
                    patch.object(Path, "read_text", return_value=mountinfo):
                if accepted:
                    recovery.persistent_store(store)
                else:
                    with self.assertRaisesRegex(RunError, "state_persistence_unproven"):
                        recovery.persistent_store(store)


if __name__ == "__main__":
    unittest.main()
