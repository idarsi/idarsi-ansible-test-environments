"""Owned bridge teardown guardrails; every backend/kernel query is mocked."""

import copy
import ipaddress
import json
import unittest
from unittest.mock import patch
import uuid
import xml.etree.ElementTree as ET

from test_isolated_safety import Fixture
from isolated_runs.backends import Backend
from isolated_runs.state import RunError, lock


class NetworkRemovalTests(Fixture):
    def setUp(self):
        super().setUp()
        identity = str(uuid.uuid4())
        self.intent = {"id": identity, "name": "itr-" + identity.replace("-", "")[:24]}
        self.bridge = "it" + identity.replace("-", "")[:12]
        self.run["network"] = self.intent
        self.store.save(self.run)
        self.backend = Backend(self.store, self.run)
        self.network = ET.Element("network")
        ET.SubElement(self.network, "name").text = self.intent["name"]
        ET.SubElement(self.network, "uuid").text = identity
        ET.SubElement(self.network, "bridge", name=self.bridge)
        ET.SubElement(self.network, "forward", mode="nat")
        ET.SubElement(self.network, "domain", name=self.intent["name"] + ".test", localOnly="yes")
        subnet = ipaddress.ip_network(self.run["subnet"])
        ip = ET.SubElement(self.network, "ip", address=str(subnet[1]), netmask="255.255.255.0")
        dhcp = ET.SubElement(ip, "dhcp")
        ET.SubElement(dhcp, "range", start=str(subnet[210]), end=str(subnet[250]))
        self.other_network = ET.fromstring(
            "<network><name>other-network</name><uuid>" + str(uuid.uuid4())
            + "</uuid><bridge name='otherbr'/></network>",
        )
        self.networks = [self.network, self.other_network]
        self.foreign_id = str(uuid.uuid4())
        self.active = {}
        self.persistent = {}
        self.links = [
            {"ifname": self.bridge, "ifindex": 10, "altnames": ["owned-alt"]},
            {"ifname": "otherbr", "ifindex": 20},
            {"ifname": "foreign-tap", "ifindex": 30, "master": 10},
        ]
        self.reads = []
        self.destroyed = []

    def domain(self, kind, attributes=None, actual=None):
        root = ET.Element("domain")
        ET.SubElement(root, "uuid").text = self.foreign_id
        devices = ET.SubElement(root, "devices")
        interface = ET.SubElement(devices, "interface", type=kind)
        if attributes is not None:
            ET.SubElement(interface, "source", attributes)
        if actual:
            resolved = ET.SubElement(interface, "actual", type=actual[0])
            ET.SubElement(resolved, "source", actual[1])
        return root

    def readonly(self, argv):
        self.reads.append(argv)
        if argv[:4] == ["ip", "-j", "link", "show"]:
            return json.dumps(self.links)
        if "list" in argv:
            if "--persistent" in argv:
                identities = self.persistent
            elif "--all" in argv:
                identities = set(self.active) | set(self.persistent)
            else:
                identities = self.active
            return "\n".join(sorted(identities))
        if "dumpxml" in argv:
            definitions = self.persistent if "--inactive" in argv else self.active
            identity = argv[argv.index("dumpxml") + 1]
            return ET.tostring(definitions[identity], encoding="unicode")
        self.fail("Unexpected query: " + repr(argv))

    def mutate(self, argv):
        self.assertEqual(argv[-2:], ["net-destroy", self.intent["id"]])
        with self.assertRaises(RunError), lock(self.store.root / ".storage-graph.lock", blocking=False):
            pass
        self.destroyed.append(argv)
        return ""

    def execute(self):
        with patch("isolated_runs.backends.libvirt_networks", side_effect=lambda: (
            [self.other_network] if self.destroyed else self.networks
        )), patch("isolated_runs.backends.command", side_effect=self.mutate), \
                patch("isolated_runs.network_references.command", side_effect=self.readonly):
            self.backend.destroy_network()

    def assert_refused(self):
        with self.assertRaises((RunError, ValueError)):
            self.execute()
        self.assertEqual(self.destroyed, [])
        self.assertEqual(self.store.load(self.run["id"])["network"], self.intent)

    def test_network_name_and_uuid_in_live_or_persistent_refuse_destroy(self):
        for reference in (self.intent["name"], self.intent["id"], self.intent["id"].upper()):
            for location in ("active", "persistent"):
                with self.subTest(reference=reference, definition=location):
                    self.active.clear()
                    self.persistent.clear()
                    getattr(self, location)[self.foreign_id] = self.domain("network", {"network": reference})
                    self.assert_refused()

    def test_direct_bridge_in_live_or_persistent_refuses_destroy(self):
        for location in ("active", "persistent"):
            with self.subTest(definition=location):
                self.active.clear()
                self.persistent.clear()
                getattr(self, location)[self.foreign_id] = self.domain("bridge", {"bridge": self.bridge})
                self.assert_refused()

    def test_different_live_and_persistent_interfaces_are_both_checked(self):
        for reference_location in ("active", "persistent"):
            with self.subTest(reference_location=reference_location):
                self.active[self.foreign_id] = self.domain("bridge", {"bridge": "otherbr"})
                self.persistent[self.foreign_id] = copy.deepcopy(self.active[self.foreign_id])
                getattr(self, reference_location)[self.foreign_id] = self.domain("bridge", {"bridge": self.bridge})
                self.assert_refused()
        self.assertTrue(any("--inactive" in argv for argv in self.reads))

    def test_network_alias_definition_using_owned_bridge_refuses_destroy(self):
        self.other_network.find("bridge").set("name", self.bridge)
        for reference in ("other-network", self.other_network.findtext("uuid")):
            with self.subTest(alias=reference):
                self.persistent[self.foreign_id] = self.domain("network", {"network": reference})
                self.assert_refused()

    def test_kernel_bridge_alternative_name_refuses_destroy(self):
        self.active[self.foreign_id] = self.domain("bridge", {"bridge": "owned-alt"})
        self.assert_refused()

    def test_actual_resolved_bridge_is_checked_not_just_declared_network(self):
        self.active[self.foreign_id] = self.domain(
            "network", {"network": "other-network"}, ("bridge", {"bridge": self.bridge}),
        )
        self.assert_refused()

    def test_direct_device_alias_or_owned_bridge_member_refuses_destroy(self):
        for device in (self.bridge, "owned-alt", "foreign-tap"):
            with self.subTest(device=device):
                self.active[self.foreign_id] = self.domain("direct", {"dev": device, "mode": "bridge"})
                self.assert_refused()

    def test_changed_expected_network_config_refuses_even_without_domains(self):
        original = ET.tostring(self.network)
        for path, attribute, value in (
            ("bridge", "name", "foreignbridge"), ("forward", "mode", "bridge"),
            ("ip", "address", "192.0.2.1"), ("./ip/dhcp/range", "end", "192.0.2.250"),
        ):
            with self.subTest(path=path):
                self.network = ET.fromstring(original)
                self.network.find(path).set(attribute, value)
                self.networks[0] = self.network
                self.assert_refused()

    def test_unresolvable_or_unsupported_source_fails_closed(self):
        for definition in (
            self.domain("network", {"network": "unknown-network"}),
            self.domain("bridge", {}),
            self.domain("ethernet"),
            self.domain("vhostuser", {"type": "unix", "path": "/fixture/socket"}),
            self.domain("bridge", {"bridge": "otherbr", "unexpected": "value"}),
        ):
            with self.subTest(xml=ET.tostring(definition)):
                self.active[self.foreign_id] = definition
                self.assert_refused()

    def test_missing_or_ambiguous_kernel_bridge_discovery_fails_closed(self):
        self.active[self.foreign_id] = self.domain("bridge", {"bridge": "otherbr"})
        self.links = [{"ifname": "otherbr", "ifindex": 20}]
        self.assert_refused()
        self.links.append({"ifname": self.bridge, "ifindex": 10, "altnames": ["otherbr"]})
        self.assert_refused()

    def test_query_failure_is_not_absence(self):
        self.persistent[self.foreign_id] = self.domain("bridge", {"bridge": "otherbr"})
        with patch.object(self, "readonly", side_effect=RunError("query denied")):
            self.assert_refused()

    def test_malformed_domain_xml_fails_closed(self):
        self.active[self.foreign_id] = self.domain("bridge", {"bridge": "otherbr"})
        readonly = self.readonly
        with patch.object(self, "readonly", side_effect=lambda argv: (
            "<domain>" if "dumpxml" in argv else readonly(argv)
        )):
            self.assert_refused()

    def test_inconsistent_domain_inventory_fails_closed(self):
        readonly = self.readonly
        with patch.object(self, "readonly", side_effect=lambda argv: (
            self.foreign_id if "list" in argv and "--all" in argv and "--persistent" not in argv
            else readonly(argv)
        )):
            self.assert_refused()

    def test_safe_unrelated_live_and_persistent_interfaces_allow_destroy(self):
        self.active[self.foreign_id] = self.domain("network", {"network": "other-network"})
        self.persistent[self.foreign_id] = self.domain("bridge", {"bridge": "otherbr"})
        self.execute()
        self.assertEqual(len(self.destroyed), 1)
        self.assertIsNone(self.store.load(self.run["id"])["network"])
        xml_queries = [argv for argv in self.reads if "dumpxml" in argv]
        self.assertEqual(len(xml_queries), 2)
        self.assertTrue(any("--inactive" in argv for argv in xml_queries))
        self.assertTrue(any("--inactive" not in argv for argv in xml_queries))

    def test_no_domains_allows_owned_network_cleanup(self):
        self.execute()
        self.assertEqual(len(self.destroyed), 1)
        self.assertIsNone(self.backend.data["network"])


if __name__ == "__main__":
    unittest.main()
