"""Owned bridge teardown guardrails; every backend/kernel query is mocked."""

import copy
import contextlib
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
        self.original_domain = {"id": str(uuid.uuid4()), "name": "itr-" + uuid.uuid4().hex}
        self.intent["domain_ownership"] = {
            "version": 1, "protocol": "create-intent-v1",
            "generation": self.run["id"], "domains": [self.original_domain],
        }
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
        self.states = {}
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
        ET.SubElement(root, "name").text = "foreign-domain"
        devices = ET.SubElement(root, "devices")
        interface = ET.SubElement(devices, "interface", type=kind)
        if attributes is not None:
            ET.SubElement(interface, "source", attributes)
        if actual:
            resolved = ET.SubElement(interface, "actual", type=actual[0])
            ET.SubElement(resolved, "source", actual[1])
        return root

    def readonly(self, argv, **kwargs):
        self.reads.append(argv)
        if argv[:4] == ["ip", "-j", "link", "show"]:
            return json.dumps(self.links)
        if "net-list" in argv:
            return "\n".join(root.findtext("uuid") for root in self.networks)
        if "net-dumpxml" in argv:
            identity = argv[argv.index("net-dumpxml") + 1]
            return ET.tostring(next(root for root in self.networks if root.findtext("uuid") == identity), encoding="unicode")
        if "domstate" in argv:
            self.assertEqual(kwargs["env"]["LC_ALL"], "C")
            return self.states.get(argv[-1], "running" if argv[-1] in self.active else "shut off")
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
        with patch.object(self, "readonly", side_effect=lambda argv, **kwargs: (
            "<domain>" if "dumpxml" in argv else readonly(argv, **kwargs)
        )):
            self.assert_refused()

    def test_inconsistent_domain_inventory_fails_closed(self):
        readonly = self.readonly
        with patch.object(self, "readonly", side_effect=lambda argv, **kwargs: (
            self.foreign_id if "list" in argv and "--all" in argv and "--persistent" not in argv
            else readonly(argv, **kwargs)
        )):
            self.assert_refused()

    def test_safe_unrelated_live_and_persistent_interfaces_allow_destroy(self):
        self.active[self.foreign_id] = self.domain("network", {"network": "other-network"})
        self.persistent[self.foreign_id] = self.domain("bridge", {"bridge": "otherbr"})
        self.execute()
        self.assertEqual(len(self.destroyed), 1)
        self.assertIsNone(self.store.load(self.run["id"])["network"])
        xml_queries = [argv for argv in self.reads if "dumpxml" in argv]
        self.assertEqual(len(xml_queries), 4)
        self.assertTrue(any("--inactive" in argv for argv in xml_queries))
        self.assertTrue(any("--inactive" not in argv for argv in xml_queries))

    def test_no_domains_allows_owned_network_cleanup(self):
        self.execute()
        self.assertEqual(len(self.destroyed), 1)
        self.assertIsNone(self.backend.data["network"])


    def test_two_foreign_shutoff_dangling_names_allow_four_distinct_targets(self):
        for _ in range(4):
            identity = str(uuid.uuid4())
            self.intent = {"id": identity, "name": "itr-" + identity.replace("-", "")[:24]}
            self.intent["domain_ownership"] = {
                "version": 1, "protocol": "create-intent-v1",
                "generation": self.run["id"], "domains": [self.original_domain],
            }
            self.bridge = "it" + identity.replace("-", "")[:12]
            self.network.find("name").text = self.intent["name"]
            self.network.find("uuid").text = identity
            self.network.find("bridge").set("name", self.bridge)
            self.network.find("domain").set("name", self.intent["name"] + ".test")
            self.links[0]["ifname"] = self.bridge
            self.backend.data["network"] = self.intent
            self.destroyed.clear()
            self.persistent.clear()
            for name in ("missing-network-a", "missing-network-b"):
                self.foreign_id = str(uuid.uuid4())
                self.persistent[self.foreign_id] = self.domain("network", {"network": name})
            self.execute()
            self.assertEqual(len(self.destroyed), 1)

    def test_dangling_requires_confirmed_shutoff_and_inactive_only(self):
        for state in ("running", "paused", "in shutdown", "crashed", "unknown", "", "SHUTOFF"):
            self.persistent[self.foreign_id] = self.domain("network", {"network": "missing"})
            self.states[self.foreign_id] = state
            with self.subTest(state=state):
                self.assert_refused()
        self.states[self.foreign_id] = "shut off"
        self.active[self.foreign_id] = self.domain("user")
        self.assert_refused()

    def test_dangling_strict_source_actual_and_later_interface_guards(self):
        for attributes in (
            {"network": "missing", "portgroup": "extra"},
            {"network": "missing", "bridge": "otherbr"},
            {"network": "missing", "dev": "otherbr"},
            {"network": "missing", "unexpected": "extra"},
            {"network": "bad name"},
        ):
            self.persistent[self.foreign_id] = self.domain("network", attributes)
            self.assert_refused()
        for child in ("seclabel", "unknown"):
            root = self.domain("network", {"network": "missing"})
            ET.SubElement(root.find("./devices/interface/source"), child)
            self.persistent[self.foreign_id] = root
            self.assert_refused()
        self.persistent[self.foreign_id] = self.domain(
            "network", {"network": "missing"}, ("bridge", {"bridge": "otherbr"}),
        )
        self.assert_refused()
        root = self.domain("network", {"network": "missing"})
        interface = ET.SubElement(root.find("devices"), "interface", type="bridge")
        ET.SubElement(interface, "source", bridge=self.bridge)
        self.persistent[self.foreign_id] = root
        self.assert_refused()

    def test_dangling_without_explicit_context_and_recovery_opt_in_refused(self):
        from isolated_runs.network_references import InterfaceReferences, assert_network_unused

        references = InterfaceReferences(self.bridge, self.intent, self.networks, runner=self.readonly)
        with self.assertRaises(RunError):
            references.check_domain(self.domain("network", {"network": "missing"}), self.foreign_id)
        with self.assertRaises(RunError):
            references.check_domain(
                self.domain("network", {"network": "missing"}), self.foreign_id,
                state="shut off", xml_origin="inactive", persistent=True, active=False,
            )
        self.persistent[self.foreign_id] = self.domain("network", {"network": "missing"})
        with self.assertRaises(RunError):
            assert_network_unused(
                self.network, self.intent, self.run["subnet"], self.networks,
                bridge_absent=True, runner=self.readonly,
            )
        self.assertFalse(any("domstate" in argv for argv in self.reads))

    def test_known_owned_domain_with_dangling_reference_refused(self):
        self.persistent[self.foreign_id] = self.domain("network", {"network": "missing"})
        self.backend.data["guests"] = [{"id": self.foreign_id}]
        self.assert_refused()

    def test_generation_owned_description_blocks_after_guest_journal_is_cleared(self):
        root = self.domain("network", {"network": "missing"})
        ET.SubElement(root, "description").text = "idarsi-run:" + self.run["id"]
        self.persistent[self.foreign_id] = root
        self.backend.data["guests"] = []
        self.assert_refused()

    def test_original_uuid_or_name_blocks_after_guest_journal_clear_without_description(self):
        for identity in ("uuid", "name"):
            for description in (None, "idarsi-run:foreign"):
                self.foreign_id = self.original_domain["id"] if identity == "uuid" else str(uuid.uuid4())
                root = self.domain("network", {"network": "missing"})
                root.find("name").text = self.original_domain["name"] if identity == "name" else "foreign"
                if description is not None:
                    ET.SubElement(root, "description").text = description
                self.persistent = {self.foreign_id: root}
                self.backend.data["guests"] = []
                with self.subTest(identity=identity, description=description):
                    self.assert_refused()

    def test_missing_or_invalid_creation_provenance_never_enables_exception(self):
        self.persistent[self.foreign_id] = self.domain("network", {"network": "missing"})
        original = copy.deepcopy(self.intent["domain_ownership"])
        for value in (
            None, {}, dict(original, protocol="reconstructed"),
            dict(original, generation=str(uuid.uuid4())),
            dict(original, domains=[self.original_domain, self.original_domain]),
        ):
            if value is None:
                self.intent.pop("domain_ownership", None)
            else:
                self.intent["domain_ownership"] = value
            self.store.save(self.backend.data)
            with self.subTest(value=value):
                self.assert_refused()
        self.assertNotIn("domstate", [argument for query in self.reads for argument in query])

    def test_missing_or_duplicate_domain_name_cannot_prove_foreign_ownership(self):
        for duplicate in (False, True):
            root = self.domain("network", {"network": "missing"})
            if duplicate:
                ET.SubElement(root, "name").text = self.original_domain["name"]
            else:
                root.remove(root.find("name"))
            self.persistent[self.foreign_id] = root
            with self.subTest(duplicate=duplicate):
                self.assert_refused()

    def test_original_names_and_uuids_persist_before_guest_creation_and_after_removal(self):
        def create(guest, platform, index):
            saved = self.store.load(self.run["id"])
            self.assertIn(
                {"id": guest["id"], "name": guest["name"]},
                saved["network"]["domain_ownership"]["domains"],
            )
            return {"instance": guest["logical"]}

        with patch.object(self.backend, "network"), patch.object(self.backend, "create_domain", side_effect=create):
            self.backend.create([{"name": "new-guest"}])
        before = copy.deepcopy(self.backend.data["network"]["domain_ownership"])
        with patch.object(self.backend, "check_context"), \
                patch.object(self.backend, "owned_domain", return_value=None), \
                patch.object(self.backend.storage, "directory", return_value=contextlib.nullcontext(123)):
            self.backend.destroy_guests()
        saved = self.store.load(self.run["id"])
        self.assertEqual(saved["guests"], [])
        self.assertEqual(saved["network"]["domain_ownership"], before)

    def test_persistent_network_alias_cannot_hide_behind_unrelated_live_bridge(self):
        self.persistent[self.foreign_id] = self.domain("network", {"network": "other-network"})
        readonly = self.readonly
        defined = copy.deepcopy(self.other_network)
        defined.find("bridge").set("name", self.bridge)
        with patch.object(self, "readonly", side_effect=lambda argv, **kwargs: (
            ET.tostring(defined, encoding="unicode")
            if "net-dumpxml" in argv and self.other_network.findtext("uuid") in argv
            else readonly(argv, **kwargs)
        )):
            self.assert_refused()

    def test_name_uuid_collision_duplicates_and_missing_bridge_refused(self):
        for change in ("uuid-only", "collision", "duplicate", "missing-bridge"):
            original = copy.deepcopy(self.networks)
            if change == "uuid-only":
                reference = self.other_network.findtext("uuid")
            else:
                reference = "other-network"
            if change == "collision":
                self.other_network.find("name").text = self.intent["id"]
                reference = self.intent["id"]
            if change == "duplicate":
                self.networks.append(copy.deepcopy(self.other_network))
            if change == "missing-bridge":
                self.other_network.remove(self.other_network.find("bridge"))
            self.persistent[self.foreign_id] = self.domain("network", {"network": reference})
            with self.subTest(change=change):
                self.assert_refused()
            self.networks = original
            self.network, self.other_network = self.networks

    def test_both_passes_discover_fresh_links_even_without_domains(self):
        self.execute()
        self.assertEqual(sum(argv == ["ip", "-j", "link", "show"] for argv in self.reads), 2)

    def test_foreign_name_uuid_collision_has_multiple_matches_and_denies(self):
        reference = self.other_network.findtext("uuid")
        collision = ET.fromstring(
            "<network><name>" + reference + "</name><uuid>" + str(uuid.uuid4())
            + "</uuid><bridge name='collisionbr'/></network>",
        )
        self.networks.append(collision)
        self.persistent[self.foreign_id] = self.domain("network", {"network": reference})
        self.assert_refused()

    def test_incomplete_duplicate_and_malformed_fresh_network_inventory_denies(self):
        self.persistent[self.foreign_id] = self.domain("network", {"network": "missing"})
        readonly = self.readonly
        for output in ("", self.intent["id"], self.intent["id"] + "\n" + self.intent["id"], "bad-uuid"):
            with self.subTest(output=output), patch.object(self, "readonly", side_effect=lambda argv, **kwargs: (
                output if "net-list" in argv and "--all" in argv and "--persistent" not in argv
                else readonly(argv, **kwargs)
            )):
                self.assert_refused()

    def test_changes_or_discovery_failure_in_second_pass_refuse(self):
        for change in ("links", "state", "xml", "network", "network-state", "inventory", "failure"):
            self.active.clear()
            self.persistent[self.foreign_id] = self.domain("bridge", {"bridge": "otherbr"})
            self.states[self.foreign_id] = "shut off"
            self.reads.clear()
            readonly = self.readonly
            links = copy.deepcopy(self.links)
            network = copy.deepcopy(self.other_network)
            second_pass = [False]

            def changed(argv, **kwargs):
                if argv == ["ip", "-j", "link", "show"] and any(
                    read == argv for read in self.reads
                ):
                    second_pass[0] = True
                    if change == "failure":
                        raise RunError("snapshot unavailable")
                    if change == "links":
                        self.links[1]["ifindex"] = 21
                    elif change == "state":
                        self.states[self.foreign_id] = "paused"
                    elif change == "xml":
                        ET.SubElement(self.persistent[self.foreign_id], "description").text = "changed"
                    elif change == "network":
                        ET.SubElement(self.other_network, "description").text = "changed"
                    elif change == "inventory":
                        self.persistent.clear()
                if second_pass[0] and change == "network-state" and "net-list" in argv and "--all" not in argv:
                    return ""
                return readonly(argv, **kwargs)

            with self.subTest(change=change), patch.object(self, "readonly", side_effect=changed):
                self.assert_refused()
            self.links = links
            self.networks[1] = self.other_network = network


if __name__ == "__main__":
    unittest.main()
