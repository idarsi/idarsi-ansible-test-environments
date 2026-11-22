"""Legacy firewall semantic regressions: fake output and private temporary Stores."""

import contextlib
import io
import ipaddress
import json
import unittest
from unittest.mock import patch

import test_isolated_recovery as fixtures
from isolated_runs import cli, network_recovery as network
from isolated_runs.state import RunError, Store

REAL_VERIFY = network.verify_absent
OPAQUE_RULE = '-A FORWARD -m u32 --u32 "12&0xFF000000=0x0A000000" -j ACCEPT'


def save(rule: str) -> str:
    return "*filter\n:FORWARD ACCEPT [0:0]\n" + rule + "\nCOMMIT\n"


class IptablesSelectorTests(unittest.TestCase):
    def validate(self, text, version=4):
        network.validate_iptables(text, ipaddress.ip_network("10.1.0.0/24"), "itfixture", version)

    def test_exact_u32_hex_reproduction_and_opaque_extensions_refuse(self):
        for rule in (
            OPAQUE_RULE,
            '-A FORWARD -m bpf --bytecode "opaque-address-selector" -j ACCEPT',
            "-A FORWARD -m set --match-set concealed_networks src -j ACCEPT",
            "-A FORWARD -m iprange --src-range 9.0.0.0-11.0.0.0 -j ACCEPT",
            '-A FORWARD -m string --string "opaque" --algo bm -j ACCEPT',
            "-A FORWARD --unknown-network-selector 0x0A000000 -j ACCEPT",
            "-A FORWARD ! -s 192.0.2.0/24 -j ACCEPT",
        ):
            with self.subTest(rule=rule), self.assertRaisesRegex(RunError, "firewall_expression_unproven"):
                self.validate(save(rule))

    def test_known_direct_address_interface_and_default_state_forms(self):
        for rule in (
            "-A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j ACCEPT",
            "-A FORWARD -i eth0 -o eth+ -j DROP",
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A FORWARD -m state --state INVALID -j DROP",
            "-A FORWARD -p tcp -m tcp --dport 22 -j ACCEPT",
            "-A FORWARD -p udp -m udp --sport 1000:2000 -j RETURN",
            '-A FORWARD -m comment --comment "ordinary policy annotation" -j ACCEPT',
        ):
            with self.subTest(rule=rule):
                self.validate(save(rule))
        self.validate(save("-A FORWARD -s 2001:db8::/32 -j ACCEPT"), version=6)
        self.validate("")

    def test_enclosing_subnets_interface_wildcards_and_aliases_refuse(self):
        for rule in (
            "-A FORWARD -s 10.0.0.0/8 -j ACCEPT",
            "-A FORWARD --destination 10.0.0.0/255.0.0.0 -j ACCEPT",
            "-A FORWARD --source 10.1.0.1 -j ACCEPT",
            "-A FORWARD -i it+ -j ACCEPT",
            "-A FORWARD --out-interface itfixture -j ACCEPT",
            "-A FORWARD -o + -j ACCEPT",
        ):
            with self.subTest(rule=rule), self.assertRaisesRegex(RunError, "firewall_footprint_remains"):
                self.validate(save(rule))

    def test_missing_extension_options_and_malformed_rule_values_refuse(self):
        for rule in (
            "-A FORWARD -m", "-A FORWARD -m conntrack -j ACCEPT",
            "-A FORWARD --ctstate ESTABLISHED -j ACCEPT",
            "-A FORWARD -m state --state -j ACCEPT",
            "-A FORWARD -m comment -j ACCEPT",
            "-A FORWARD -p tcp --dport -j ACCEPT",
            "-A FORWARD -p tcp --dport 65536 -j ACCEPT",
            "-A FORWARD -p tcp --dport 200:100 -j ACCEPT",
            "-A FORWARD -p tcp -m udp -j ACCEPT",
            "-A FORWARD -s 0x0A000000/8 -j ACCEPT",
            "-A FORWARD -s 192.0.2.0/24 -m u32 --u32 opaque -j ACCEPT",
            "-A FORWARD -j FOREIGN_CHAIN",
            "-A FORWARD -j MASQUERADE",
            "-A FORWARD -j ACCEPT --opaque-address-math 0x0A000000",
        ):
            with self.subTest(rule=rule), self.assertRaises(RunError):
                self.validate(save(rule))

    def test_dump_framing_and_tokenization_errors_refuse(self):
        for text in (
            save('-A FORWARD -m comment --comment "unterminated -j ACCEPT'),
            "*filter\n:FORWARD ACCEPT [0:0]\n-A MISSING -j ACCEPT\nCOMMIT",
            "*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -j ACCEPT",
            "*filter\n:FORWARD ACCEPT [0:0]\n*nat\nCOMMIT",
            "*filter\n:FORWARD ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT",
            "COMMIT", "*filter\nCOMMIT\n*filter\nCOMMIT",
            "*filter\n:FORWARD UNKNOWN [0:0]\nCOMMIT",
        ):
            with self.subTest(text=text), self.assertRaises(RunError):
                self.validate(text)


class IptablesRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RecoveryTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.data["subnet"] = "10.1.0.0/24"
        self.fixture.store.save(self.fixture.data)
        self.fixture.new_boot()

    def boundaries(self, view, text, calls):
        def command(argv):
            calls.append(argv)
            if argv[:3] == ["ip", "-j", "address"]:
                return '[{"ifname":"lo","ifindex":1,"addr_info":[]}]'
            if argv[0] == "ip":
                return "[]"
            if argv[0] == "nft":
                return '{"nftables":[]}'
            if argv[0] in ("iptables-save", "ip6tables-save"):
                return text if argv[0] == view else ""
            raise AssertionError(argv)

        return (
            patch.object(network, "command", side_effect=command),
            patch.object(network, "libvirt_networks", return_value=[]),
            patch.object(network, "assert_network_unused"),
            patch.object(network, "helpers_absent"),
            patch.object(network, "verify_absent", side_effect=REAL_VERIFY),
        )

    def test_opaque_selector_in_either_view_never_verifies_or_releases(self):
        fixture = self.fixture
        for view in ("iptables-save", "ip6tables-save"):
            calls = []
            with self.subTest(view=view), contextlib.ExitStack() as stack:
                for boundary in self.boundaries(view, save(OPAQUE_RULE), calls):
                    stack.enter_context(boundary)
                with self.assertRaisesRegex(RunError, "firewall_expression_unproven"):
                    fixture.apply()
                data = fixture.store.load(fixture.run_id)
                self.assertNotEqual(data["status"], "cleaned")
                self.assertEqual(data["network"], fixture.data["network"])
                self.assertNotIn("completion", data["operations"][-1])
                self.assertTrue(all(attempt["phase"] == "intent" for attempt in data["recoveries"]["attempts"]))
                self.assertIn(["iptables-save"], calls)
                self.assertIn(["ip6tables-save"], calls)

    def test_malformed_output_cli_is_bounded_and_private_output_not_echoed(self):
        fixture = self.fixture
        calls = []
        with contextlib.ExitStack() as stack:
            for boundary in self.boundaries("iptables-save", save(
                '-A FORWARD -m comment --comment "private /secret/firewall.conf',
            ), calls):
                stack.enter_context(boundary)
            stack.enter_context(patch.object(Store, "open_existing", return_value=fixture.store))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            errors = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            code = cli.main(["recover-destroy", fixture.run_id, "--operation", fixture.operation, "--apply"])
            self.assertEqual(code, 1)
            self.assertEqual(len(output.getvalue().splitlines()), 1)
            self.assertEqual(json.loads(output.getvalue())["blockers"], ["firewall_query_incomplete"])
            self.assertNotIn("secret", output.getvalue())
            self.assertEqual(errors.getvalue(), "")
        self.assertNotEqual(fixture.store.load(fixture.run_id)["status"], "cleaned")


if __name__ == "__main__":
    unittest.main()
