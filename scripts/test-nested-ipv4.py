#!/usr/bin/env python3
import unittest

from nested_ipv4 import validate


class NestedIPv4Tests(unittest.TestCase):
    def test_valid_static_configuration(self):
        validate("192.168.250.20", "255.255.255.0", "192.168.250.1", "192.168.250.1")

    def test_rejects_network_mismatch(self):
        with self.assertRaises(ValueError):
            validate("192.168.251.20", "255.255.255.0", "192.168.250.1", "192.168.250.1")

    def test_rejects_dhcp_collision(self):
        with self.assertRaises(ValueError):
            validate("192.168.250.120", "255.255.255.0", "192.168.250.1", "192.168.250.1")

    def test_rejects_nonmember_gateway_or_dns(self):
        for gateway, dns in (("192.168.251.1", "192.168.250.1"), ("192.168.250.1", "8.8.8.8")):
            with self.subTest(gateway=gateway, dns=dns), self.assertRaises(ValueError):
                validate("192.168.250.20", "255.255.255.0", gateway, dns)


if __name__ == "__main__":
    unittest.main()
