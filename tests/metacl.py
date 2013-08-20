#!/usr/bin/env python

import unittest
import lib.metacl as m
import lib.third_party.ipaddr as ipaddr

class TestStringToPorts(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(m.string_to_ports("80"), [('eq', 80)])
    
    def test_multiple_ports(self):
        ports = m.string_to_ports("80,443,8080")
        self.assertItemsEqual(ports, [('eq', 80), ('eq', 443), ('eq', 8080)])
    
    def test_port_range(self):
        ports = m.string_to_ports("1-1024")
        self.assertItemsEqual(ports, [('range', (1, 1024))])
    
    def test_multiple_port_ranges(self):
        ports = m.string_to_ports("1-1024,2000-2342")
        self.assertItemsEqual(ports, [('range', (1, 1024)), ('range', (2000, 2342))])
    
    def test_single_and_range_combination(self):
        ports = m.string_to_ports("1-1024,8080")
        self.assertItemsEqual(ports, [('eq', 8080), ('range', (1, 1024))])
    
    def test_sigle_port_contained_in_range(self):
        ports = m.string_to_ports("1-1024,80")
        self.assertItemsEqual(ports, [('range', (1, 1024))])
    
    def test_multiple_ports_and_ranges(self):
        ports = m.string_to_ports("1-1024,8080,4000-5000,2342")
        self.assertItemsEqual(ports, 
            [('eq', 8080), ('range', (1, 1024)), ('range', (4000,5000)), ('eq', 2342)])
    
    def test_multiple_same_ports(self):
        ports = m.string_to_ports("23,23")
        self.assertItemsEqual(ports, [('eq', 23)])
    
    def test_complete_overlapping_ranges(self):
        # Complete overlap
        ports = m.string_to_ports("1-1024,512-1000")
        self.assertItemsEqual(ports, [('range', (1, 1024))])
    
    def test_partial_overlapping_ranges(self):
        # Partial overlap
        ports = m.string_to_ports("1-1024,512-2342")
        self.assertItemsEqual(ports, [('range', (1, 2342))])
    
    def test_meeting_ranges(self):
        # Meeting borders
        ports = m.string_to_ports("1-1024,1024-2342")
        self.assertItemsEqual(ports, [('range', (1, 2342))])

class TestStringToIPs(unittest.TestCase):
    def test_simple_ip_address(self):
        # IPv4
        ips = m.string_to_ips("127.0.0.1")
        self.assertItemsEqual(ips, [ipaddr.IPv4Network("127.0.0.1/32")])
        # IPv6
        ips = m.string_to_ips("fe80:2342:abcd:ff12:1016:8f7f:fe80:c9a")
        self.assertItemsEqual(ips, [ipaddr.IPv6Network("fe80:2342:abcd:ff12:1016:8f7f:fe80:c9a/128")])
    
    def test_simple_ip_network(self):
        # IPv4
        ips = m.string_to_ips("127.0.0.0/8")
        self.assertItemsEqual(ips, [ipaddr.IPv4Network("127.0.0.0/8")])
        # IPv6
        ips = m.string_to_ips("fe80::/64")
        self.assertItemsEqual(ips, [ipaddr.IPv6Network("fe80::/64")])
    
    def test_multiple_ip_addresses(self):
        # IPv4
        ips = m.string_to_ips("127.0.0.1;127.0.0.2;192.168.0.23")
        self.assertItemsEqual(ips, [ipaddr.IPv4Network("127.0.0.1/32"),
                                    ipaddr.IPv4Network("127.0.0.2/32"),
                                    ipaddr.IPv4Network("192.168.0.23/32")])
        # IPv6
        ips = m.string_to_ips("fe80:2342:abcd:ff12:1016:8f7f:fe80:c9a;248f::1234;::dead:beef")
        self.assertItemsEqual(ips, [ipaddr.IPv6Network("fe80:2342:abcd:ff12:1016:8f7f:fe80:c9a/128"),
                                    ipaddr.IPv6Network("248f::1234/128"),
                                    ipaddr.IPv6Network("::dead:beef/128")])
    
        # IPv6+IPv4
        # is not allowed
    
    def test_multiple_ip_networks(self):
        # IPv4
        ips = m.string_to_ips("127.0.0.0/8;192.168.0.0/24;169.168.0.0/16")
        self.assertItemsEqual(ips, [ipaddr.IPv4Network("127.0.0.1/8"),
                                    ipaddr.IPv4Network("192.168.0.0/24"),
                                    ipaddr.IPv4Network("169.168.0.0/16")])
        # IPv6
        ips = m.string_to_ips("fe80::/64;248f::/16;2342:16::/10")
        self.assertItemsEqual(ips, [ipaddr.IPv6Network("fe80::/64"),
                                    ipaddr.IPv6Network("248f::/16"),
                                    ipaddr.IPv6Network("2342:16::/10")])
                                    
    def test_asterix_notation(self):
        # IPv4
        ips = m.string_to_ips("172.17.0.*")
        self.assertItemsEqual(ips, [ipaddr.IPv4Network("172.17.0.0/24")])
        # IPv6
        # Not supported
    
    def test_comma_notation(self):
        # IPv4
        ips = m.string_to_ips("172.17.0.1,5,8")
        self.assertItemsEqual(ips, [ipaddr.IPv4Network("172.17.0.1/32"),
                                    ipaddr.IPv4Network("172.17.0.5/32"),
                                    ipaddr.IPv4Network("172.17.0.8/32")])
        # IPv6
        ips = m.string_to_ips("fe80::23,42,1")
        self.assertItemsEqual(ips, [ipaddr.IPv6Network("fe80::23/128"),
                                    ipaddr.IPv6Network("fe80::42/128"),
                                    ipaddr.IPv6Network("fe80::1/128")])
    
    def test_overlapping(self):
        # IPv4
        ips = m.string_to_ips("0.0.0.0/0;192.168.0.0/24;169.168.0.0/16;127.0.0.1")
        self.assertItemsEqual(ips, [ipaddr.IPv4Network("0.0.0.0/0")])
        # IPv6
        ips = m.string_to_ips("::/0;fe80::/64;248f::/16;2342:16::/10;" + \
            "fe80:2342:abcd:ff12:1016:8f7f:fe80:c9a")
        self.assertItemsEqual(ips, [ipaddr.IPv6Network("::/0")])