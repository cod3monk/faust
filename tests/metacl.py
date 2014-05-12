#!/usr/bin/env python

import sys
import os
sys.path.append(os.path.dirname(os.path.realpath(__file__))+'/../')
import unittest

import lib.metacl as m
import lib.third_party.ipaddr as ipaddr
import lib.config as config

def setUpModule():
    config.load('tests/environment/config.ini')

def tearDownModule():
    config.unload()

class TestStringToPorts(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(m.Ports("80"), m.Ports([80]))
    
    def test_multiple_ports(self):
        ports = m.Ports("80,443,8080")
        self.assertItemsEqual(ports, m.Ports([80,443,8080]))
    
    def test_port_range(self):
        ports = m.Ports("1-1024")
        self.assertItemsEqual(ports, m.Ports([], [(1, 1024)]))
    
    def test_multiple_port_ranges(self):
        ports = m.Ports("1-1024,2000-2342")
        self.assertItemsEqual(ports, m.Ports([], [(1, 1024),(2000, 2342)]))
    
    def test_single_and_range_combination(self):
        ports = m.Ports("1-1024,8080")
        self.assertItemsEqual(ports, m.Ports([8080], [(1, 1024)]))
    
    def test_sigle_port_contained_in_range(self):
        ports = m.Ports("1-1024,80")
        self.assertItemsEqual(ports, m.Ports([], [(1, 1024)]))
    
    def test_multiple_ports_and_ranges(self):
        ports = m.Ports("1-1024,8080,4000-5000,2342")
        self.assertItemsEqual(ports, m.Ports([2342, 8080], [(1, 1024), (4000, 5000)]))
    
    def test_multiple_same_ports(self):
        ports = m.Ports("23,23")
        self.assertItemsEqual(ports, m.Ports([23]))
    
    def test_complete_overlapping_ranges(self):
        # Complete overlap
        ports = m.Ports("1-1024,512-1000")
        self.assertItemsEqual(ports, m.Ports([], [(1, 1024)]))
    
    def test_partial_overlapping_ranges(self):
        # Partial overlap
        ports = m.Ports("1-1024,512-2342")
        self.assertItemsEqual(ports, m.Ports([], [(1, 2342)]))
    
    def test_meeting_ranges(self):
        # Meeting borders
        ports = m.Ports("1-1024,1024-2342")
        self.assertItemsEqual(ports, m.Ports([], [(1, 2342)]))
    
    def test_to_string_and_back(self):
        ports = m.Ports([1,23,42,18000],[(100,200),(1024,4096)])
        # To string
        self.assertItemsEqual(str(ports), "1,23,42,18000,100-200,1024-4096")
        # and back
        self.assertItemsEqual(m.Ports(str(ports)), ports)

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

class TestContext(unittest.TestCase):
    def test_init(self):
        m.Context('POLES', '23')

if __name__ == '__main__':
    unittest.main()