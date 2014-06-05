#!/usr/bin/env python

import sys
import os
sys.path.append(os.path.dirname(os.path.realpath(__file__))+'/../')
import unittest
from textwrap import dedent

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
    def setUp(self):
        self.ctxt = m.Context('POLES', '42')
        self.ctxt2 = m.Context('POLES', '105')
    
    def test_alias_local(self):
        # Check for import from VLANs
        self.assertItemsEqual(self.ctxt.get_alias('local'),
                              [ipaddr.IPv4Network("42.42.42.0/24"),
                               ipaddr.IPv6Network('2001:638:a000:42::/64')])
        self.assertItemsEqual(self.ctxt.get_alias('local', 'ipv4'),
                              [ipaddr.IPv4Network("42.42.42.0/24")])
        self.assertItemsEqual(self.ctxt.get_alias('local', 'ipv6'),
                              [ipaddr.IPv6Network('2001:638:a000:42::/64')])
        
        # Also check if TNETs gets imported
        self.assertItemsEqual(self.ctxt2.get_alias('local'),
                              [ipaddr.IPv4Network("10.0.5.0/24"),
                               ipaddr.IPv4Network('42.42.100.0/30')])
    
    def test_alias_any(self):
        self.assertItemsEqual(self.ctxt.get_alias('any'),
                              [ipaddr.IPv4Network("0.0.0.0/0"),
                               ipaddr.IPv6Network('::1/0')])
    
    def test_alias_from_hosts(self):
        # Straight from hosts.ini
        self.assertItemsEqual(self.ctxt.get_alias('rfc1918'),
                              [ipaddr.IPv4Network("10.0.0.0/8"),
                               ipaddr.IPv4Network("172.16.0.0/12"),
                               ipaddr.IPv4Network("192.168.0.0/16")])
        
        # From imported file:
        self.assertItemsEqual(self.ctxt.get_alias('testing'),
                              [ipaddr.IPv4Network("1.2.3.4/32"),
                               ipaddr.IPv6Network("::23/128")])
    
    def test_alias_set_and_get(self):
        # IPv4
        self.ctxt2.set_alias('fooo', '131.188.10.0/24')
        self.ctxt2.set_alias('fooo', '131.188.11.0/24')
        self.assertItemsEqual(self.ctxt2.get_alias('fooo'),
                              [ipaddr.IPv4Network("131.188.10.0/24"),
                               ipaddr.IPv4Network("131.188.11.0/24")])
        
        # IPv6
        self.ctxt2.set_alias('fooo', 'fe80::/64')
        self.ctxt2.set_alias('fooo', 'fe81::1/128')
        self.assertItemsEqual(self.ctxt2.get_alias('fooo', 'ipv6'),
                              [ipaddr.IPv6Network("fe80::/64"),
                               ipaddr.IPv6Network("fe81::1/128")])
    
    def test_policy_path(self):
        self.assertEqual(self.ctxt.get_policy_path(), 'policies/POLES/42.pol')
    
    def test_policy_dir(self):
        self.assertEqual(self.ctxt.get_policy_dir(), 'policies/POLES/')

    def test_get_acl(self):
        self.assertEqual(self.ctxt.get_acl(), m.ACL.from_file('policies/POLES/42.pol',
                         context=self.ctxt))
    
    def test_equal(self):
        self.assertNotEqual(self.ctxt, self.ctxt2)
        self.assertEqual(self.ctxt, m.Context('POLES', '42'))


class TestACL(unittest.TestCase):
    def test_parse(self):
        acl = m.ACL.from_string(dedent('''
        lan()
        domain()
        broadcast()
        antiSpoof()
        update()

        IN:
        permit ip 23.0.0.0/8 0.0.0.0/0
        deny ip 0.0.0.0/0 0.0.0.0/0

        OUT:
        permit ip 0.0.0.0/0 23.0.0.0/8
        deny ip 0.0.0.0/0 0.0.0.0/0
        '''))
        
        self.assertEqual(
            acl.get_rules('in'),
            [m.Rule('permit', m.Filter(['ip'], [ipaddr.IPv4Network('23.0.0.0/8')],
                                       [ipaddr.IPv4Network('0.0.0.0/0')])),
             m.Rule('deny', m.Filter(['ip'], [ipaddr.IPv4Network('0.0.0.0/0')],
                                     [ipaddr.IPv4Network('0.0.0.0/0')]))])
        self.assertEqual(
            acl.get_rules('out'),
            [m.Rule('permit', m.Filter(['ip'], [ipaddr.IPv4Network('0.0.0.0/0')],
                                       [ipaddr.IPv4Network('23.0.0.0/8')])),
             m.Rule('deny', m.Filter(['ip'], [ipaddr.IPv4Network('0.0.0.0/0')],
                                     [ipaddr.IPv4Network('0.0.0.0/0')]))])
        
        self.assertEqual(acl.macros,
                         [m.MacroCall('lan'), m.MacroCall('domain'), m.MacroCall('broadcast'), 
                          m.MacroCall('antiSpoof'), m.MacroCall('update')])
    
    # TODO test many more features!

class TestRule(unittest.TestCase):
    def test_parser(self):
        self.assertEqual(
            m.Rule('permit',
                   m.Filter(
                       ['ip'],
                       [ipaddr.IPv4Network('127.0.0.0/8')],
                       [ipaddr.IPv4Network('255.255.255.255/32')])),
            m.Rule.from_string('permit ip 127.0.0.0/8 255.255.255.255'))
        
        self.assertEqual(
            m.Rule('deny',
                   m.Filter(
                       ['tcp'],
                       sources=[ipaddr.IPv4Network('127.0.0.0/8')],
                       destinations=[ipaddr.IPv4Network('255.255.255.255/32')],
                       sports=m.Ports("80"),
                       dports=m.Ports("23")),
                   extensions=['established']),
            m.Rule.from_string('deny tcp 127.0.0.0/8 80 255.255.255.255 23 established'))

    def test_to_str(self):
        r = 'deny tcp 127.0.0.0/8 80 255.255.255.255/32 23 established'
        self.assertEqual(r, str(m.Rule.from_string(r)))


class TestFilter(unittest.TestCase):
    def test_parser(self):
        self.assertEqual(
            m.Filter(['tcp', 'udp'], [ipaddr.IPv4Network('127.0.0.0/8')],
                     [ipaddr.IPv4Network('255.255.255.255/32')],
                     sports=m.Ports("80"), dports=m.Ports("23")),
            m.Filter.from_string('tcp,udp 127.0.0.0/8 80 255.255.255.255 23'))
    
    def test_wrong_protocol(self):
        self.assertRaises(m.ProtocolDoesNotSupportPortsError, m.Filter.from_string,
                          'ip 1.1.1.1 23 2.3.4.5 42')
        self.assertRaises(m.ProtocolDoesNotSupportPortsError, m.Filter.from_string,
                          'ip 1.1.1.1 2.3.4.5 42')
        self.assertRaises(m.ProtocolDoesNotSupportPortsError, m.Filter.from_string,
                          'ip 1.1.1.1 23 2.3.4.5')


class TestMacroCall(unittest.TestCase):
    pass


if __name__ == '__main__':
    unittest.main()