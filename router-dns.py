#!/usr/bin/python
# -*- coding: utf-8 -*-

import lib.config as cfg
from faust import read_lannetfile
import ConfigParser

cfg.load()
router_cfg = ConfigParser.SafeConfigParser()
routers_file = cfg.get('global', 'routers_file')
assert len(router_cfg.read(routers_file)) > 0, 'File could not be read: ' + routers_file
routingdomains = router_cfg.items('routingdomains')
routingdomains = dict(routingdomains)
for k in routingdomains:
    routingdomains[k] = routingdomains[k].split(', ')

vlans = read_lannetfile(cfg.get('global', 'vlans_file'))

# print routingdomains #, vlans

print "SUBJECT: Ein paar, wenige, Updates"
print
print "Hallo Jochen,"
print ""
print "hier unsere aktuellen VLAN-Router-Interface einträge:"

for rd, id, name, ipv4, ipv6, comment in vlans:
    rd = rd.lower()

    if rd not in routingdomains:
        continue

    # print rd, id, ipv4, ipv6
    hosts_v4 = []
    hosts_v6 = []

    if ipv4:
        # /31 nets:
        if ipv4.numhosts == 2:
            host_id = 0
            for h in routingdomains[rd]:
                hosts_v4.append((host_id, h))
                host_id += 1

            continue

        # Shared primary ip
        if len(routingdomains[rd]) > 1:
            hosts_v4.append((1, '-'.join(routingdomains[rd])))

            host_id = -2
            for h in routingdomains[rd]:
                hosts_v4.append((host_id, h))
                host_id -= 1

        # Single router nets:
        if len(routingdomains[rd]) == 1:
            hosts_v4.append((1, routingdomains[rd][0]))

    if ipv6:
        host_id = 1
        for h in routingdomains[rd]:
            hosts_v6.append((host_id, h))
            host_id += 1

    # output
    for ipid, hostname in hosts_v4:
        # print ipid, hostname
        if ipv4:
            print hostname, 'IN A', ipv4[ipid]
    for ipid, hostname in hosts_v6:
        # print ipid, hostname
        print hostname, 'IN AAAA', ipv6[ipid]

print ""
print "Bitte vergleichen und gegebenenfalls nachtragen, aktuallisieren oder löschen."
print ""
print "Grüße von fünf Türen weiter,"
print "netadm"

print
print '.'
