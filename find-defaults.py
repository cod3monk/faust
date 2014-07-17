#!/usr/bin/env python

import ConfigParser
import sys
import os

import lib
from lib import metacl, helpers, macros, dialects
import logging

try:
    lib.config.load()
    routers_cfg = ConfigParser.SafeConfigParser()
    routers_file = lib.config.get('global', 'routers_file')
    routers_cfg.read(routers_file)
except lib.config.ConfigError, err:
    print >> sys.stderr, "Problem with the configuration: %s" % err
    sys.exit(2)
log = logging.getLogger('faust')

# so every module can see lib
sys.path.append(os.path.abspath(__file__))

rnet = list(enumerate(open('/home/rrze/netd/netdns/RNET').readlines()))


def get_routingdomains():
    '''Returns list of routingdomains.'''
    return map(lambda x: x[0].upper(), routers_cfg.items('routingdomains'))


def get_contact(ip):
    try:
        from_ = filter(lambda l: l[1].startswith(
            '$NETNAME') and l[1][8:].strip().startswith(ip), rnet)[0][0]
        to = filter(lambda l: l[1].startswith('$NETNAME'), rnet[from_ + 1:])[0][0]

        return map(lambda x: x[1], rnet[from_:to])
    except:
        return ['No contact found.', '']


if __name__ == '__main__':
    routingdomains = get_routingdomains()

    for rd in routingdomains:
        try:
            l = os.listdir(lib.config.get('global', 'policies_dir') + '/' + rd)
        except OSError as e:
            log.warn("Could not read policy directory for routing domain '%s': %s" %
                     (rd, e))
        ext = lib.config.get('global', 'policies_ext')
        vlans = map(lambda x: x[:-len(ext)], filter(lambda x: x.endswith(ext), l))

        for vlan in vlans:
            ctxt = lib.metacl.Context(rd, vlan)
            if ctxt.get_acl().is_default(macros=False, extensions=False):

                if 'local' in ctxt.ipv4_aliases and ctxt.ipv4_aliases['local'] is not None and len(ctxt.ipv4_aliases['local']) >= 1:
                    local = str(ctxt.ipv4_aliases['local'][0])
                elif 'local' in ctxt.ipv6_aliases and ctxt.ipv6_aliases['local'] is not None and len(ctxt.ipv6_aliases['local']) >= 1:
                    local = str(ctxt.ipv6_aliases['local'][0])
                else:
                    local = "No associated network range found."

                print rd, vlan, str(local)
                print ''.join(get_contact(str(local)))
