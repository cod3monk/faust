#!/usr/bin/env python
# Used by meta to generate ACLs for startup-config

import sys
import os

from lib import metacl
import lib

# Change to the directory of this script
os.chdir(os.path.split(__file__)[0])

lib.config.load()

assert len(sys.argv) == 3, 'Usage: %s <routing_domain> <base_config_file>' % sys.argv[0]

routingdomain = sys.argv[1]
base_config = sys.argv[2]

try:
    l = os.listdir(lib.config.get('global', 'policies_dir')+'/'+routingdomain)
except OSError:
    print 'No ACLs found for routing domain %s (directory does not exist)' % \
        routingdomain
ext = lib.config.get('global', 'policies_ext')
vlans = map(lambda x: x[:-len(ext)], filter(lambda x: x.endswith(ext), l))
    
assert len(vlans) > 0, 'No ACLs found for routing domain %s' % routingdomain

ipv6_vlans = {}

acls = ''

acls += '''
!!----------------------------------------------------------------------------
!!     START OF FAUST2 ACL CONFIGURATION
!!----------------------------------------------------------------------------
'''

for vlanid in vlans:
    acls += '!!-------%s%s------\n' % (routingdomain, vlanid)
    context = metacl.Context(routingdomain,vlanid)
    macl = context.get_acl()
    cfile, acl, ipv6 = macl.compile(timestamp=False)
    ipv6_vlans[vlanid] = ipv6
    acls += acl+'\n'

acls += '''
!!----------------------------------------------------------------------------
!!     END OF FAUST2 ACL CONFIGURATION
!!----------------------------------------------------------------------------

!!----------------------------------------------------------------------------
!!     START OF FAUST2 ACL-to-INTERFACE CONFIGURATION
!!----------------------------------------------------------------------------
'''

for vlanid in vlans:
    acls += 'interface vlan %s\n' % vlanid
    acls += 'ip access-group %s%s_IN in\n' % (routingdomain, vlanid)
    acls += 'ip access-group %s%s_OUT out\n' % (routingdomain, vlanid)
    if ipv6_vlans[vlanid]:
        acls += 'ipv6 traffic-filter %s%s_IN6 in\n' % (routingdomain, vlanid)
        acls += 'ipv6 traffic-filter %s%s_OUT6 out\n' % (routingdomain, vlanid)

acls += '''
!!----------------------------------------------------------------------------
!!     END OF FAUST2 ACL-to-INTERFACE CONFIGURATION
!!----------------------------------------------------------------------------
'''

# Find end of base config
f = open(base_config, 'r')
orig_config = f.readlines()
orig_config = map(lambda x: x.strip(), orig_config)
f.close()
# Searching for 'end' in the last 5 lines
for i in range(len(orig_config)-1,len(orig_config)-6, -1):
    if 'end' == orig_config[i].strip():
        f = open(base_config, 'w')
        orig_config.insert(i, acls)
        f.write('\n'.join(orig_config))
        f.close()
        sys.exit(0)

assert True, "Did not find 'end' in last 5 lines of %s" % base_config
