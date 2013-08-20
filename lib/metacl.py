#!/usr/bin/env python
from pprint import pformat
import re
import logging
log = logging.getLogger('lib.metacl')
import os
import itertools
import difflib

import ipaddr_ng
from ipaddr_ng import IPv4Descriptor, IPv6Descriptor, IPDescriptor
from third_party.ipaddr import IPv4Network, IPv6Network, AddressValueError, NetmaskValueError
from helpers import Trackable
import macros

import ConfigParser
from __init__ import config

# IP Version names
ip_versions = ['ipv4', 'ipv6']

# Protocol names
protocol_names = ['tcp','udp','ip','icmp','esp','ahp','pim','igmp','ospf']
# Protocol names that support ports (they must still apprear above)
port_protocols = ['tcp','udp']

# Extension names
extension_names = ['established', 'log', 'echo', 'echo-reply', 'ttl-exceeded']

# Directions
directions = ['in', 'out']

class Error(Exception):
    """Base class for exceptions in this module."""

class IPVersionMissmatchError(Error, Trackable):
    '''Rule needs source and destination filters of same IP version.'''

class MacroDoesNotExist(Error, Trackable):
    '''The requested macro does not exist.'''

class VLANDoesNotExist(Error):
    '''The VLAN couldn't be found in VLANs file.'''

class VLANDescriptionError(Error):
    '''Description in VLANs file is faulty.'''

class NeedsContext(Error, Trackable):
    '''No context was provided, but aliases are used. Can not proceed.'''

class InvalidACL(Error, Trackable):
    '''ACL file/string is invalid.'''

class UnknownRoutingdomain(Error):
    '''Requested routingdomain is unknown.'''

class UnknownRouter(Error):
    '''Requested router is unknown.'''

class ProtocolDoesNotSupportPorts(Error, Trackable):
    '''One of the protocols does not support ports, but ports were given.'''

class Ports:
    '''Ports and Port range handeling in one object'''
    def __init__(self):
        self.ranges = []
        self.ports = []
    
    def add_port(self, port):
        # Only add port if not yet existant
        if port not in self:
            self.ports.append(port)
    
    def add_range(self, start, end):
        # Finding overlaping and neighboring ranges
        for r in self.ranges:
            if r[0] <= end and r[1] >= start:
                # deleting range and (possibly) increasing size of new range
                start = min(r[0], start)
                end = max(r[1], end)
                self.ranges.remove(r)
        
        # Finding included ports
        self.ports = filter(lambda n: start > n or n > end, self.ports)
        
        # Adding range
        self.ranges.append((start, end))
    
    def to_tuples(self):
        data = map(lambda x: ('eq', x), self.ports)
        data += map(lambda x: ('range', (x[0], x[1])), self.ranges)
        
        return data
        
    def __contains__(self, port):
        # Find in single ports:
        if port in self.ports:
            return True
        
        # Find in port ranges:
        for r in self.ranges:
            if port <= r[1] and port >= r[0]:
                return True
        
        # Not found
        return False
    
    @classmethod
    def from_string(cls, s):
        '''Parses port description *s* and returns approriate list.
        *s* must have the following syntax: 23-80,443'''
        ports = Ports()

        # First we build a set with all matching port numbers:
        s = s.split(',')

        for ports_str in s:
            if '-' in ports_str:
                range_str = ports_str.split('-')
                ports.add_range(int(range_str[0]), int(range_str[1]))
            else:
                ports.add_port(int(ports_str))

        return ports
    
    def to_string(self):
        '''Returns string which can be parsed by from_string() method.'''
        s = ''
        for p in self.ports:
            if len(s) > 0:
                s += ','
            s += '%s' % p
        
        for r in self.ranges:
            if len(s) > 0:
                s += ','
            s += '%s-%s' % r
        
        return s
    
    def __iter__(self):
        for p in self.ports:
            yield p
        for r in self.ranges:
            for p in range(r[0], r[1]+1):
                yield p
                
    def __bool__(self):
        return bool(self.ports) or bool(self.ranges)
    __nonzero__=__bool__

def string_to_ips(string, context=None, temp_aliases=None):
    '''Parses ip description *string* and returns approriate list of
    IPv4Network and IPv6Network objects.
    Resolves aliases using temp_aliases and context object.

    If alias is found, and context is None, a NeedsContext exception will be thrown.'''

    ips = []
    if string[0] == '$' or string.startswith("any") or string.startswith("local"):
        # Check for context
        if not context and not temp_aliases:
            raise NeedsContext('Can not resolve host/net aliases without context or temp_aliases.')

        name = string.replace("$", "")

        # Alias from temp_alias (if existent)
        if temp_aliases and name in temp_aliases:
            # IPv4 selector?
            if name.endswith("[4]"):
                return filter(lambda ip: type(ip) is IPv4Network, temp_aliases[name[:-3]])
            # IPv6 selctor?
            elif name.endswith("[6]"):
                return filter(lambda ip: type(ip) is IPv6Network, temp_aliases[name[:-3]])
            else:
                return temp_aliases[name]

        # Alias from context (IPv4 or IPv6)
        if name.endswith("[4]"):
            return context.get_alias(name[:-3], ip_versions='ipv4')
        elif name.endswith("[6]"):
            return context.get_alias(name[:-3], ip_versions='ipv6')
        else:
            return context.get_alias(name)
    else:
        return IPDescriptor(string)

class ACL(Trackable):
    '''Represents a parsed Policy File, containing Rules for IN, OUT and
       MacroCalls

       Trackable enables this object to be traced back to an originating file
       '''
    # flag indicating if macros have already been applied, because things
    # will break if that is done multiple times
    macros_applied = False

    def __init__(self, acl_in=[], acl_out=[], macros=[], context=None,
        filename=None, parent=None):
        self.macros = macros
        self.acl_in = acl_in
        self.acl_out = acl_out
        self.context = context
        Trackable.__init__(self, filename, None, parent)

    @classmethod
    def from_string(cls, policies, context=None, filename=None, parent=None):
        '''Constructs ACL object from string *policies*.'''
        # Fill *lines* with tupels, containing line number (starting from 1)
        # and line content
        # lines = [(number, content), ...]
        lines = zip(itertools.count(1), policies.split('\n'))

        # Removing lines which are blank or contain only comments
        # Line numbers are preserved
        lines = filter(lambda x: not len(x[1].strip()) == 0
            and not x[1].strip().startswith('#'), lines)
        # Strip all leading and ending whitespaces from lines
        lines = map(lambda x: (x[0], x[1].strip()), lines)

        if len(lines) == 0:
            err = InvalidACL('ACL can not be empty!')
            Trackable.__init__(err, filename=filename, parent=parent)
            raise err

        # Split lines into macro-, in- and out-block
        macros = []
        acl_in = []
        acl_out = []
        try:
            # Find beginning of in-block by locating "IN:" line
            index_in = next((i for i in xrange(len(lines) - 1, -1, -1) \
                if lines[i][1] == 'IN:'), None)
            # Find beginning of out-block by locating "OUT:" line
            index_out = next((i for i in xrange(len(lines) - 1, -1, -1) \
                if lines[i][1] == 'OUT:'), None)

            # Macros are infront of in-block
            macros = lines[:index_in]

            acl_in = lines[index_in+1:index_out]
            acl_out = lines[index_out+1:]

        # Index search returned unsuccessful
        except:
            err = InvalidACL('IN and OUT sections could not be found in ACL.')
            Trackable.__init__(err, filename=filename, parent=parent)
            raise err

        # Create Rule objects from *lines*
        # Macros via MarcoCall.from_string()
        macros = map(lambda x: MacroCall.from_string(x[1], lineno=x[0],
            filename=filename), macros)
        # In/Out rules via Rule.from_string()
        acl_in = map(lambda x: Rule.from_string(x[1], context,
            lineno=x[0], filename=filename), acl_in)
        acl_out = map(lambda x: Rule.from_string(x[1], context,
            lineno=x[0], filename=filename), acl_out)

        # Return class object
        return cls(acl_in, acl_out, macros, context, filename, parent)

    @classmethod
    def from_file(cls, path, context=None):
        '''Construct ACL object from file at location *path*.'''
        # Open file and redirect to from_string() method
        return cls.from_string(open(path).read(), context, filename=path)

    @classmethod
    def from_context(cls, context):
        '''Constructs ACL object by getting the path of the policy file
        from *context*.'''
        # Generate path and redirect to from_file() method
        return cls.from_file(context.get_policy_path(), context)

    def apply_macros(self):
        '''Applies MacroCalls in topological order to this ACL object'''

        if not self.context:
            raise NeedsContext('Macros can only applied in a context!')

        if self.macros_applied:
            raise Error('Macros can only be applied once!')
        else:
            self.macros_applied = True

        # Not yet sorted
        macros_sorted = self.macros

        # Remove dependencies which do not apply, e.g. dhcp depends on
        # broadcast, but broadcast is not used
        for m in macros_sorted:
            m.macro.dependencies = filter(lambda x: x in map(lambda x: \
                type(x.macro), macros_sorted), m.macro.dependencies)

        # Execute in topological order
        while len(macros_sorted) > 0:
            # Sort macros by number of dependencies, in increasing order
            macros_sorted = sorted(macros_sorted,
                key=lambda x: len(x.macro.dependencies), reverse=True)

            # Get one macro
            m = macros_sorted.pop()

            # Have all dependencies been resolved?
            if len(m.macro.dependencies) == 0:
                # AppACLly macro
                m.call(self)

                # Remove fullfilled dependency
                for n in macros_sorted:
                    try:
                        n.macro.dependencies.remove(m.macroclass)
                    except ValueError:
                        pass
            else:
                raise macros.UnresolvableDependencies(
                    "Couldn't resolve dependencies for macro: "
                    +m.name+' from '+m.origin())

    def compile(self, timestamp=True, save_to_file=True):
        '''Compiles this ACL with given *context*.

        Macros will be applied, if not done before. See :func:`apply_macros`

        If *timestamp* is True, compiled ACL will contain remarks with date
        and time of compilation.
        If *save_to_file* is True, compiled ACL will be saved to compiled_dir,
        as configured.'''

        if not self.context:
            raise NeedsContext('Can only be compiled with a context!')

        if not self.macros_applied:
            self.apply_macros()

        context = self.context
        acl = context.dialect_module.compile_all(self, context.routingdomain+\
            context.vlanid, timestamp)

        cfile = None
        if save_to_file:
            # Saving compiled ACLs to cfile in cdir
            cdir = config.get('global','compiled_dir')+'/'+ \
                context.routingdomain
            cfile = cdir+'/'+context.vlanid+'.acl'

            try:
                try:
                    umask = int(config.get('global','umask'))
                except:
                    umask = None
                try:
                    gid = int(config.get('global','groupid'))
                except:
                    gid = None

                # Routingdomain directory might not exist
                if not os.path.isdir(cdir):
                    # So create it
                    os.mkdir(cdir)
                    # Correcting rights and group ownership, if configured
                    if umask:
                        import stat
                        # We make shure that also executable flags are set
                        os.chmod(cdir, umask+stat.S_IXUSR+stat.S_IXGRP+stat.S_IXOTH)
                    if gid:
                        os.chown(cdir, -1, gid)


                # If file allready exists
                if os.path.isfile(cfile):
                    # Delete it
                    os.remove(cfile)

                # Creating new file
                f = open(cfile,'w')

                # Correcting rights and group ownership, if configured
                if umask:
                    os.chmod(cfile, umask)
                if gid:
                    os.chown(cfile, -1, gid)

                f.writelines(acl)
                f.close()

                log.debug('Compiled %s to %s' % (context.vlanid, cfile))
            except Exception, err:
                log.error("Problem saving acl file: %s" % err)
        else:
            log.debug('Compiled %s (not saved to file)' % self.context.vlanid)

        return cfile, acl, 'ipv6' in self.context.ip_versions

    def install(self, timestamp=True, save_to_file=True):
        '''Installs ACL to routers as defined in context.

        Calls :func:`compile`, see there for arguments.'''

        if not self.context:
            raise NeedsContext('Can only be installed with a context!')

        if save_to_file:
            self.compile(timestamp=timestamp, save_to_file=True)

        self.context.dialect_module.install(self, timestamp=timestamp)

        return True

    def check(self, direction='in', protocol='ipv4', output=None):
        '''Compares *other* with this ACLs *protocol* rules in *direction*.

        Macros will be applied, if not done before. See :func:`apply_macros`
        '''

        if not self.context:
            raise NeedsContext('Can only be compiled with a context!')

        if not self.macros_applied:
            self.apply_macros()

        # Compiling rules
        context = self.context
        dialect = context.dialect_module
        acl = dialect.compile_one(
            self,
            context.routingdomain+context.vlanid,
            direction,
            protocol,
            comments=False)
        local_acl = acl[1]

        vlanid = self.context.vlanid
        routingdomain = self.context.routingdomain

        ifaces = self.context.interfaces

        services = dialect.get_service_dictionary()

        same = True
        same_router = {}

        # For each router:
        for router in self.context.get_router_connections():
            # Get needed ACLs which are bound to interface
            acl_names = router.get_bound_acl_form_interface(ifaces[router.name])
            if not acl_names[protocol][direction]:
                same = False
                same_router[router.name] = False
                print >> output, "No ACLs are bound on interface "+ifaces[router.name]+\
                    " ("+protocol+" "+direction+") on "+router.name
                continue

            acl_on_router = router.read_acl(acl_names[protocol][direction], protocol)
            acl_on_router = acl_on_router.split('\n')

            if not acl_on_router == local_acl: # and ouput
                same = False
                same_router[router.name] = False

                print >> output, "Diff of VLAN",vlanid," ("+protocol,direction+") on",router.name+':'

                for l in difflib.unified_diff(acl_on_router, local_acl, fromfile='local ('+protocol+' '+direction+')', tofile=router.name+' ('+protocol+' '+direction+')', lineterm=""):
                    print >> output, '    '+l

            # Compare them:
            same_router[router.name] = True
            if len(local_acl) != len(acl_on_router):
                same = False
                same_router[router.name] = False
                continue

            for i in range(len(acl_on_router)):
                if local_acl[i] != acl_on_router[i]:
                    # still not same same
                    same = False
                    same_router[router.name] = False

        return same, same_router

    def get_rules(self, directions=directions, ip_versions=ip_versions):
        '''Returns all rules matching *directions* and *ip_versions*.

        Arguments can be a list subset of global *directions* or *ip_verions*
        or a single value from the lists.

        By default returns all rules.'''

        # Convert argument to list, if neccessary
        if type(directions) is not list:
            directions = [directions]
        if type(ip_versions) is not list:
            ip_versions = [ip_versions]

        rules = []
        if 'in' in directions:
            rules += self.acl_in
        if 'out' in directions:
            rules += self.acl_out

        # Remove rules, that do not fit ip_versions pattern
        rules = filter(lambda r: [x for x in r.ip_versions if x in ip_versions], rules)

        return rules

    def sanity_check(self):
        '''check if acl is valid.
            the returned list contains a string depending on the conflict that matched
            a string with in or out
            and the rule(s) that caused the conflict
            different protocols are ignored'''
            #TODO Improve protocol checks

        if not self.macros_applied:
            self.apply_macros()

        #filter macros
        ignore_macros = config.get('global','ignore_macros').split()
        ignore_macros = map(lambda x:eval("macros.%s"%x),ignore_macros);

        ret = []
        #check both directions d will be 'in' or 'out'
        for d in directions:
            acl = self.get_rules(d)
            #remove permit any/local local/any and deny any any
            acl = filter(lambda x:not (x.action == 'deny'
            and self.equals_any(x.filter.sources)
            and self.equals_any(x.filter.destinations)),acl)
            if(d == 'in'):
                acl = filter(lambda x:not (x.action == 'permit'
                and self.equals_local(x.filter.sources)
                and self.equals_any(x.filter.destinations)),acl)
            else:
                acl = filter(lambda x:not (x.action == 'permit'
                and self.equals_any(x.filter.sources)
                and self.equals_local(x.filter.destinations)),acl)

            #remove rule from macros specified in config.ini
            for i in ignore_macros:
                acl = filter(lambda x:type(x.parent) != i,acl)

            #save acl to reset it later
            orig = acl
            #check if IN.sources and OUT.destinations are in local
            #description string: "Rule not in local"
            for i in range(len(acl)):
                #filter reduces list to the rules that are not in local and unequal any
                #map connects the elemnts to the string
                if d == 'in':
                    ret += map(lambda x:('Rule not in local',d,x),
                        filter(lambda x:not self.in_local(x.filter.sources)
                        and not self.equals_any(x.filter.sources)
                        #TODO build config to ignore ips in this check
                        and not x.filter.sources[0] == IPv4Network('224.0.0.0/4')
                        and not x.filter.sources[0] == IPv4Network('255.255.255.255/32')
                        and not x.filter.sources[0] == IPv6Network('fe80::/10')
                        ,acl[i+1:]))
                else:
                    ret += map(lambda x:('Rule not in local',d,x),
                    filter(lambda x:not self.in_local(x.filter.destinations)
                    and not self.equals_any(x.filter.destinations)
                    and not x.filter.destinations[0] == IPv4Network('224.0.0.0/4')
                    and not x.filter.destinations[0] == IPv4Network('255.255.255.255/32')
                    and not x.filter.destinations[0] == IPv6Network('fe80::/10')
                    ,acl[i+1:]))

            #check if a rule is never reached cause it is fully contained in an ealier rule
            #reset acl
            acl = orig
            for i in range(len(acl)):
                #filter reduces list to the rules never reached
                #map connects the rules to the ones they are contained in
                #description string: "Rule never reached"
                ret += map(lambda r2:('Rule never reached',d,r2,acl[i]),
                    filter(lambda x:x.filter in acl[i].filter
                    and x.filter.protocols == acl[i].filter.protocols
                    and (((x.filter.sports or acl[i].filter.sports) == [])
                    or filter(x.filter.sports.__contains__, acl[i].filter.sports))
                    and (((x.filter.dports or acl[i].filter.dports) == [])
                    or filter(x.filter.dports.__contains__, acl[i].filter.dports))
                    ,acl[i+1:]))

            #reset acl
            acl = orig
            #check if rules do overlapse, any and local are ignored
            #filter removes any and local
            acl = filter(lambda x:not self.equals_any(x.filter.sources) and
                not self.equals_any(x.filter.destinations) and
                not self.equals_local(x.filter.sources) and
                not self.equals_local(x.filter.destinations),acl)

            for i in range(len(acl)):
                #filter reduces list to the rules that overlaps
                #map connects the rules to the ones they overlaps with
                #description string: "Rule overlapses
                ret += map(lambda r2:('Rules overlaps',d,acl[i],r2),
                    filter(lambda x:acl[i].filter.overlaps(x.filter)
                    and x.filter.protocols == acl[i].filter.protocols
                    and (((x.filter.sports or acl[i].filter.sports) == [])
                    or filter(x.filter.sports.__contains__, acl[i].filter.sports))
                    and (((x.filter.dports or acl[i].filter.dports) == [])
                    or filter(x.filter.dports.__contains__, acl[i].filter.dports))
                    ,acl[i+1:]))

            #reset acl
            acl = orig
            #check if rule is fully contained in a later rule with same action
            #(permit, deny)
            for i in range(len(acl)):
                #filter reduces list to the rules that are contained in sth.
                #map connects the rules to the ones they are contained in
                #description string: "Rule contained in other"
                ret += map(lambda r2:('Rule contained in later rule',d,acl[i],r2),
                    filter(lambda x:acl[i].filter in x.filter and
                    acl[i].action == x.action
                    and x.filter.protocols == acl[i].filter.protocols
                    and (((x.filter.sports or acl[i].filter.sports) == [])
                    or filter(x.filter.sports.__contains__, acl[i].filter.sports))
                    and (((x.filter.dports or acl[i].filter.dports) == [])
                    or filter(x.filter.dports.__contains__, acl[i].filter.dports))
                    ,acl[i+1:]))

        return ret

    def equals_any(self, networks):
        '''returns true if *networks* is 'any' '''
        return networks[0] == IPv4Network('0.0.0.0/0') or networks[0] == IPv6Network('::1/0')

    def equals_local(self, networks):
        '''returns true if *network* is 'local' '''
        return networks == self.context.get_alias('local')

    def is_pal(self, rule):
        '''returns true if *rule* is Rule: permit ip any local'''
        if rule.action == 'permit' and self.equals_any(rule.filter.sources) and self.equals_local(rule.filter.destinations):
            return True;

    def is_daa(self, rule):
        '''returns true if *rule* is Rule: deny ip any any'''
        if rule.action == 'deny' and self.equals_any(rule.filter.sources) and self.equals_any(rule.filter.destinations):
            return True;

    def in_local(self, network):
        '''returns true if *network* is completely contained in local'''
        for n in network:
            # False if any *n* is not contained in local
            if not any(map(lambda x: n in x, self.context.get_alias('local'))):
                return False
        return True

    def __str__(self):
        return 'ACL:' \
             + '\n MACROS:\n' + pformat(self.macros, 3) +\
               '\n ACL IN:\n' + pformat(self.acl_in, 3) +\
               '\n ACL OUT:\n' + pformat(self.acl_out, 3)

class Context(object):
    '''Represents a context, within which a ACL can be checked and compiled.

    It knows aliases and other information, necessary to understand a ACL and
    to compile a real ACL out of it's meta object.'''

    def __init__(self, routingdomain=None, vlanid=None):
        self.routingdomain = routingdomain
        self.vlanid = vlanid
        self.interfaces = {}

        # Find and read host alias configuration
        hosts_config = ConfigParser.SafeConfigParser()
        hosts_config.read(config.get("global","aliases_file"))

        # Build dictionary of aliases found in config
        self.ipv4_aliases = dict(map(
            lambda x: (x[0], IPv4Descriptor(x[1].strip().replace(" ",""))),
                hosts_config.items('ipv4')))
        self.ipv6_aliases = dict(map(
            lambda x: (x[0], IPv6Descriptor(x[1].strip().replace(" ",""))),
                hosts_config.items('ipv6')))

        # Including external alias descriptions
        for k,v in hosts_config.items('include'):
            if not v:
                continue
            for l in open(v).readlines():
                if not l.startswith('#') and \
                   not l.startswith(';') and len(l)>0:
                    self.set_alias(k, l.strip())

        # Static and globally present aliases:
        self.ipv4_aliases['any'] = [IPv4Network('0.0.0.0/0')]
        self.ipv6_aliases['any'] = [IPv6Network('::1/0')]

        self.ip_versions = []

        self.get_vlan_info()
        self.get_router_info()

        # Default interface name if nothing was specified in TNETs: 'Vlan'+vlanid
        for r in self.routers:
            if r['name'] not in self.interfaces:
                self.interfaces[r['name']] = 'Vlan'+vlanid

        router_connections = None

        macro_configs = {} # used by macros to exchange informations

    def get_alias(self, host, ip_versions=ip_versions):
        '''Resolves *host* by checking ipv4 or ipv6 alias lists.
        Wether ipv4 or ipv6 aliases are returned dependes on *ip_versions*, this
        can be either a list or a string of 'ipv4', 'ipv6'.

        Returns list of :class:`faust2.lib.third_party.ipaddr.IPv4Network` and
        :class:`faust2.lib.third_party.ipaddr.IPv6Network` objects.

        Throws KeyError exception if none could be found.'''

        # Convert ip_versions to list
        if type(ip_versions) is not list:
            ip_versions = [ip_versions]

        l = []
        if 'ipv4' in ip_versions and self.ipv4_aliases.has_key(host):
            l += self.ipv4_aliases[host]
        if 'ipv6' in ip_versions and self.ipv6_aliases.has_key(host):
            l += self.ipv6_aliases[host]

        return l

    def set_alias(self, name, ip_string):
        '''Sets alias *name* to *ip_string*.

        If alias *name* already existed, it will be combined.
        If *ip_string* can only be IPv6 or IPv4 and will be applied
        apropriatly.'''

        ips = []
        if ':' in ip_string:
            # IPv6
            ips = IPv6Descriptor(ip_string)

            if self.ipv6_aliases.has_key(name):
                self.ipv6_aliases[name] += ips
            else:
                self.ipv6_aliases[name] = ips
        else:
            # IPv4
            ips = IPv4Descriptor(ip_string)

            if self.ipv4_aliases.has_key(name):
                self.ipv4_aliases[name] += ips
            else:
                self.ipv4_aliases[name] = ips

    def get_vlan_info(self):
        '''Reads aliases from vlans_file and transit_file (paths from config).

        Automaticly called in constructor.

        Throws VLANDoesNotExist exeption if vlan could not be found in file.'''

        self.ipv4_aliases['local'] = []
        self.ipv6_aliases['local'] = []

        f = open(config.get("global", "vlans_file"))
        for l in f.readlines():
            # turn line into array
            # RRZE		3	rlan3		131.188.2.0/23		2001:638:A00:2::/64	RRZE-UNIX
            # to
            # ['RRZE','3','rlan3',131.188.2.0/23','2001:638:A00:2::/64','RZE-UNIX']
            l = filter(lambda x: not x=='' and not x.startswith(';'), l.strip().split('\t'))

            # Sufficient columns
            if not len(l) >= 4:
                continue

            # Does this match our routingdomain and vlanid?
            if l[0] == self.routingdomain and l[1] == self.vlanid:
                # If column starts with -, ignore
                if not l[3].startswith('-'):
                    self.ip_versions.append('ipv4')
                    try:
                        self.ipv4_aliases['local'] += [IPv4Network(l[3])]
                    except AddressValueError:
                        raise VLANDescriptionError(('Bad IPv4 range '+ \
                            'description of VLAN %s %s in %s, must be in '+\
                            '/ notation') % (self.routingdomain, self.vlanid,\
                            config.get("global", "vlans_file")))

                if not l[4].startswith('-'):
                    self.ip_versions.append('ipv6')
                    try:
                        self.ipv6_aliases['local'] += [IPv6Network(l[4])]
                    except AddressValueError:
                        raise VLANDescriptionError(('Bad IPv6 range '+ \
                            'description of VLAN %s %s in %s, must be in '+\
                            '/ notation') % (self.routingdomain, self.vlanid,\
                            config.get("global", "vlans_file")))

        f = open(config.get("global", "transit_file"))
        for l in f.readlines():
            # turn line into array
            # RRZE		3	rlan3		131.188.2.0/23		2001:638:A00:2::/64	RRZE-UNIX
            # to
            # ['RRZE','3','rlan3',131.188.2.0/23','2001:638:A00:2::/64','RZE-UNIX']
            l = filter(lambda x: not x=='' and not x.startswith(';'), l.strip().split('\t'))

            # Sufficient columns
            if not len(l) >= 4:
                continue

            # Does this match our routingdomain and vlanid?
            if l[0] == self.routingdomain and l[1] == self.vlanid:
                # Special case: if vlanid is not a number, we will take the third element
                # as the interface name
                # e.g.:
                # RRZE		somenet	Gi1/23		131.188.2.0/23		2001:638:A00:2::/64	RRZE-UNIX
                try:
                    int(self.vlanid)
                except:
                    try:
                        import ast

                        ifaces = ast.literal_eval(l[2])
                        if type(ifaces) == dict:
                            self.interfaces = ifaces
                    except:
                        raise VLANDescriptionError(('Bad interface name in '+ \
                            'description of VLAN %s %s in %s, must be in '+\
                            ' python dictionary string notation') % (self.routingdomain,
                            self.vlanid, config.get("global", "transit_file")))

                # If column starts with -, ignore
                if not l[3].startswith('-'):
                    self.ip_versions.append('ipv4')
                    try:
                        self.ipv4_aliases['local'] += [IPv4Network(l[3])]
                    except AddressValueError:
                        raise VLANDescriptionError(('Bad IPv4 range '+ \
                            'description of VLAN %s %s in %s, must be in '+\
                            '/ notation') % (self.routingdomain, self.vlanid,\
                            config.get("global", "transit_file")))

                # If column starts with -, ignore
                if not l[4].startswith('-'):
                    self.ip_versions.append('ipv6')
                    try:
                        self.ipv6_aliases['local'] += [IPv6Network(l[4])]
                    except AddressValueError:
                        raise VLANDescriptionError(('Bad IPv6 range '+ \
                            'description of VLAN %s %s in %s, must be in '+\
                            '/ notation') % (self.routingdomain, self.vlanid,\
                            config.get("global", "transit_file")))

        if not self.ip_versions:
            raise VLANDoesNotExist('The VLAN ('+self.routingdomain+'/'+ \
                self.vlanid+') couldn\'t be found in VLANs nor in'+ \
                ' TNETs file.')

        if not self.ip_versions:
            log.info('VLAN ('+self.routingdomain+'/'+self.vlanid+') '+ \
                'has no IPv4 and no IPv6 network address.')

    def get_router_info(self):
        '''Reads information about the routers for this context and stores
        them in *self* object.'''

        c = ConfigParser.SafeConfigParser()
        routers_file = config.get('global', 'routers_file')
        assert len(c.read(routers_file)) > 0, 'File could not be read: '+routers_file

        # Get list of routernames from routingdomains section
        try:
            routernames = c.get('routingdomains', self.routingdomain).split(',')
        except ConfigParser.NoOptionError:
            raise UnknownRoutingdomain('Routingdomain ('+self.routingdomain+ \
                ') not found in routers_file ('+routers_file+').')

        self.routers = []
        self.dialect = None
        # Get router section for each routername:
        for r in map(lambda x: x.strip(), routernames):
            try:
                self.routers.append(dict(c.items('router_'+r)))
                if 'host' not in self.routers[-1]:
                    raise UnknownRouter('Router section router_'+r+ \
                        ' has no host option.')
                if 'dialect' not in self.routers[-1]:
                    raise UnknownRouter('Router section router_'+r+ \
                        ' has not dialect option.')
                if self.dialect == None:
                    self.dialect = self.routers[-1]['dialect']
                elif self.routers[-1]['dialect'] != self.dialect:
                    raise UnknownRouter('Router section router_'+r+ \
                        'has different dialect then other routers in '+ \
                        'routingdomain')
                self.routers[-1]['name'] = r
            except ConfigParser.NoSectionError:
                raise UnknownRouter('Router section (router_'+r+ \
                    ') not found in routers_file ('+routers_file+').')

        self.dialect_module = __import__('lib.dialects.'+self.dialect, fromlist='lib.dialects')

        self.user = c.get('access', 'user')
        self.pw = c.get('access', 'pw')

    def get_router_connections(self, read_running_config_first=False):
        '''Returns Router object, needed for communication with router.'''
        ret = []
        for router in self.routers:
            ret.append(self.dialect_module.Router(router['host'], self.user,
                self.pw, read_running_config_first=read_running_config_first, name=router['name']))

        return ret

    def get_policy_path(self):
        '''Returns path to policy file.'''
        return config.get("global", "policies_dir")+'/'+self.routingdomain \
            +'/'+self.vlanid+config.get("global", "policies_ext")

    def get_policy_dir(self):
        '''Returns path to directory of policy files for same routingdomain.'''
        return config.get("global", "policies_dir")+'/'+self.routingdomain+'/'

    def get_acl(self):
        '''Returns :class:`ACL` object for this context'''
        return ACL.from_context(self)

class MacroCall(Trackable):
    '''Reference to a macro with possible arguments.'''
    def __init__(self, name, arguments="", filename=None, lineno=None, parent=None):
        self.name = name
        self.arguments = arguments
        Trackable.__init__(self, filename, lineno, parent)
        try:
            self.macroclass = getattr(macros, self.name)
            self.macro = self.macroclass(self.arguments)
            self.macro.originate_from(self)
            self.macro._comment = name+'('+str(arguments)+')'
        except AttributeError:
            err = MacroDoesNotExist('Macro name is not valid')
            Trackable.__init__(err, filename=filename, lineno=lineno,
                parent=parent)
            raise err

    @classmethod
    def from_string(cls, string, filename=None, lineno=None, parent=None):
        '''Takes *string* and parses it to a MacroCall object.'''

        # Removing comments and unnecessary white spaces
        string = string.split('#')[0].strip()

        # Retriving and checking macro name
        name = string.split('(')[0]
        if re.match(r'^\w+$', name) == None:
            err = MacroDoesNotExist('Macro name is not valid')
            Trackable.__init__(err, filename=filename, lineno=lineno,
                parent=parent)
            raise err

        # Retriving arguments
        arguments = string.split(')')[0].split('(')[1]

        return cls(name, arguments, filename, lineno, parent)

    def call(self, acl):
        '''Applies macro with arguments to *acl* ACL object.'''
        return self.macro.call(acl)

class Rule(Trackable):
    '''Abstraction of one rule from the policy file.'''

    def __init__(self, action, filter, extensions=[], filename=None, lineno=None, parent=None):
        if action not in ['permit', 'deny']:
            err = InvalidACL('Action is not valid')
            Trackable.__init__(err, filename=filename, lineno=lineno,
                parent=parent)
            raise err

        self.action = action
        assert type(filter) is Filter, "argument 'filter' must be of type Filter"
        self.filter = filter
        assert type(extensions) is list and all(map(lambda x: type(x) is str, extensions)), \
            "argument 'extensions' must be a list of strings"
        self.extensions = extensions

        self.ip_versions = self.filter.ip_versions

        Trackable.__init__(self, filename, lineno, parent)
        # Passing along origine
        self.filter.originate_from(self)

    @classmethod
    def from_string(cls, string, context=None, temp_aliases=None, filename=None, lineno=None,
        parent=None, sourceline=None, ignore_mismatch=False):
        '''Takes *string* and parses it into a Rule object.

        As Rule objects require a Filter object, the parsing of the filter is
        deligated to Filter.from_string.'''

        # Removing comments and unnecessary white spaces
        string = string.split('#')[0].strip()

        # Retriving action
        action = string.split(' ')[0]

        # Creating Filter
        # Retrieves substring, relevant for Filter
        fstring = string.split(' ')[1:]
        # Extract extensions from the end
        extensions = []
        while fstring[-1] in extension_names:
            extensions.append(fstring.pop())

        # Create Filter object
        filter = Filter.from_string(' '.join(fstring), context, temp_aliases,
            filename, lineno, parent, sourceline, ignore_mismatch)

        return cls(action, filter, extensions, filename, lineno, parent)

    def __str__(self):
        return self.action+' '+str(self.filter)+' '+' '.join(self.extensions)

    def __repr__(self):
        #return '<metacl.Rule '+self.action+' '+str(self.filter)+' '+str(self.extensions)+'>'
        return str(self)

class Filter(Trackable):
    '''Describes a filter under which condition a Rule applies.

    Selection can be done based on protocol, source and destination addresses
    and ports.'''

    def __init__(self, protocols, sources, destinations, sports=None, dports=None,
            filename=None, lineno=None, parent=None, sourceline=None, ignore_mismatch=False):

        if not all(map(lambda x: x in protocol_names, protocols)):
            err = InvalidACL('Invalid protocol')
            Trackable.__init__(err, filename=filename, lineno=lineno,
                parent=parent)
            raise err

        self.protocols = protocols # protocols (e.g. ip, tcp)
        if type(sports) is str:
            self.sports = Ports.from_string(sports)
        elif sports is None:
            self.sports = Ports()
        elif isinstance(sports, Ports):
            self.sports = sports
        else:
            raise ValueError('sports has to be of either str, Ports or None type.')
            
        if type(dports) is str:
            self.dports = Ports.from_string(dports)
        elif dports is None:
            self.dports = Ports()
        elif isinstance(dports, Ports):
            self.dports = dports
        else:
            raise ValueError('dports has to be of either str, Ports or None type.')
        
        self.destinations = destinations
        self.sources = sources

        # check if ports are given, that combination with protocol makes sense
        if (sports or dports) and not all(map(port_protocols.__contains__, self.protocols)):
            err = ProtocolDoesNotSupportPorts("One of the protocols does not support ports, " +
                "but ports were given.")
            Trackable.__init__(err, filename=filename, lineno=lineno,
                parent=parent, sourceline=sourceline)
            raise err

        Trackable.__init__(self, filename, lineno, parent)

        self.ip_versions = []
        if filter(lambda x: type(x) is IPv6Network, sources) != [] \
            and filter(lambda x: type(x) is IPv6Network, destinations) != []:
            self.ip_versions.append('ipv6')
        if filter(lambda x: type(x) is IPv4Network, sources) != [] \
            and filter(lambda x: type(x) is IPv4Network, destinations) != []:
            self.ip_versions.append('ipv4')

        # Were we able to create a filter for IPv4 or IPv6?
        if not self.ip_versions and not ignore_mismatch:
            err = IPVersionMissmatchError("IPv6 or IPv4 addresses have to " +
                "appear in source and destination!")
            Trackable.__init__(err, filename=filename, lineno=lineno,
                parent=parent, sourceline=sourceline)
            raise err

        # Remove unused IP Versions
        if 'ipv6' not in self.ip_versions:
            self.sources = filter(lambda x: type(x) is not IPv6Network, self.sources)
            self.destinations = filter(lambda x: type(x) is not IPv6Network, self.destinations)
        if 'ipv4' not in self.ip_versions:
            self.sources = filter(lambda x: type(x) is not IPv4Network, self.sources)
            self.destinations = filter(lambda x: type(x) is not IPv4Network, self.destinations)

    @classmethod
    def from_string(cls, string, context=None, temp_aliases=None, filename=None, lineno=None,
        parent=None, sourceline=None, ignore_mismatch=False):
        '''Parsers *string* and returns Filter object.'''
        string_orig = string

        string = string.strip().split(' ')
        string.reverse()

        if len(string) < 3:
            err = InvalidACL('The rule is not valid')
            Trackable.__init__(err, filename=filename, lineno=lineno,
                parent=parent)
            raise err

        protocols = string.pop().split(',')

        try:
            sources = string_to_ips(string.pop(), context, temp_aliases)
        except (AddressValueError, NetmaskValueError):
            err = InvalidACL('Source IP in rule is invalid')
            Trackable.__init__(err, filename=filename, lineno=lineno,
                parent=parent)
            raise err

        sports = Ports()
        # Is the following a port? Port descreption may only contain numbers, commas and dashes
        # IPs will not match, as they must contain dots or colons
        if re.match(r'^[0-9\-,]+$', string[-1]) != None:
            sports = Ports.from_string(string.pop())

        try:
            destinations = string_to_ips(string.pop(), context, temp_aliases)
        except (AddressValueError, NetmaskValueError):
            err = InvalidACL('Destination IP in rule is invalid')
            Trackable.__init__(err, filename=filename, lineno=lineno,
                parent=parent)
            raise err

        dports = Ports()
        # Also checking if sufficient elements are left
        if len(string) and re.match(r'^[0-9\-,]+$', string[-1]) != None:
            dports = Ports.from_string(string.pop())

        if len(string) > 0:
            err = InvalidACL('Not all elements of filter could be parsed')
            Trackable.__init__(err, filename=filename, lineno=lineno,
                parent=parent)
            raise err

        return cls(protocols, sources, destinations, sports, dports,
            filename, lineno, parent, sourceline, ignore_mismatch)

    def overlaps(self, other):
        '''Tell if self sources and destination overlapse with other sources and destination'''
        for ss in self.sources:
            for so in other.sources:
                if ss.overlaps(so):
                    for ds in self.destinations:
                        for do in other.destinations:
                            if ds.overlaps(do):
                                return True
        return False

    def __contains__(self, other):
        '''Tell if *self* sources contain *other* sources and destinations'''
        for ss in self.sources:
            for so in other.sources:
                if so in ss:
                    for ds in self.destinations:
                        for do in other.destinations:
                            if do in ds:
                                return True
        return False

    def __str__(self):
        return str(self.protocols)+' '+str(self.sources)+' '+str(self.sports.to_string())+' ' \
            +str(self.destinations)+' '+str(self.dports.to_string())

    def __repr__(self):
        #return '<metacl.Filter '+self.name+' '+str(self.sources)+' '+str(self.sports.to_string())+' ' \
        #    +str(self.destinations)+' '+str(self.dports.to_string())+'>'
        return str(self)
