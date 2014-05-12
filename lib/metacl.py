# !/usr/bin/env python
# FAUST2 - a network ACL compiler and ditribution system.
# Copyright (C) 2013  Julian Hammer <julian.hammer@u-sys.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Implements abstraction of ACLs and information requierd to interpret it.

Everything required to parse, abstract and store the core of ACLs and related
information is part of the `metacl` module.

Classes:
`ACL` parses, checks and installs access control lists.
`Context` stores all information required to fully interpret an `ACL`.
`Rule` parses one line and defines the action to be taken if `Filter` matches.
`Filter` parses filter section in `Rule` and allows comparsion.
`MacroCall` parses and interprets calls to macros from `ACL`.
`Ports` abstracts arbitrary port lists made up of individual entries and ranges.

Functions:
`string_to_ips` parses IP string and returns list of `ipaddr.IPv4Network` and `ipaddr.IPv6Network`.

Exceptions:
`Error`, base class for all `metacl` exceptions
`IPVersionMissmatchError` raised if a filter's source and destination are not of same IP version.
`MacroDoesNotExistError` raised if requested macro does not exist.
`VLANDoesNotExistError` raised if VLAN couldn't be found in VLANs file.
`VLANDescriptionError` raised if description in VLANs file is faulty.
`NeedsContextError` raied if no context was provided, but aliases are used by `ACL`.
`InvalidACLError` raised if `ACL` could not parse the given string or file.
`UnknownRoutingdomainError` raised if routingdomain is unknown.
`UnknownRouterError` rased if router is unknown.
`ProtocolDoesNotSupportPortsError` raised if ports were given and protocol does not support ports.

Constants:
`IP_VERSIONS` list of supported IP versions (e.g. 'ipv6').
`PROTOCOL_NAMES` list of supported protocol names (e.g. 'icmp').
`PORT_PROTOCOLS` list of protocols that support ports (e.g. 'tcp').
`EXTENSION_NAMES` list of supported extensions (e.g. 'established')
`DIRECTIONS` list of directions ('in' and 'out')
"""

from pprint import pformat
import re
import os
import itertools
import difflib

import ConfigParser

from third_party.ipaddr import IPv4Network, IPv6Network, AddressValueError, NetmaskValueError

import ipaddr_ng
from ipaddr_ng import IPv4Descriptor, IPv6Descriptor, IPDescriptor
from helpers import Trackable
import macros
import logging
import config

log = logging.getLogger('lib.metacl')

# IP Version names
IP_VERSIONS = ['ipv4', 'ipv6']
# Protocol names
PROTOCOL_NAMES = ['tcp', 'udp', 'ip', 'icmp', 'esp', 'ahp', 'pim', 'igmp', 'ospf', 'gre']
# Protocol names that support ports (they must still apprear above)
PORT_PROTOCOLS = ['tcp', 'udp']
# Extension names
EXTENSION_NAMES = ['established', 'log', 'echo', 'echo-reply', 'ttl-exceeded', 'time-exceeded']
# Directions
DIRECTIONS = ['in', 'out']


class Error(Exception):
    """Base class for exceptions in this module."""


class IPVersionMissmatchError(Error, Trackable):
    '''Rule needs source and destination filters of same IP version.'''


class MacroDoesNotExistError(Error, Trackable):
    '''The requested macro does not exist.'''


class VLANDoesNotExistError(Error):
    '''The VLAN couldn't be found in VLANs file.'''


class VLANDescriptionError(Error):
    '''Description in VLANs file is faulty.'''


class NeedsContextError(Error, Trackable):
    '''No context was provided, but aliases are used. Can not proceed.'''


class InvalidACLError(Error, Trackable):
    '''ACL file/string is invalid.'''


class UnknownRoutingdomainError(Error):
    '''Requested routingdomain is unknown.'''


class UnknownRouterError(Error):
    '''Requested router is unknown.'''


class ProtocolDoesNotSupportPortsError(Error, Trackable):
    '''One of the protocols does not support ports, but ports were given.'''


class Ports:
    '''Ports list and range handeling in one object'''
    def __init__(self, *args):
        '''Forms a combination of individual ports and ranges.

        If *args* are two lists the first element must be a list of port
        integers and the second a list of port range tupels:
        >>> Ports( [23,42], [(1,5), (100,200)] ).__str__()
        "23,42,1-5,100-200"

        If *args* is instance of list, it must be a list of port integers:
        >>> Ports( [23,42] ).__str__()
        "23,42"

        If *args* is instance of str or unicode, it must be a comma seperated
        string of individual port numbers and port ranges (e.g. "1-1024"):
        >>> Ports( "23,42,256-1024" )
        Ports(([23,42],[256,1024]))

        Otherwise, an empty list/range will be created:
        >>> Ports()
        Ports([])
        '''
        if len(args) == 2:
            assert isinstance(args[0], list) and isinstance(args[1], list), \
                "in case of 2 arguments, only lists are valid."
            self.singles = args[0]
            self.ranges = args[1]
        elif len(args) == 1 and isinstance(args[0], list):
            self.singles = args[0]
            self.ranges = []
        elif len(args) == 1 and isinstance(args[0], (str, unicode)):
            # Empty initialization
            self.singles = []
            self.ranges = []

            # First we build a set with all matching port numbers:
            s = args[0].split(',')

            for ports_str in s:
                if '-' in ports_str:
                    range_str = ports_str.split('-')
                    self.add_range(int(range_str[0]), int(range_str[1]))
                else:
                    self.add_port(int(ports_str))
        elif len(args) == 0:
            self.singles = []
            self.ranges = []
        else:
            raise TypeError("To many arguments or of wrong type.")

    def add_port(self, port):
        '''Adds single port. Duplicates are ignored'''
        if port not in self:
            self.singles.append(port)

    def add_range(self, start, end):
        '''Adds port range from `start` to and including `end`.'''
        assert start <= end, "range has to be given in increasing order " + \
            "(e.g. NOT 42 to 23, but 23 to 42)"

        # Finding overlaping and neighboring ranges
        for r in self.ranges:
            if r[0] <= end and r[1] >= start:
                # deleting range and (possibly) increasing size of new range
                start = min(r[0], start)
                end = max(r[1], end)
                self.ranges.remove(r)

        # Finding included ports
        self.singles = filter(lambda n: start > n or n > end, self.singles)

        # Adding range
        self.ranges.append((start, end))

    def to_tuples(self):
        '''Cisco style notation, in tuple form.'''
        data = map(lambda x: ('eq', x), self.singles)
        data += map(lambda x: ('range', (x[0], x[1])), self.ranges)

        return data

    def __contains__(self, port):
        # Find in single ports:
        if port in self.singles:
            return True

        # Find in port ranges:
        for r in self.ranges:
            if port <= r[1] and port >= r[0]:
                return True

        # Not found
        return False

    def __str__(self):
        '''Returns string which can be parsed by __init__() method.'''
        s = ''
        for p in self.singles:
            if len(s) > 0:
                s += ','
            s += '%s' % p

        for r in self.ranges:
            if len(s) > 0:
                s += ','
            s += '%s-%s' % r

        return s

    def __iter__(self):
        for p in self.singles:
            yield p
        for r in self.ranges:
            for p in range(r[0], r[1] + 1):
                yield p

    def __bool__(self):
        return bool(self.singles) or bool(self.ranges)
    __nonzero__ = __bool__

    def __eq__(self, other):
        return set(other.singles) ^ set(self.singles) == set() and \
            set(other.ranges) ^ set(self.ranges) == set()

    def __len__(self):
        # Returns total number of ports
        s = sum(map(lambda x, y: y - x + 1, self.ranges))
        return len(self.singles) + s

    def __repr__(self):
        if not self.ranges and not self.singles:
            return self.__class__.__name__ + '()'
        if not self.ranges:
            return self.__class__.__name__ + '(%r)' % self.singles
        else:
            return self.__class__.__name__ + '((%r, %r))' % (self.singles, self.ranges)


# TODO IPs version of Ports
class IPs:
    def __init__(self, singles=None, ranges=None):
        if singles:
            self.singles = singles
        else:
            self.singles = []

        if ranges:
            self.ranges = ranges
        else:
            self.ranges = []

    def add_single(self, single):
        # Only add if not yet existant
        # TODO find ranges where this could be applied to
        # Careful: join of ranges might be required!
        if single not in self:
            self.singles.append(single)

    def add_range(self, start, end):
        assert start <= end, "range has to be given in increasing order " + \
            "(e.g. NOT 42 to 23, but 23 to 42)"

        # Finding overlaping and neighboring ranges
        for r in self.ranges:
            if r[0] <= end and r[1] >= start:
                # deleting range and (possibly) increasing size of new range
                start = min(r[0], start)
                end = max(r[1], end)
                self.ranges.remove(r)

        # Finding included ports
        self.singles = filter(lambda n: start > n or n > end, self.singles)

        # Adding range
        self.ranges.append((start, end))

    def __contains__(self, port):
        # Find in single ports:
        if port in self.singles:
            return True

        # Find in port ranges:
        for r in self.ranges:
            if port <= r[1] and port >= r[0]:
                return True

        # Not found
        return False

    def __iter__(self):
        for p in self.singles:
            yield p
        for r in self.ranges:
            for p in range(r[0], r[1] + 1):
                yield p

    def __bool__(self):
        return bool(self.singles) or bool(self.ranges)
    __nonzero__ = __bool__

    def __eq__(self, other):
        return set(other.singles) ^ set(self.singles) == set() and \
            set(other.ranges) ^ set(self.ranges) == set()

    def __len__(self):
        # Returns total number of ports
        s = sum(map(lambda x, y: y - x + 1, self.ranges))
        return len(self.singles) + s

    def __repr__(self):
        if not self.ranges and not self.singles:
            return self.__class__.__name__ + '()'
        if not self.ranges:
            return self.__class__.__name__ + '(%r)' % self.singles
        else:
            return self.__class__.__name__ + '(%r, %r)' % (self.singles, self.ranges)


def string_to_ips(string, context=None, temp_aliases=None):
    '''Parses ip description *string* and returns approriate list of
    IPv4Network and IPv6Network objects.
    Resolves aliases using temp_aliases and context object.

    If alias is found, and context is None, a NeedsContextError exception will be thrown.'''

    ips = []
    if string[0] == '$' or string.startswith("any") or string.startswith("local"):
        # Check for context
        if not context and not temp_aliases:
            raise NeedsContextError('Can not resolve host/net aliases without context or ' +
                                    'temp_aliases.')

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

    def __init__(self, acl_in=None, acl_out=None, macros=None, context=None,
                 filename=None, parent=None):
        if macros is None:
            self.macros = []
        else:
            self.macros = macros
        if acl_in is None:
            self.acl_in = []
        else:
            self.acl_in = acl_in
        if acl_out is None:
            self.acl_out = []
        else:
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
        lines = filter(lambda x: not len(x[1].strip()) == 0 and not x[1].strip().startswith('#'),
                       lines)
        # Strip all leading and ending whitespaces from lines
        lines = map(lambda x: (x[0], x[1].strip()), lines)

        if len(lines) == 0:
            err = InvalidACLError('ACL can not be empty!')
            Trackable.__init__(err, filename=filename, parent=parent)
            raise err

        # Split lines into macro-, in- and out-block
        macros = []
        acl_in = []
        acl_out = []
        try:
            # Find beginning of in-block by locating "IN:" line
            index_in = next((i for i in xrange(len(lines) - 1, -1, -1) if lines[i][1] == 'IN:'),
                            None)
            # Find beginning of out-block by locating "OUT:" line
            index_out = next((i for i in xrange(len(lines) - 1, -1, -1) if lines[i][1] == 'OUT:'),
                             None)

            # Macros are infront of in-block
            macros = lines[:index_in]

            acl_in = lines[index_in + 1:index_out]
            acl_out = lines[index_out + 1:]

        # Index search returned unsuccessful
        except:
            err = InvalidACLError('IN and OUT sections could not be found in ACL.')
            Trackable.__init__(err, filename=filename, parent=parent)
            raise err

        # Create Rule objects from *lines*
        # Macros via MarcoCall.from_string()
        macros = map(lambda x: MacroCall.from_string(x[1], lineno=x[0], filename=filename), macros)
        # In/Out rules via Rule.from_string()
        acl_in = map(lambda x: Rule.from_string(x[1], context, lineno=x[0], filename=filename),
                     acl_in)
        acl_out = map(lambda x: Rule.from_string(x[1], context, lineno=x[0], filename=filename),
                      acl_out)

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
            raise NeedsContextError('Macros can only applied in a context!')

        if self.macros_applied:
            raise Error('Macros can only be applied once!')
        else:
            self.macros_applied = True

        # Not yet sorted
        macros_sorted = self.macros

        # Remove dependencies which do not apply, e.g. dhcp depends on
        # broadcast, but broadcast is not used
        for m in macros_sorted:
            m.macro.dependencies = filter(lambda x: x in map(lambda x: type(x.macro),
                                                             macros_sorted),
                                          m.macro.dependencies)

        # Execute in topological order
        while len(macros_sorted) > 0:
            # Sort macros by number of dependencies, in increasing order
            macros_sorted = sorted(macros_sorted, key=lambda x: len(x.macro.dependencies),
                                   reverse=True)

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
                    "Couldn't resolve dependencies for macro: %s form %s" % (m.name, m.origin()))

    def compile(self, timestamp=True, save_to_file=True):
        '''Compiles this ACL with given *context*.

        Macros will be applied, if not done before. See :func:`apply_macros`

        If *timestamp* is True, compiled ACL will contain remarks with date
        and time of compilation.
        If *save_to_file* is True, compiled ACL will be saved to compiled_dir,
        as configured.'''

        if not self.context:
            raise NeedsContextError('Can only be compiled with a context!')

        if not self.macros_applied:
            self.apply_macros()

        context = self.context
        acl = context.dialect_module.compile_all(self, context.routingdomain + context.vlanid,
                                                 timestamp)

        cfile = None
        if save_to_file:
            # Saving compiled ACLs to cfile in cdir
            cdir = '%s/%s' % (config.get('global', 'compiled_dir'), context.routingdomain)
            cfile = '%s/%s.acl' % (cdir, context.vlanid)

            try:
                try:
                    umask = int(config.get('global', 'umask'))
                except:
                    umask = None
                try:
                    gid = int(config.get('global', 'groupid'))
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
                        os.chmod(cdir, umask + stat.S_IXUSR + stat.S_IXGRP + stat.S_IXOTH)
                    if gid:
                        os.chown(cdir, -1, gid)

                # If file allready exists
                if os.path.isfile(cfile):
                    # Delete it
                    os.remove(cfile)

                # Creating new file
                f = open(cfile, 'w')

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
            raise NeedsContextError('Can only be installed with a context!')

        if save_to_file:
            self.compile(timestamp=timestamp, save_to_file=True)

        self.context.dialect_module.install(self, timestamp=timestamp)

        return True

    def check(self, direction='in', protocol='ipv4', output=None):
        '''Compares *other* with this ACLs *protocol* rules in *direction*.

        Macros will be applied, if not done before. See :func:`apply_macros`'''

        if not self.context:
            raise NeedsContextError('Can only be compiled with a context!')

        if not self.macros_applied:
            self.apply_macros()

        # Compiling rules
        context = self.context
        dialect = context.dialect_module
        acl = dialect.compile_one(
            self,
            context.routingdomain + context.vlanid,
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
                print >> output, "No ACLs are bound on interface " + ifaces[router.name] + \
                    " (" + protocol + " " + direction + ") on " + router.name
                continue

            acl_on_router = router.read_acl(acl_names[protocol][direction], protocol)
            acl_on_router = acl_on_router.split('\n')

            if not acl_on_router == local_acl:  # and ouput
                same = False
                same_router[router.name] = False

                print >> output, "Diff of VLAN %s (%s %s) on %s:" % (vlanid, protocol, direction,
                                                                     router.name)

                for l in difflib.unified_diff(acl_on_router, local_acl,
                                              fromfile='local (%s %s)' % (protocol, direction),
                                              tofile='%s (%s %s)' % (router.name, protocol,
                                                                     direction),
                                              lineterm=""):
                    print >> output, '    ' + l

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

    def get_rules(self, directions=DIRECTIONS, ip_versions=IP_VERSIONS):
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
        '''Check if ACL is valid.

        Returns list containing strings depending on the conflict that matched
        a string with in or out
        and the rule(s) that caused the conflict
        different protocols are ignored'''
        # TODO Improve protocol checks

        if not self.macros_applied:
            self.apply_macros()

        # filter macros
        ignore_macros = config.get('global', 'ignore_macros').split()
        ignore_macros = map(lambda x: eval("macros.%s" % x), ignore_macros)

        ret = []
        # check both directions d will be 'in' or 'out'
        for d in DIRECTIONS:
            acl = self.get_rules(d)

            # remove rule from macros specified in config.ini
            for i in ignore_macros:
                acl = filter(lambda x: type(x.parent) != i, acl)

            # save acl to reset it later
            orig = acl
            
            acl = filter(lambda x: not ('established' in x.extensions),acl)
            
            # check if a rule is never reached cause it is fully contained in an ealier rule
            for i in range(len(acl)):
                # filter reduces list to the rules never reached
                # map connects the rules to the ones they are contained in
                # description string: "Rule never reached"
                ret += map(
                    lambda r2: ('Rule never reached', d, r2, acl[i]),
                    filter(lambda x: x.filter in acl[i].filter and
                           x.filter.protocols == acl[i].filter.protocols and
                           ((not x.filter.sports or not acl[i].filter.sports) or
                            filter(x.filter.sports.__contains__, acl[i].filter.sports)) and
                           ((not x.filter.dports or not acl[i].filter.dports) or
                            filter(x.filter.dports.__contains__, acl[i].filter.dports)),
                           acl[(i + 1):]))
            
            #reset acl
            acl = orig
            
            # remove permit any/local local/any and deny any any
            acl = filter(lambda x: not (x.action == 'deny' and
                                        self.equals_any(x.filter.sources) and
                                        self.equals_any(x.filter.destinations)), acl)
            if(d == 'in'):
                acl = filter(lambda x: not (x.action == 'permit' and
                                            self.equals_local(x.filter.sources) and
                                            self.equals_any(x.filter.destinations)), acl)
            else:
                acl = filter(lambda x: not (x.action == 'permit' and
                                            self.equals_any(x.filter.sources) and
                                            self.equals_local(x.filter.destinations)), acl)
            # save acl to reset it later
            orig = acl

            # check if IN.sources and OUT.destinations are in local
            # description string: "Rule not in local"
            for i in range(len(acl)):
                # filter reduces list to the rules that are not in local and unequal any
                # map connects the elemnts to the string
                if d == 'in':
                    ret += map(
                        lambda x: ('Rule not in local', d, x),
                        filter(lambda x: not self.in_local(x.filter.sources) and
                               not self.equals_any(x.filter.sources) and
                               # TODO build config to ignore ips in this check
                               not x.filter.sources[0] == IPv4Network('224.0.0.0/4') and
                               not x.filter.sources[0] == IPv4Network('255.255.255.255/32') and
                               not x.filter.sources[0] == IPv6Network('fe80::/10'),
                               acl[(i + 1):]))
                else:
                    ret += map(
                        lambda x: ('Rule not in local', d, x),
                        filter(lambda x: not self.in_local(x.filter.destinations) and
                               not self.equals_any(x.filter.destinations) and
                               not x.filter.destinations[0] == IPv4Network('224.0.0.0/4') and
                               not x.filter.destinations[0] == IPv4Network('255.255.255.255/32') and
                               not x.filter.destinations[0] == IPv6Network('fe80::/10'),
                               acl[(i + 1):]))



            # reset acl
            acl = orig
            # check if rules do overlapse, any and local are ignored
            # filter removes any and local
            acl = filter(lambda x: not self.equals_any(x.filter.sources) and
                         not self.equals_any(x.filter.destinations) and
                         not self.equals_local(x.filter.sources) and
                         not self.equals_local(x.filter.destinations), acl)

            for i in range(len(acl)):
                # filter reduces list to the rules that overlaps
                # map connects the rules to the ones they overlaps with
                # description string: "Rule overlapses
                ret += map(
                    lambda r2: ('Rules overlaps', d, acl[i], r2),
                    filter(lambda x: acl[i].filter.overlaps(x.filter) and
                           x.filter.protocols == acl[i].filter.protocols and
                           ((not x.filter.sports or not acl[i].filter.sports) or
                            filter(x.filter.sports.__contains__, acl[i].filter.sports)) and
                           ((not x.filter.dports or not acl[i].filter.dports) or
                            filter(x.filter.dports.__contains__, acl[i].filter.dports)),
                           acl[(i + 1):]))

            # reset acl
            acl = orig
            # check if rule is fully contained in a later rule with same action
            # (permit, deny)
            for i in range(len(acl)):
                # filter reduces list to the rules that are contained in sth.
                # map connects the rules to the ones they are contained in
                # description string: "Rule contained in other"
                ret += map(
                    lambda r2: ('Rule contained in later rule', d, acl[i], r2),
                    filter(lambda x: acl[i].filter in x.filter and
                           acl[i].action == x.action and
                           x.filter.protocols == acl[i].filter.protocols and
                           ((not x.filter.sports or not acl[i].filter.sports) or
                            filter(x.filter.sports.__contains__, acl[i].filter.sports)) and
                           ((not x.filter.dports or not acl[i].filter.dports) or
                            filter(x.filter.dports.__contains__, acl[i].filter.dports)),
                           acl[(i + 1):]))

        return ret

    def equals_any(self, networks):
        '''returns true if *networks* is 'any' '''
        return networks[0] == IPv4Network('0.0.0.0/0') or networks[0] == IPv6Network('::1/0')

    def equals_local(self, networks):
        '''returns true if *network* is 'local' '''
        return networks == self.context.get_alias('local')

    def is_pal(self, rule):
        '''returns true if *rule* is Rule: permit ip any local'''
        if rule.action == 'permit' and \
                self.equals_any(rule.filter.sources) and \
                self.equals_local(rule.filter.destinations):
            return True

    def is_daa(self, rule):
        '''returns true if *rule* is Rule: deny ip any any'''
        if rule.action == 'deny' and \
                self.equals_any(rule.filter.sources) and \
                self.equals_any(rule.filter.destinations):
            return True

    def in_local(self, network):
        '''returns true if *network* is completely contained in local'''
        for n in network:
            # False if any *n* is not contained in local
            if not any(map(lambda x: n in x, self.context.get_alias('local'))):
                return False
        return True
    
    def is_default(self, macros=True, extensions=True):
        '''Returns True if ACL is equal to default ACL.'''
        default = ACL.from_file(config.get('global', 'default_pol'), self.context)
        if self.macros_applied:
            default.apply_macros()
        
        return self.__eq__(default, macros=macros, extensions=extensions)
    
    def __eq__(self, other, macros=True, extensions=True):
        '''Returns True if ACL is equal to *other*.
        
        If macros have only been applied on one ACL, will return False.'''
        # TODO preserve original ACL even after macros have been applied
        
        if not extensions:
            if len(self.acl_in) != len(other.acl_in) or len(self.acl_out) != len(other.acl_out):
                acls = False
            else:
                acls = all(map(lambda i: self.acl_in[i].__eq__(other.acl_in[i]),
                               range(len(self.acl_in)))) and \
                       all(map(lambda i: self.acl_out[i].__eq__(other.acl_out[i]),
                               range(len(self.acl_out))))
        else:
            acls = self.acl_in == other.acl_in and self.acl_out == other.acl_out
        
        return ((not macros or self.macros_applied == other.macros_applied) and
                (not macros or self.macros == other.macros) and
                acls and
                self.context == other.context)

    def __str__(self):
        return 'ACL:\n MACROS:\n%s\n ACL IN:\n%s\n ACL OUT:\n%s' % \
            (pformat(self.macros, 3), pformat(self.acl_in, 3), pformat(self.acl_out, 3))


class Context(object):
    '''Represents a context, within which a ACL can be checked and compiled.

    It knows aliases and other information, necessary to understand a ACL and
    to compile a real ACL out of it's meta object.'''

    def __init__(self, routingdomain=None, vlanid=None):
        self.routingdomain = routingdomain
        self.vlanid = str(vlanid)
        self.interfaces = {}

        # Find and read host alias configuration
        hosts_config = ConfigParser.SafeConfigParser()
        hosts_config.read(config.get("global", "aliases_file"))

        # Build dictionary of aliases found in config
        self.ipv4_aliases = dict(map(lambda x: (x[0],
                                                IPv4Descriptor(x[1].strip().replace(" ", ""))),
                                     hosts_config.items('ipv4')))
        self.ipv6_aliases = dict(map(lambda x: (x[0],
                                                IPv6Descriptor(x[1].strip().replace(" ", ""))),
                                     hosts_config.items('ipv6')))

        # Including external alias descriptions
        basepath = os.path.abspath(os.path.dirname(config.get("global", "aliases_file")))
        for k, v in hosts_config.items('include'):
            if not v:
                continue
            for l in open(basepath+'/'+v).readlines():
                if not l.startswith('#') and not l.startswith(';') and len(l) > 0:
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
                self.interfaces[r['name']] = 'Vlan' + self.vlanid

        router_connections = None

        macro_configs = {}  # used by macros to exchange informations

    def get_alias(self, host, ip_versions=IP_VERSIONS):
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
        if 'ipv4' in ip_versions and host in self.ipv4_aliases:
            l += self.ipv4_aliases[host]
        if 'ipv6' in ip_versions and host in self.ipv6_aliases:
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

            if name in self.ipv6_aliases:
                self.ipv6_aliases[name] += ips
            else:
                self.ipv6_aliases[name] = ips
        else:
            # IPv4
            ips = IPv4Descriptor(ip_string)

            if name in self.ipv4_aliases:
                self.ipv4_aliases[name] += ips
            else:
                self.ipv4_aliases[name] = ips

    def get_vlan_info(self):
        '''Reads aliases from vlans_file and transit_file (paths from config).

        Automaticly called in constructor.

        Throws VLANDoesNotExistError exeption if vlan could not be found in file.'''

        self.ipv4_aliases['local'] = []
        self.ipv6_aliases['local'] = []

        f = open(config.get("global", "vlans_file"))
        for l in f.readlines():
            # turn line into array
            # RRZE        3	rlan3		131.188.2.0/23		2001:638:A00:2::/64	RRZE-UNIX
            # to
            # ['RRZE','3','rlan3',131.188.2.0/23','2001:638:A00:2::/64','RZE-UNIX']
            l = filter(lambda x: x != '' and not x.startswith(';'), l.strip().split('\t'))

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
                        raise VLANDescriptionError(
                            'Bad IPv4 range description of VLAN %s %s in %s.' %
                            (self.routingdomain, self.vlanid, config.get("global", "vlans_file")))

                if not l[4].startswith('-'):
                    self.ip_versions.append('ipv6')
                    try:
                        self.ipv6_aliases['local'] += [IPv6Network(l[4])]
                    except AddressValueError:
                        raise VLANDescriptionError(
                            'Bad IPv6 range description of VLAN %s %s in %s.' %
                            (self.routingdomain, self.vlanid, config.get("global", "vlans_file")))

        f = open(config.get("global", "transit_file"))
        for l in f.readlines():
            # turn line into array
            # RRZE		3	rlan3		131.188.2.0/23		2001:638:A00:2::/64	RRZE-UNIX
            # to
            # ['RRZE','3','rlan3',131.188.2.0/23','2001:638:A00:2::/64','RZE-UNIX']
            l = filter(lambda x: x != '' and not x.startswith(';'), l.strip().split('\t'))

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
                        raise VLANDescriptionError(
                            ('Bad interface name in description of VLAN %s %s in %s, must be in ' +
                             'python dictionary string notation') %
                            (self.routingdomain, self.vlanid, config.get("global", "transit_file")))

                # If column starts with -, ignore
                if not l[3].startswith('-'):
                    self.ip_versions.append('ipv4')
                    try:
                        self.ipv4_aliases['local'] += [IPv4Network(l[3])]
                    except AddressValueError:
                        raise VLANDescriptionError(
                            'Bad IPv4 range description of VLAN %s %s in %s' %
                            (self.routingdomain, self.vlanid, config.get("global", "transit_file")))

                # If column starts with -, ignore
                if not l[4].startswith('-'):
                    self.ip_versions.append('ipv6')
                    try:
                        self.ipv6_aliases['local'] += [IPv6Network(l[4])]
                    except AddressValueError:
                        raise VLANDescriptionError(
                            ('Bad IPv6 range description of VLAN %s %s in %s, must be in ' +
                             '/-notation') %
                            (self.routingdomain, self.vlanid, config.get("global", "transit_file")))

        if not self.ip_versions:
            raise VLANDoesNotExistError(('The VLAN (%s/%s) could not be found in VLANs nor in ' +
                                         'TNETs file.') % (self.routingdomain, self.vlanid))

        if not self.ip_versions:
            log.info('VLAN (%s/%s) has no IPv4 and no IPv6 network address.' %
                     (self.routingdomain, self.vlanid))

    def get_router_info(self):
        '''Reads information about the routers for this context and stores
        them in *self* object.'''

        c = ConfigParser.SafeConfigParser()
        routers_file = config.get('global', 'routers_file')
        assert len(c.read(routers_file)) > 0, 'File could not be read: ' + routers_file

        # Get list of routernames from routingdomains section
        try:
            routernames = c.get('routingdomains', self.routingdomain).split(',')
        except ConfigParser.NoOptionError:
            raise UnknownRoutingdomainError('Routingdomain (%s) not found in routers_file (%s).' %
                                            (self.routingdomain, routers_file))

        self.routers = []
        self.dialect = None
        # Get router section for each routername:
        for r in map(lambda x: x.strip(), routernames):
            try:
                self.routers.append(dict(c.items('router_' + r)))
                if 'host' not in self.routers[-1]:
                    raise UnknownRouterError('Router section router_%s has no host option.' % r)
                if 'dialect' not in self.routers[-1]:
                    raise UnknownRouterError('Router section router_%s has no host option.' % r)
                if self.dialect is None:
                    self.dialect = self.routers[-1]['dialect']
                elif self.routers[-1]['dialect'] != self.dialect:
                    raise UnknownRouterError(('Router section router_%s has different dialect ' +
                                              'then other routers in routingdomain') % r)
                self.routers[-1]['name'] = r
            except ConfigParser.NoSectionError:
                raise UnknownRouterError(('Router section (router_%s) not found in ' +
                                         'routers_file (%s).') % (r, routers_file))
        
        self.dialect_module = __import__('lib.dialects.' + self.dialect, fromlist='lib.dialects')

        self.user = c.get('access', 'user')
        self.pw = c.get('access', 'pw')

    def get_router_connections(self, read_running_config_first=False):
        '''Returns Router object, needed for communication with router.'''
        ret = []
        for router in self.routers:
            ret.append(self.dialect_module.Router(
                router['host'], self.user, self.pw,
                read_running_config_first=read_running_config_first, name=router['name']))

        return ret

    def get_policy_path(self):
        '''Returns path to policy file.'''
        return '%s/%s/%s' % (config.get("global", "policies_dir"), self.routingdomain,
                             self.vlanid+config.get("global", "policies_ext"))

    def get_policy_dir(self):
        '''Returns path to directory of policy files for same routingdomain.'''
        return '%s/%s/' % (config.get("global", "policies_dir"), self.routingdomain)

    def get_acl(self):
        '''Returns :class:`ACL` object for this context'''
        return ACL.from_context(self)
        
    def __eq__(self, other):
        '''Returns True if routingdomain, vlanid and interface are the same.
        
        Other parameters are not checked, since the should be equal.'''
        return (self.routingdomain == other.routingdomain and
                self.vlanid == other.vlanid and
                self.interfaces == other.interfaces)
                


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
            self.macro._comment = '%s(%s)' % (name, arguments)
        except AttributeError:
            err = MacroDoesNotExistError('Macro name is not valid')
            Trackable.__init__(err, filename=filename, lineno=lineno, parent=parent)
            raise err

    @classmethod
    def from_string(cls, string, filename=None, lineno=None, parent=None):
        '''Takes *string* and parses it to a MacroCall object.'''

        # Removing comments and unnecessary white spaces
        string = string.split('#')[0].strip()

        # Retriving and checking macro name
        name = string.split('(')[0]
        if re.match(r'^\w+$', name) is None:
            err = MacroDoesNotExistError('Macro name is not valid')
            Trackable.__init__(err, filename=filename, lineno=lineno, parent=parent)
            raise err

        # Retriving arguments
        arguments = string.split(')')[0].split('(')[1]

        return cls(name, arguments, filename, lineno, parent)

    def call(self, acl):
        '''Applies macro with arguments to *acl* ACL object.'''
        return self.macro.call(acl)
        
    def __eq__(self, other):
        '''Returns True if macro name and arguments are the same.
        
        Other parameters are not checked.'''
        return (self.name == other.name and
                self.arguments == other.arguments)


class Rule(Trackable):
    '''Abstraction of one rule from the policy file.'''

    def __init__(self, action, filter, extensions=[], filename=None, lineno=None, parent=None):
        if action not in ['permit', 'deny']:
            err = InvalidACLError('Action is not valid')
            Trackable.__init__(err, filename=filename, lineno=lineno, parent=parent)
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

        while fstring[-1] in EXTENSION_NAMES:
            extensions.append(fstring.pop())

        # Create Filter object
        filter = Filter.from_string(' '.join(fstring), context, temp_aliases, filename, lineno,
                                    parent, sourceline, ignore_mismatch)

        return cls(action, filter, extensions, filename, lineno, parent)

    def __str__(self):
        if self.extensions:
            return '%s %s %s' % (self.action, self.filter, ' '.join(self.extensions))
        else:
            return '%s %s' % (self.action, self.filter)

    def __repr__(self):
        # TODO include filename, lineno and parent in output
        r = self.__class__.__name__+'(%s, %s' % (self.action.__repr__(), self.filter.__repr__())

        if self.extensions:
            r += ', %s' % self.extensions.__repr__()

        if self.filename:
            r += ', filename=%s' % self.filename.__repr__()
        if self.lineno:
            r += ', lineno=%s' % self.lineno.__repr__()

        return r + ')'
    
    def __eq__(self, other, extensions=True):
        '''Returns True if action, filter and extensions are the same.
        
        Other parameters are not checked.'''
        return (self.action == other.action and
                self.filter == other.filter and
                (not extensions or self.extensions == other.extensions))


class Filter(Trackable):
    '''Describes a filter under which condition a Rule applies.

    Selection can be done based on protocol, source and destination addresses
    and ports.'''

    def __init__(self, protocols, sources, destinations, sports=None, dports=None, filename=None,
                 lineno=None, parent=None, sourceline=None, ignore_mismatch=False):
        Trackable.__init__(self, filename, lineno, parent)

        if not all(map(lambda x: x in PROTOCOL_NAMES, protocols)):
            err = InvalidACLError('Invalid protocol')
            Trackable.__init__(err, filename=filename, lineno=lineno,
                               parent=parent)
            raise err

        self.protocols = protocols  # protocols (e.g. ip, tcp)
        if type(sports) is str:
            self.sports = Ports(sports)
        elif sports is None:
            self.sports = Ports()
        elif isinstance(sports, Ports):
            self.sports = sports
        else:
            raise ValueError('sports has to be of either str, Ports or None type.')

        if type(dports) is str:
            self.dports = Ports(dports)
        elif dports is None:
            self.dports = Ports()
        elif isinstance(dports, Ports):
            self.dports = dports
        else:
            raise ValueError('dports has to be of either str, Ports or None type.')

        self.destinations = destinations
        self.sources = sources

        # check if ports are given, that combination with protocol makes sense
        if (sports or dports) and not all(map(PORT_PROTOCOLS.__contains__, self.protocols)):
            err = ProtocolDoesNotSupportPortsError("One of the protocols does not support ports, " +
                                                   "but ports were given.")
            Trackable.__init__(err, filename=filename, lineno=lineno, parent=parent,
                               sourceline=sourceline)

            raise err

        self.ip_versions = []
        if filter(lambda x: type(x) is IPv6Network, sources) != [] and \
                filter(lambda x: type(x) is IPv6Network, destinations) != []:
            self.ip_versions.append('ipv6')
        if filter(lambda x: type(x) is IPv4Network, sources) != [] and \
                filter(lambda x: type(x) is IPv4Network, destinations) != []:
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
            err = InvalidACLError('The rule is not valid')
            Trackable.__init__(err, filename=filename, lineno=lineno,
                               parent=parent)
            raise err

        protocols = string.pop().split(',')

        try:
            sources = string_to_ips(string.pop(), context, temp_aliases)
        except (AddressValueError, NetmaskValueError):
            err = InvalidACLError('Source IP in rule is invalid')
            Trackable.__init__(err, filename=filename, lineno=lineno,
                               parent=parent)
            raise err

        # Is the following a port? Port descreption may only contain numbers, commas and dashes
        # IPs will not match, as they must contain dots or colons
        if re.match(r'^[0-9\-,]+$', string[-1]) is not None:
            sports = Ports(string.pop())
        else:
            sports = Ports()

        try:
            destinations = string_to_ips(string.pop(), context, temp_aliases)
        except (AddressValueError, NetmaskValueError):
            err = InvalidACLError('Destination IP in rule is invalid')
            Trackable.__init__(err, filename=filename, lineno=lineno,
                               parent=parent)
            raise err

        # Also checking if sufficient elements are left
        if len(string) and re.match(r'^[0-9\-,]+$', string[-1]) is not None:
            dports = Ports(string.pop())
        else:
            dports = Ports()

        if len(string) > 0:
            err = InvalidACLError('Not all elements of filter could be parsed')
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
        if self.sports or self.dports:
            return '%s %s %s %s %s' % (','.join(self.protocols), ';'.join(map(str, self.sources)),
                                       self.sports, ';'.join(map(str, self.destinations)),
                                       self.dports)
        else:
            return ' '.join((','.join(self.protocols), ';'.join(map(str, self.sources)),
                             ';'.join(map(str, self.destinations))))

    def __repr__(self):
        # TODO include filename, lineno and parent in output
        r = self.__class__.__name__+'(%s, %s, %s' % \
            (self.protocols.__repr__(), self.sources.__repr__(), self.destinations.__repr__())

        if self.sports:
            r += ', sports=%s' % self.sports.__repr__()
        if self.dports:
            r += ', dports=%s' % self.dports.__repr__()

        if self.filename:
            r += ', filename=%s' % self.filename.__repr__()
        if self.lineno:
            r += ', lineno=%s' % self.lineno.__repr__()

        return r + ')'
    
    def __eq__(self, other):
        '''Returns True if protocols, sources, sports, destinations and dports are the same.
        
        Other parameters are not checked.'''
        return (self.protocols == other.protocols and
                self.sources == other.sources and
                self.sports == other.sports and
                self.destinations == other.destinations and
                self.dports == other.dports)
