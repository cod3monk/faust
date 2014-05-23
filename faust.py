#!/usr/bin/env python
#
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

'''
FAU Security Tool (FAUST)
An ACL generator and distributor.

Usage:
  faust.py (compile|install|check|scheck) [-q] <routingdomain> [<vlan_id> ...]
  faust.py block <ip> [<comment> ...]
  faust.py unblock <ip>
  faust.py search <ip>
  faust.py rules <ip>
  faust.py create <routingdomain> <vlan_id>
  faust.py trace <src_ip> <dst_ip> [<port>] [<protocol>] [-r]
  faust.py -h | --help
  faust.py --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  -q --quiet    Quiet mode. Only errors are reported.
  -r --reverse  Reverses direction of src_ip and dst_ip

Commands:
    compile     Only compiles, no interation with router(s).
    install     Compiles and installs on router(s).
    check       Compiles and checks if ACL is up-to-date on router(s).
    scheck      Compiles and checks ACL for sanity (consitent rules).
    block       Blocks ip in ACL and installes current acl on router(s).
    unblock     Unblocks ip in ACL and installes current acl on router(s).
    search      Find VLAN information for given ip.
    rules       Print all rules regarding given ip.
    create      Creates default ACL for given VLAN.
    trace       Print rules between src_ip and dst_ip.
'''

import os
import sys
import random
import string
import time
import datetime
import warnings
import pprint
import re
import ConfigParser
import getpass

# so every module can see lib
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from lib.third_party import ipaddr
from lib.third_party import texttable
from lib.third_party import docopt

import lib
from lib import metacl, helpers, macros, dialects
import logging

try:
    lib.config.load()
except lib.config.ConfigError, err:
    print >> sys.stderr, "Problem with the configuration: %s" % err
    sys.exit(2)
log = logging.getLogger('faust')

def compare_acls(routingdomain, vlanid, output=sys.stdout):
    '''Compares local ACLs with active ACLs found on router.
    
    Will write diff information to `output` (default `sys.stdout`).
    '''
    try:
        ctxt = metacl.Context(routingdomain, vlanid)
        acl = ctxt.get_acl()
        acl.apply_macros()
        acl.compile()
    except lib.metacl.VLANDoesNotExistError, err:
        log.error("VLAN does not exist: %s" % err)
        return False

    for v in ['ipv4', 'ipv6']:
        if v in acl.context.ip_versions:
            for direction in ['in', 'out']:
                same = acl.check(protocol=v, direction=direction, output=output)[0]
                if not same:
                    return False

    return True


def read_lannetfile(filename):
    '''Reads a Network or VLAN description file, like VLANs or TNETs and returns a list
    of networks.'''
    nets = []

    with open(filename) as f:
        for l in f:
            l = l.strip()
            if not l.startswith(';') and not l.startswith('-') and len(l) > 0:
                n = filter(lambda x: len(x) > 0, l.split('\t'))

                # Try reading IPv4 Network or None
                try:
                    n[3] = ipaddr.IPv4Network(n[3])
                except:
                    n[3] = None

                # Try reading IPv6 Network or None
                try:
                    n[4] = ipaddr.IPv6Network(n[4])
                except:
                    n[4] = None

                nets.append(n)

    return nets


def print_conflicts(confs):
    '''Prints the list of given conflicts on log.info'''
    lines = []
    for c in confs:
        #conflicts from the same line are only shown once
        if(c[2].lineno not in lines):
            f = open(c[2].filename)
            polLines = f.readlines()
            log.info('')
            log.info("in file %s:" % c[2].filename)
            lines += [c[2].lineno]
            for line in c[2:]:
                log.info("%s in line %s" % (polLines[line.lineno-1], line.lineno))

            #diffrent presentation style:
            #for line in c[2:]:
            #    log.info("%s in line %s" %(line,line.lineno))
            #    lines += [line.lineno]


def choose_conflicts(conflicts):
    '''Shows all `conflicts` by types and prints them on `log.info` if choosen'''
    #split up conflicts into types
    notLocal = []
    contained = []
    neverReached = []
    overlap = []
    for c in conflicts:
        if c[0] == "Rule not in local":
            notLocal += [c]
        elif c[0] == "Rule contained in later rule":
            contained += [c]
        elif c[0] == "Rules overlaps":
            overlap += [c]
        elif c[0] == "Rule never reached":
            neverReached += [c]
        else:
            log.error("Conflict name not found: %s" % c[0])

    log.info("%s Conflicts for Rule not in local (1)" % len(notLocal))
    log.info("%s Conflicts for Rule contained in later rule (2)" % len(contained))
    log.info("%s Conflicts for Rules overlaps (3)" % len(overlap))
    log.info("%s Conflicts for Rule never reached (4)" % len(neverReached))
    log.info("Choose from Conflicts or (n) to continue")
    choice = sys.stdin.readline()
    while(choice != "n\n"):
        log.info("If one line caused multiple conflicts the line will be shown only once:")
        if choice == "1\n":
            log.info("Rule not in local:")
            print_conflicts(notLocal)
        elif choice == "2\n":
            log.info("Rule contained in later rule:")
            print_conflicts(contained)
        elif choice == "3\n":
            log.info("Rules overlaps:")
            print_conflicts(overlap)
        elif choice == "4\n":
            log.info("Rule never reached:")
            print_conflicts(neverReached)
        log.info('\n')
        log.info("%s Conflicts for Rule not in local (1)" % len(notLocal))
        log.info("%s Conflicts for Rule contained in later rule (2)" % len(contained))
        log.info("%s Conflicts for Rules overlaps (3)" % len(overlap))
        log.info("%s Conflicts for Rule never reached (4)" % len(neverReached))
        log.info("Choose from Conflicts or (n) to continue")
        choice = sys.stdin.readline()


def main(arguments):
    '''Main function taking care of all command-line functionality.'''
    if len(sys.argv) <= 1:
        print >> sys.stderr, "No arguments given"
        usage()
        sys.exit(2)

    command = sys.argv[1]
    options = sys.argv[2:]

    log.debug("Called with argv: %s" % sys.argv)

    if arguments['compile']:
        routingdomain, vlans = arguments['<routingdomain>'], arguments['<vlan_id>']

        # Do we want to compile and install all vlans in one routing domain?
        if not vlans:
            try:
                l = os.listdir(lib.config.get('global', 'policies_dir')+'/'+routingdomain)
            except OSError:
                log.error("Domain policy directory not found.")
                sys.exit(2)
            ext = lib.config.get('global', 'policies_ext')
            vlans = map(lambda x: x[:-len(ext)], filter(lambda x: x.endswith(ext), l))

        log.info("Compiling ACL(s) for vlan(s): %s" % vlans)

        ipv6_count = 0
        fail_count = []
        for vlanid in vlans:
            try:
                context = metacl.Context(routingdomain, vlanid)
                acl = context.get_acl()
                #make sanity_check for vlanid
                if not arguments['--quiet']:
                    conflicts = acl.sanity_check()
                    if conflicts:
                        log.info("sanity_check found %s Conflicts in %s" % (len(conflicts), vlanid))
                        log.info("(y) to show or any other key to skip and continue compiling")
                        choice = sys.stdin.readline()
                        if choice == "y\n":
                            choose_conflicts(conflicts)
                            log.info("press (y) to continue compiling or other key to abort")
                            choice = sys.stdin.readline()
                            if choice != "y\n":
                                fail_count.append(vlanid)
                                continue
                cfile, acl, ipv6 = acl.compile()
            except (metacl.Error, macros.Error, dialects.generic.Error), err:
                if isinstance(err, helpers.Trackable):
                    msg = err.origin(with_sourceline=True)
                else:
                    msg = ''
                log.warning(msg+'%s' % err)
                fail_count.append(vlanid)
                continue

            if ipv6:
                ipv6_count += 1

        log.info("Successfully compiled %s ACLs and %.2f %% with IPv6" %
                 (len(vlans)-len(fail_count), float(ipv6_count)/float(len(vlans))*100))

        if fail_count:
            log.warning("%s ACLs did not compile, they are: %s" %
                        (len(fail_count), str(fail_count)))

    elif arguments['install']:
        routingdomain, vlans = arguments['<routingdomain>'], arguments['<vlan_id>']

        # Do we want to compile and install all vlans in one routing domain?
        if not vlans:
            try:
                l = os.listdir(lib.config.get('global', 'policies_dir')+'/'+routingdomain)
            except OSError as e:
                log.critical("Could not read policy directory for routing domain '%s': %s" %
                             (routingdomain, e))
                sys.exit(2)
            ext = lib.config.get('global', 'policies_ext')
            vlans = map(lambda x: x[:-len(ext)], filter(lambda x: x.endswith(ext), l))

        log.info("Installing ACLs for vlan(s): %s" % (vlans))

        ipv6_count = 0
        fail_count = []

        for vlanid in vlans:
            try:
                context = metacl.Context(routingdomain, vlanid)
                acl = context.get_acl()
                #make sanity_check for vlanid
                if not arguments['--quiet']:
                    conflicts = acl.sanity_check()
                    if conflicts:
                        log.info("sanity_check found %s Conflicts in %s" % (len(conflicts), vlanid))
                        log.info("(y) to show any other key to skip and continue compiling")
                        choice = sys.stdin.readline()
                        if choice == "y\n":
                            choose_conflicts(conflicts)
                            log.info("press (y) to continue compiling or other key to abort")
                            choice = sys.stdin.readline()
                            if choice != "y\n":
                                fail_count.append(vlanid)
                                continue
                cfile, acl_string, ipv6 = acl.compile()
            except (metacl.Error, macros.Error, dialects.generic.Error), err:
                if isinstance(err, helpers.Trackable):
                    msg = err.origin(with_sourceline=True)
                else:
                    msg = ''
                log.warning(msg+'%s' % err)
                fail_count.append(vlanid)
                continue

            acl.install()

            if ipv6:
                ipv6_count += 1

        log.info("Successfully installed %s ACLs and %.2f %% with IPv6" %
                 (len(vlans)-len(fail_count), float(ipv6_count)/float(len(vlans))*100))

        if fail_count:
            log.warning("%s ACLs did not install, they are: %s" %
                        (len(fail_count), str(fail_count)))

    elif arguments['search']:
        try:
            ip = ipaddr.IPAddress(arguments['<ip>'])
        except Exception, err:
            log.error(str(err))
            sys.exit(2)

        nets = read_lannetfile(lib.config.get('global', 'vlans_file'))
        tnets = read_lannetfile(lib.config.get('global', 'transit_file'))

        found = []
        for n in nets:
            if type(ip) is ipaddr.IPv4Address:
                if n[3] and ip in n[3]:
                    found.append(n)
            elif type(ip) is ipaddr.IPv6Address:
                if n[4] and ip in n[4]:
                    found.append(n)

        for n in tnets:
            if type(ip) is ipaddr.IPv4Address:
                if n[3] and ip in n[3]:
                    found.append(n)
            elif type(ip) is ipaddr.IPv6Address:
                if n[4] and ip in n[4]:
                    found.append(n)
            n[5] += " !TRANSFER!"

        if len(found) > 0:
            print 'Found', ip, 'in the following VLAN(s):'
            tt = texttable.Texttable()
            tt.header(['RD', 'Id', 'Name', 'Netzv4', 'NetzV6', 'Kommentar'])
            tt.add_rows(found, header=False)
            try:
                print tt.draw()

                # Getting routers by routingdomain
                c = ConfigParser.SafeConfigParser()
                routers_file = lib.config.get('global', 'routers_file')
                assert len(c.read(routers_file)) > 0, 'File could not be read: '+routers_file

                for f in found:
                    try:
                        routers = c.get('routingdomains', f[0]).split(',')
                        routers = map(lambda x: x.strip(), routers)
                    except:
                        routers = 'not configured in '+routers_file

                    print f[0], 'is handled by:', routers

            except UnicodeDecodeError:
                log.critical("ERROR: found invalid character in VLANs or TNETs file")
                sys.exit(1)
            sys.exit(0)

        print >> sys.stderr, 'Nothing found.'
        sys.exit(2)

    elif arguments['block']:
        comment = str(datetime.datetime.now())+' by '+getpass.getuser()
        if arguments['<comment>']:
            comment += ': '+' '.join(arguments['<comment>'])

        try:
            ip = ipaddr.IPAddress(arguments['<ip>'])
        except Exception, err:
            log.error(str(err))
            sys.exit(2)

        nets = read_lannetfile(lib.config.get('global', 'vlans_file'))
        tnets = read_lannetfile(lib.config.get('global', 'transit_file'))

        found = []
        for n in nets+tnets:
            if type(ip) is ipaddr.IPv4Address:
                if n[3] and ip in n[3]:
                    found.append(n)
            elif type(ip) is ipaddr.IPv6Address:
                if n[4] and ip in n[4]:
                    found.append(n)

        if len(found) == 0:
            try:
                default = tuple(lib.config.get('global', 'default_block_vlan').split(' '))
            except:
                default = None

            if not default:
                log.error('No VLAN found for given IP. Aborting. Set default_block_vlan in ' +
                          'config to enable a default block VLAN.')
                sys.exit(2)

            log.warning('No VLAN found for given IP. Making use of default VLAN: %s.' % (default,))
            found = [default]
        elif len(found) > 1:
            log.warning('Multiple VLANs found for given IP, continuing anyway.')
        for n in found:
            rd, vlanid = n[0], n[1]
            log.info('Blocking IP in VLAN '+str(vlanid)+' on '+rd+'...')
            c = metacl.Context(rd, vlanid)

            # RCS checkout
            if lib.config.get('global', 'use_rcs') == 'true':
                cmd = 'co -l '+c.get_policy_path()
                sts = os.system(cmd)
                if sts:
                    log.error('RCS checkout of '+c.get_policy_path()+' failed.')
                    sys.exit(2)

            f = open(c.get_policy_path())
            l = f.readlines()
            l.insert(0, 'block('+arguments['<ip>']+') # '+comment+'\n')
            f.close()
            f = open(c.get_policy_path(), 'w')
            f.writelines(l)
            f.close()

            # RCS checkin
            if lib.config.get('global', 'use_rcs') == 'true':
                cmd = 'ci -u -m"block by faust" '+c.get_policy_path()
                sts = os.system(cmd)
                if sts:
                    log.error('RCS checkin of '+c.get_policy_path()+' failed.')
                    sys.exit(2)

            metacl.ACL.from_context(c).install()
            log.info("Sucessfully blocked %s" % ip)

    elif arguments['rules']:
        try:
            ip = ipaddr.IPAddress(arguments['<ip>'])
        except Exception, err:
            log.error(str(err))
            sys.exit(2)

        nets = read_lannetfile(lib.config.get('global', 'vlans_file'))
        tnets = read_lannetfile(lib.config.get('global', 'transit_file'))

        found = []
        ip_versions = set()
        for n in nets+tnets:
            if type(ip) is ipaddr.IPv4Address:
                if n[3] and ip in n[3]:
                    ip_versions.add('ipv4')
                    found.append(n)
            elif type(ip) is ipaddr.IPv6Address:
                if n[4] and ip in n[4]:
                    ip_versions.add('ipv6')
                    found.append(n)

        if len(found) > 0:
            if len(found) > 1:
                log.warning('Multiple VLANs found for given IP, continuing anyway.')
            for n in found:
                rd, vlanid = n[0], n[1]
                c = metacl.Context(rd, vlanid)
                acl = c.get_acl()
                acl.apply_macros()
                rules = acl.get_rules(ip_versions=list(ip_versions))

                print "From %s VLAN %s:" % (rd, vlanid)
                print "lineno  rule"
                linenos = []
                for r in rules:
                    f = r.filter
                    if r.lineno not in linenos and \
                            any(map(lambda x: ip in x, f.sources+f.destinations)):
                        print '%s\t%s' % (r.lineno, r.sourceline.strip())
                        linenos.append(r.lineno)
        else:
            log.error('No VLAN found for given IP. Aborting.')
            sys.exit(2)

    elif arguments['unblock']:
        try:
            ip = ipaddr.IPAddress(arguments['<ip>'])
        except Exception, err:
            log.error(str(err))
            sys.exit(2)

        nets = read_lannetfile(lib.config.get('global', 'vlans_file'))
        tnets = read_lannetfile(lib.config.get('global', 'transit_file'))

        found = []
        for n in nets+tnets:
            if type(ip) is ipaddr.IPv4Address:
                if n[3] and ip in n[3]:
                    found.append(n)
            elif type(ip) is ipaddr.IPv6Address:
                if n[4] and ip in n[4]:
                    found.append(n)

        if len(found) > 0:
            if len(found) > 1:
                log.warning('Multiple VLANs (%s) found for given IP (%s). Continuing...' %
                            (found, ip))
            for n in found:
                rd, vlanid = n[0], n[1]
                log.info('Unblocking IP in VLAN %s on %s...' % (vlanid, rd))
                c = metacl.Context(rd, vlanid)

                # RCS checkout
                if lib.config.get('global', 'use_rcs') == 'true':
                    cmd = 'co -l '+c.get_policy_path()
                    sts = os.system(cmd)
                    if sts:
                        log.error('RCS checkout of '+c.get_policy_path()+' failed.')
                        sys.exit(2)

                f = open(c.get_policy_path())
                orig = f.read()
                new = re.sub(re.escape('block('+arguments['<ip>']+')')+r'[^\n]*\n', '', orig)
                f.close()

                if orig != new:
                    f = open(c.get_policy_path(), 'w')
                    f.write(new)
                    f.close()
                else:
                    log.warning('Could not identify block-line in %s. Only exact matches can be ' +
                                'found, please check manualy.' % c.get_policy_path())

                # RCS checkin
                if lib.config.get('global', 'use_rcs') == 'true':
                    cmd = 'ci -u -m"block by faust" '+c.get_policy_path()
                    sts = os.system(cmd)
                    if sts:
                        log.error('RCS checkin of '+c.get_policy_path()+' failed.')
                        sys.exit(2)

                metacl.ACL.from_context(c).install()
                log.info("Sucessfully unblocked %s" % ip)
        else:
            log.error('No VLAN found for given IP. Aborting.')
            sys.exit(2)

    elif arguments['check']:
        routingdomain, vlans = arguments['<routingdomain>'], arguments['<vlan_id>']
        uptodate = True

        # Do we want to compile and install all vlans in one routing domain?
        if not vlans:
            try:
                l = os.listdir(lib.config.get('global', 'policies_dir')+'/'+routingdomain)
            except OSError as e:
                log.error("Could not read policy directory for routing domain '%s': %e" %
                          (routingdomain, str(e)))
                sys.exit(2)
            ext = lib.config.get('global', 'policies_ext')
            vlans = map(lambda x: x[:-len(ext)], filter(lambda x: x.endswith(ext), l))

        log.info("Checking ACLs for vlan(s): %s" % vlans)

        for vlanid in vlans:
            log.info('Checking VLAN %s ACLs...' % vlanid)
            try:
                if compare_acls(routingdomain, vlanid):
                    log.info('ACLS for VLAN %s are up-to-date' % vlanid)
                else:
                    log.info('ACLS for VLAN %s are NOT up-to-date' % vlanid)
            except Exception as err:
                if isinstance(err, helpers.Trackable):
                    msg = err.origin(with_sourceline=True)
                else:
                    msg = ''
                log.error(msg+'%s' % err)
                continue

    elif arguments['create']:
        routingdomain, vlanid = arguments['<routingdomain>'], arguments['<vlan_id>'][0]

        context = metacl.Context(routingdomain, vlanid)
        pol_directory = context.get_policy_dir()
        pol_file = context.get_policy_path()

        # Loading umaks and gid form configuration
        try:
            umask = int(lib.config.get('global', 'umask'))
        except:
            umask = None
        try:
            gid = int(lib.config.get('global', 'groupid'))
        except:
            gid = None

        # Routingdomain directory might not exist
        if not os.path.isdir(pol_directory):
            log.info("Policy directory did not exist, but will be created.")

            try:
                # So create it
                os.mkdir(pol_directory)
                # Correcting rights and group ownership, if configured
                if umask:
                    import stat
                    # We make shure that also executable flags are set
                    os.chmod(pol_directory, umask+stat.S_IXUSR+stat.S_IXGRP+stat.S_IXOTH)
                if gid:
                    os.chown(pol_directory, -1, gid)
            except Exception as err:
                log.error("Problem creating directory: %s" % err)
                sys.exit(2)

        # Check if file already exists
        if os.path.isfile(pol_file):
            log.error("Policy file already exists. Will do no more.")
            sys.exit(2)

        import shutil
        try:
            shutil.copyfile(lib.config.get('global', 'default_pol'), pol_file)
        except IOError as err:
            log.error("Problem copying default policy to new policy file: %s" % err)
            sys.exit(2)

        # Correcting rights and group ownership, if configured
        if umask:
            os.chmod(pol_file, umask)
        if gid:
            os.chown(pol_file, -1, gid)

        log.info("Successfully created default policy for %s %s" % (routingdomain, vlanid))

    elif arguments['scheck']:
        routingdomain, vlans = arguments['<routingdomain>'], arguments['<vlan_id>']

        # Do we want to check all vlans in one routing domain?
        if not arguments['<vlan_id>']:
            try:
                l = os.listdir(lib.config.get('global', 'policies_dir')+'/'+routingdomain)
            except OSError as e:
                log.error("Could not read policy directory for routing domain '%s': %s" %
                          (routingdomain, str(e)))
                sys.exit(2)
            ext = lib.config.get('global', 'policies_ext')
            vlans = map(lambda x: x[:-len(ext)], filter(lambda x: x.endswith(ext), l))

        log.info("Checking ACLs for vlan(s): %s" % (vlans))

        conflicts = []
        fail_count = []
        for vlanid in vlans:
            try:
                context = metacl.Context(routingdomain, vlanid)
                macl = context.get_acl()
                macl.apply_macros()
                conflicts += macl.sanity_check()
            except (metacl.Error, macros.Error, dialects.generic.Error), err:
                if isinstance(err, helpers.Trackable):
                    msg = err.origin(with_sourceline=True)
                else:
                    msg = ''
                log.error(msg+'%s' % err)
                fail_count.append(vlanid)
                continue

        if fail_count:
            log.info("%s ACLS could not be checked, they are: %s" %
                     (len(fail_count), str(fail_count)))

        if conflicts != []:
            log.info("%s Conflicts found:" % len(conflicts))
            log.info("Show conflicts? (y)")
            choice = sys.stdin.readline()
            if choice == "y\n":
                choose_conflicts(conflicts)

        else:
            log.info("No Conflicts found!")

    elif arguments['trace']:
        try:
            src_ip = ipaddr.IPAddress(arguments['<src_ip>'])
            dst_ip = ipaddr.IPAddress(arguments['<dst_ip>'])
            if arguments['--reverse']:
                src_ip, dst_ip = dst_ip, src_ip
            if arguments['<protocol>'] is not None:
                if arguments['<protocol>'] in lib.metacl.protocol_names:
                    protocol = arguments['<protocol>']
                else:
                    log.error("Given protocol not supported: " + arguments['<protocol>'])
                    sys.exit(2)
            if arguments['<port>'] is not None:
                port = int(arguments['<port>'])
        except Exception, err:
            log.error(str(err))
            sys.exit(2)

        nets = read_lannetfile(lib.config.get('global', 'vlans_file'))
        tnets = read_lannetfile(lib.config.get('global', 'transit_file'))

        found_src = []
        found_dst = []
        ip_versions = set()
        for n in nets+tnets:
            if type(src_ip) is ipaddr.IPv4Address:
                if n[3] and src_ip in n[3]:
                    ip_versions.add('ipv4')
                    found_src.append(n)
                if n[3] and dst_ip in n[3]:
                    found_dst.append(n)
            elif type(src_ip) is ipaddr.IPv6Address:
                if n[4] and src_ip in n[4]:
                    ip_versions.add('ipv6')
                    found_src.append(n)
                if n[3] and dst_ip in n[3]:
                    found_dst.append(n)

        if len(found_src) > 0 and len(found_dst):
            if len(found_src) > 1 or len(found_dst) > 1:
                #VLAN file probably wrong
                log.warning('Multiple VLANs found for given IP. Aborting')
                sys.exit(2)

            #for sources
            rd, vlanid = found_src[0][0], found_src[0][1]
            c = metacl.Context(rd, vlanid)
            acl = c.get_acl()
            acl.apply_macros()
            rules = acl.get_rules(ip_versions=list(ip_versions), directions='in')
            #filter rules to match only when destination is dst_ip
            rules = filter(lambda x: any(map(lambda y: dst_ip in y, x.filter.destinations)), rules)
            rules = filter(lambda x: any(map(lambda y: src_ip in y, x.filter.sources)), rules)
            if arguments['<protocol>'] is not None:
                rules = filter(lambda x: any(map(lambda y: y == protocol, x.filter.protocols)),
                               rules)
            if arguments['<port>'] is not None:
                rules = filter(lambda x: (port in x.filter.sports) or (port in x.filter.dports),
                               rules)

            if rules:
                print "From %s VLAN %s:" % (rd, vlanid)
                print "lineno  rule"
                linenos = []
                for r in rules:
                    #f = r.filter
                    if r.lineno not in linenos:
                        if 'permit ' not in r.sourceline and 'deny ' not in r.sourceline:
                            info = ' ('+str(r)+')'
                        else:
                            info = ''
                        print '%s\t%s%s' % (r.lineno, r.sourceline.strip(), info)
                        #to prevent same rule printed twice
                        linenos.append(r.lineno)
                print

            #for destination
            rd, vlanid = found_dst[0][0], found_dst[0][1]
            c = metacl.Context(rd, vlanid)
            acl = c.get_acl()
            acl.apply_macros()
            rules = acl.get_rules(ip_versions=list(ip_versions), directions='out')
            #filter rules to match only when source is src_ip
            rules = filter(lambda x: any(map(lambda y: src_ip in y, x.filter.sources)), rules)
            rules = filter(lambda x: any(map(lambda y: dst_ip in y, x.filter.destinations)),
                           rules)
            if arguments['<protocol>'] is not None:
                rules = filter(lambda x: any(map(lambda y: y == protocol, x.filter.protocols)),
                               rules)
            if arguments['<port>'] is not Port:
                rules = filter(lambda x: (port in x.filter.sports) or (port in x.filter.dports),
                               rules)

            if rules:
                print "From %s VLAN %s:" % (rd, vlanid)
                print "lineno  rule"
                linenos = []
                for r in rules:
                    f = r.filter
                    if r.lineno not in linenos:
                        if 'permit ' not in r.sourceline and 'deny ' not in r.sourceline:
                            info = ' ('+str(r)+')'
                        else:
                            info = ''
                        print '%s\t%s%s' % (r.lineno, r.sourceline.strip(), info)
                        #to prevent same rule printed twice
                        linenos.append(r.lineno)

        else:
            log.error('No VLAN found for given source or destination. Aborting.')
            sys.exit(2)

    else:
        log.error('Unrecognized command')
        sys.exit(2)

if __name__ == "__main__":
    try:
        arguments = docopt.docopt(__doc__, version='FAUST 2.0b1 Gold')
        #print arguments
        main(arguments)
    except KeyboardInterrupt:
        log.warning('Aborted by user interaction.')
        sys.exit(2)
