#!/usr/bin/env python

import metacl
from helpers import Trackable, build_alias_list
from ipaddr_ng import IPv4Descriptor, any_
from third_party import ipaddr
import itertools

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class UnresolvableDependencies(Error):
    '''Dependencies couldn't be resolved.'''
    pass

class InvalidMacroArguments(Error):
    '''The macro arguments are malformed or otherwise invalid.'''
    pass

class Macro(Trackable):
    '''Baseclass for macros'''
    
    # List of macros that need to be executed first
    dependencies = []
    
    def __init__(self, argument=''):
        # Can be changed, if not wanted
        self.args = argument.split(' ')
        if len(self.args) == 1 and len(self.args[0]) == 0:
            self.args = []
    
    def call(self, macl):
        # We do nothing here, but this is there a macros
        # can change the macl object
        return macl

class update(Macro):
    '''Allows all IP packets from and to 131.188.12.16/28 and .3.202'''
    def call(self, macl):
        macl.acl_in.insert(0, metacl.Rule.from_string(
            'permit tcp local 131.188.3.202 80', 
            context=macl.context, parent=self, ignore_mismatch=True))
        macl.acl_in.insert(0, metacl.Rule.from_string(
            'permit ip local 131.188.12.16/28', 
            context=macl.context, parent=self, ignore_mismatch=True))
        
        macl.acl_out.insert(0, metacl.Rule.from_string(
            'permit tcp 131.188.3.202 80 local', 
            context=macl.context, parent=self, ignore_mismatch=True))
        macl.acl_out.insert(0, metacl.Rule.from_string(
            'permit ip 131.188.12.16/28 local', 
            context=macl.context, parent=self, ignore_mismatch=True))

class nms(Macro):
    def call(self, macl):
        macl.acl_in.insert(0, metacl.Rule.from_string(
            'permit udp local 131.188.4.0/24 1023-65535', 
            context=macl.context, parent=self))
        macl.acl_in.insert(0, metacl.Rule.from_string(
            'permit icmp local 131.188.4.0/24 echo-reply', 
            context=macl.context, parent=self))
        macl.acl_in.insert(0, metacl.Rule.from_string(
            'permit udp local 10.5.5.0/24 1023-65535', 
            context=macl.context, parent=self))
        macl.acl_in.insert(0, metacl.Rule.from_string(
            'permit tcp local 10.5.5.0/24 established', 
            context=macl.context, parent=self))
        macl.acl_in.insert(0, metacl.Rule.from_string(
            'permit icmp local 10.5.5.0/24 echo-reply', 
            context=macl.context, parent=self))
        macl.acl_in.insert(0, metacl.Rule.from_string(
            'permit ip local 131.188.4.20', 
            context=macl.context, parent=self))
        macl.acl_in.insert(0, metacl.Rule.from_string(
            'permit ip local 131.188.4.11', 
            context=macl.context, parent=self))
        
        macl.acl_out.insert(0, metacl.Rule.from_string(
            'permit udp 131.188.4.0/24 local 161', 
            context=macl.context, parent=self))
        macl.acl_out.insert(0, metacl.Rule.from_string(
            'permit icmp 131.188.4.0/24 local echo', 
            context=macl.context, parent=self))
        macl.acl_out.insert(0, metacl.Rule.from_string(
            'permit udp 10.5.5.0/24 local 161', 
            context=macl.context, parent=self))
        macl.acl_out.insert(0, metacl.Rule.from_string(
            'permit tcp 10.5.5.0/24 local 22', 
            context=macl.context, parent=self))
        macl.acl_out.insert(0, metacl.Rule.from_string(
            'permit tcp 10.5.5.0/24 local 23', 
            context=macl.context, parent=self))
        macl.acl_out.insert(0, metacl.Rule.from_string(
            'permit icmp 10.5.5.0/24 local echo', 
            context=macl.context, parent=self))
        macl.acl_out.insert(0, metacl.Rule.from_string(
            'permit ip 131.188.4.20 local', 
            context=macl.context, parent=self))
        macl.acl_out.insert(0, metacl.Rule.from_string(
            'permit ip 131.188.4.11 local', 
            context=macl.context, parent=self))
    
class antiSpoof(Macro):
    '''Denies packets from "the outside" with local IPs and vice versa.'''
    def call(self, macl):
        local = macl.context.get_alias('local')
        
        macl.acl_in.insert(0, metacl.Rule.from_string(
            'deny ip any local', context=macl.context, parent=self))
        
        macl.acl_out.insert(0, metacl.Rule.from_string(
            'deny ip local any', context=macl.context, parent=self))

class broadcast(Macro):
    '''Denies IPv4 broadcast packets to pass through the router.'''

    def call(self, macl):
        bc = IPv4Descriptor('255.255.255.255')+\
            map(lambda x: ipaddr.IPNetwork(x.broadcast), macl.context.get_alias('local', ip_versions='ipv4'))

        macl.acl_in.insert(0,metacl.Rule('deny', 
            metacl.Filter(['ip'], 
                macl.context.get_alias('any', ip_versions='ipv4'), 
                bc, 
                parent=self), parent=self))

        macl.acl_out.insert(0,metacl.Rule('deny', 
            metacl.Filter(['ip'], 
                macl.context.get_alias('any', ip_versions='ipv4'), 
                bc,
                parent=self), parent=self))

class lan(Macro):
    def call(self, macl):
        if 'ipv6' in macl.context.ip_versions:
            local6 = macl.context.get_alias('local', ip_versions='ipv6')[0]
            first = [ipaddr.IPNetwork(local6[1]), ipaddr.IPNetwork(local6[2])]

            macl.acl_out.insert(0, metacl.Rule.from_string('permit ip any fe80::/10', context=macl.context, parent=self))
            macl.acl_in.insert(0, metacl.Rule.from_string('permit ip fe80::/10 any', context=macl.context, parent=self))
            macl.acl_in.insert(1, metacl.Rule.from_string('permit ip local fe80::/10', context=macl.context, parent=self))
            macl.acl_in.insert(2, metacl.Rule('permit',
               metacl.Filter(['icmp'],
                   macl.context.get_alias('local'),
                   first,
                   parent=self), parent=self))

        if 'ipv4' in macl.context.ip_versions:
            local = macl.context.get_alias('local', ip_versions='ipv4')[0]
            first = [ipaddr.IPNetwork(local[1])]
            last = [ipaddr.IPNetwork(local[-3]), ipaddr.IPNetwork(local[-2])]
            temp_aliases = {'first': first, 'last': last, 'firstlast': first+last}
            
            # Rules to be inserted at top of IN list:
            rules_in = [
                'permit ip $firstlast 224.0.0.1', 
                'permit udp $firstlast 1985 224.0.0.2 1985',
                'permit udp $firstlast 1985 224.0.0.102 1985', 
                'permit ip $firstlast 224.0.0.13',
                'permit tcp local $firstlast established',
                'permit icmp local $firstlast', 
                'permit udp local $ntp_server 123',
                'permit udp local $first 123', 
                'deny ip any $firstlast', 
            ]
            
            # We have to reverse the order, since insertion will be done at beginning of list
            rules_in.reverse()
            # Injecting rules into acl_in
            for r in rules_in:
                macl.acl_in.insert(0, metacl.Rule.from_string(
                    r, 
                    context=macl.context, temp_aliases=temp_aliases, parent=self))
            
            
            # Rules to be inserted at top of OUT list:
            rules_out = [
                'permit ip $firstlast local', 
                'permit icmp local $firstlast', 
                'permit udp $ntp_server 123 local',
                'permit ip any 224.0.0.0/4',
            ]
            
            # We have to reverse the order, since insertion will be done at beginning of list
            rules_out.reverse()
            # Injecting rules into acl_out
            for r in rules_out:
                macl.acl_out.insert(0, metacl.Rule.from_string(
                    r, 
                    context=macl.context, temp_aliases=temp_aliases, parent=self))

class dhcp6(Macro):
    def call(self, macl):
        local6 = macl.context.get_alias('local', ip_versions='ipv6')[0]
        first = [ipaddr.IPNetwork(local6[1]), ipaddr.IPNetwork(local6[2])]
 
        macl.acl_in.insert(0,metacl.Rule('permit', 
            metacl.Filter(['udp'], 
                macl.context.get_alias('local'), 
                first, 
                dports=metacl.Ports.from_string('546,547'),
                parent=self), parent=self))
 
class dhcp(Macro):
    '''Allows DHCP broadcasts to DHCP servers:
    arguments can be 'linux', 'solaris', 'rrze' or an ip address of a dhcp server
    Can also be a space seperated list, to allow more then one class/ip, or empty.
    If empty all DHCP classes (linux, solaris, rrze) are allowed.'''

    dependencies = [broadcast, lan]
    
    dhcp_classes = {
        'rrze':
            '10.188.12.19;10.188.12.27',
        'linux':
            '131.188.3.145', 
        'solaris':
            '131.188.3.89', 
        'mac':
            '131.188.3.117'
    }

    def call(self, macl):
        local = macl.context.get_alias('local', ip_versions='ipv4')[0]
        first = [ipaddr.IPNetwork(local[1])]
        last = [ipaddr.IPNetwork(local[-3]), ipaddr.IPNetwork(local[-2])]
        routers = first+last

        if len(self.args) > 0:
            dhcp_servers = [self.dhcp_classes[i] for i in self.args if self.dhcp_classes.has_key(i)]
            # everything else will be interpreted as ip-address for a dhcp-server
            dhcp_servers += [i for i in self.args if not self.dhcp_classes.has_key(i)]
        else:
            dhcp_servers = [self.dhcp_classes[i] for i in self.dhcp_classes]

        temp_aliases = {'dhcp': build_alias_list(dhcp_servers), 'routers': routers}

        acl_in = []
        acl_in.append(metacl.Rule.from_string( \
            'permit udp 0.0.0.0 68 255.255.255.255 67', parent=self))
        acl_in.append(metacl.Rule.from_string( \
            'permit udp local 68 255.255.255.255 67', parent=self, \
            context=macl.context))
     
        acl_in.append(metacl.Rule.from_string('permit udp local 68 $dhcp 67', 
            temp_aliases=temp_aliases, context=macl.context, parent=self))
        
        # Peer-link / Nexus dhcp-relay workaround
        # dhcp-server zum relay bleibt an der in-liste haengen wenn das
        # Paket ueber den peer-link kommt (weil schon geroutet)
        # Und: Selbst lokale DHCP-Server muessen als RELAY eingetragen sein,
        # (das system Filter bootps/bootpc-pakete innerhalb des LANs per VACL raus)
        # Damits per RELAY funktioniert, muss aber der lokale server den Router
        # erreichen (d.h. server(bootps) --> router(bootps) )
        acl_in.append(metacl.Rule.from_string('permit udp $dhcp $routers 67', 
            temp_aliases=temp_aliases, context=macl.context, parent=self))

        macl.acl_in = acl_in + macl.acl_in

        acl_out = []
        #out 'permit udp $ROUTERS 67 255.255.255.255 68',
        acl_out.append(metacl.Rule.from_string('permit udp $routers 67 255.255.255.255 68', 
            temp_aliases=temp_aliases, context=macl.context, parent=self))
        #out 'permit udp $ROUTERS eq 67 local 68',
        acl_out.append(metacl.Rule.from_string('permit udp $routers 67 local 68', 
            temp_aliases=temp_aliases, context=macl.context, parent=self))

        #out 'permit udp $DHCP_SERVERS local 68'  
        acl_out.append(metacl.Rule.from_string('permit udp $dhcp local 68', 
            temp_aliases=temp_aliases, context=macl.context, parent=self))
        #out 'permit udp $DHCP_SERVERS $ROUTERS 67'  
        acl_out.append(metacl.Rule.from_string('permit udp $dhcp $routers 67',
            temp_aliases=temp_aliases, context=macl.context, parent=self))
            
        macl.acl_out = acl_out + macl.acl_out

class domain(Macro):
    '''Deprecated! Use dns() instead'''
    '''Grants access to the DNS servers, with 'old' set as *argument* also to 
    old DNS Servers.'''
    dns_servers = ['131.188.0.10', '131.188.0.11']
    dns_servers_old = [ '131.188.3.72', '131.188.3.73', '131.188.2.103', 
                        '131.188.2.104' ]
    
    def call(self, macl):
        in_acl = []
        out_acl = []

        for ip in [self.dns_servers, self.dns_servers+self.dns_servers_old][self.args == ['old']]:
            in_acl.append(metacl.Rule('permit', 
                metacl.Filter(['tcp','udp'], 
                    macl.context.get_alias('local'), 
                    IPv4Descriptor(ip), 
                    dports=metacl.Ports.from_string('53'), parent=self), parent=self))
            
            out_acl.append(metacl.Rule('permit', 
                metacl.Filter(['tcp','udp'], 
                    IPv4Descriptor(ip), 
                    macl.context.get_alias('local'), 
                    sports=metacl.Ports.from_string('53'), parent=self), parent=self))
        
        macl.acl_in = in_acl + macl.acl_in
        macl.acl_out = out_acl + macl.acl_out

        return macl

class dns(Macro):
    '''Grants access to the DNS servers, with 'old' set as *argument* also to
    old DNS Servers.'''

    dns_servers_old = [ '131.188.3.72', '131.188.3.73', '131.188.2.103', 
                        '131.188.2.104' ]

    def call(self, macl):
        if self.args == ['old']:
            for ip in self.dns_servers_old:
                macl.acl_in.insert(0,metacl.Rule('permit',
                    metacl.Filter(['tcp','udp'], 
                        macl.context.get_alias('local'), 
                        IPv4Descriptor(ip), 
                        dports=metacl.Ports.from_string('53'), parent=self), parent=self))

                macl.acl_out.insert(0,metacl.Rule('permit',
                    metacl.Filter(['tcp','udp'], 
                        IPv4Descriptor(ip), 
                        macl.context.get_alias('local'), 
                        sports=metacl.Ports.from_string('53'), parent=self), parent=self))

        macl.acl_in.insert(0,metacl.Rule('permit',
            metacl.Filter(['tcp','udp'],
                macl.context.get_alias('local'),
                macl.context.get_alias('dns_server'),
                dports=metacl.Ports.from_string('53'), parent=self), parent=self))

        macl.acl_out.insert(0,metacl.Rule('permit',
            metacl.Filter(['tcp','udp'],
                macl.context.get_alias('dns_server'),
                macl.context.get_alias('local'),
                sports=metacl.Ports.from_string('53'), parent=self), parent=self))

class wlan(Macro):
    # opens local lan to wlan-controller
    def call(self, macl):
        local = macl.context.get_alias('local', ip_versions='ipv4')[0]

        macl.acl_in.insert(0, metacl.Rule.from_string('permit ip local $wlancontroller', 
            context=macl.context, parent=self))

        macl.acl_out.insert(0, metacl.Rule('permit ip $wlancontroller local', 
            context=macl.context, parent=self))


class netbackup(Macro):
    '''Opens net or hosts to netBackup server (defined with $netbackup alias)
    
    Usage: netbackup() opens complete network
           netbackup(ip ip ...) opens ip's to netbackup'''
    def call(self, macl):
        if len(self.args) == 0:
            # Open whole net to netbackup
            macl.acl_in.insert(0, metacl.Rule.from_string(
                'permit tcp local 13782 $netbackup established', 
                context=macl.context, parent=self))

            macl.acl_in.insert(0, metacl.Rule.from_string(
                'permit tcp local $netbackup 13782', 
                context=macl.context, parent=self))

            macl.acl_in.insert(0, metacl.Rule.from_string(
                'permit tcp local $netbackup 13724', 
                context=macl.context, parent=self))

            macl.acl_in.insert(0, metacl.Rule.from_string(
                'permit tcp local $netbackup 13720', 
                context=macl.context, parent=self))

            macl.acl_out.insert(0, metacl.Rule.from_string(
                'permit tcp $netbackup 13782 local established', 
                context=macl.context, parent=self))

            macl.acl_out.insert(0, metacl.Rule.from_string(
                'permit tcp $netbackup 13724 local established', 
                context=macl.context, parent=self))

            macl.acl_out.insert(0, metacl.Rule.from_string(
                'permit tcp $netbackup 13720 local established', 
                context=macl.context, parent=self))

            macl.acl_out.insert(0, metacl.Rule.from_string(
                'permit tcp $netbackup local 13782', 
                context=macl.context, parent=self))

        else:
            for h in self.args:
                # Open only given hosts to netbackup
                h = metacl.string_to_ips(h, context=macl.context)
                
                macl.acl_in.insert(0, metacl.Rule('permit', 
                    metacl.Filter(['tcp'], 
                    h, 
                    macl.context.get_alias('netbackup'), 
                    sports=metacl.Ports.from_string('13782'),
                    parent=self), extensions=['established'], parent=self))
                
                macl.acl_in.insert(0, metacl.Rule('permit', 
                    metacl.Filter(['tcp'], 
                    h, 
                    macl.context.get_alias('netbackup'), 
                    dports=metacl.Ports.from_string('13720,13724,13782'),
                    parent=self), parent=self))
                
                macl.acl_out.insert(0, metacl.Rule('permit', 
                    metacl.Filter(['tcp'], 
                    macl.context.get_alias('netbackup'), 
                    h, 
                    sports=metacl.Ports.from_string('13720,13724,13782'),
                    parent=self), extensions=['established'], parent=self))
                
                macl.acl_out.insert(0, metacl.Rule('permit', 
                    metacl.Filter(['tcp'], 
                    macl.context.get_alias('netbackup'), 
                    h,
                    dports=metacl.Ports.from_string('13782'),
                    parent=self), parent=self))


class faucam(Macro):

    '''Opens net or hosts to faucam server (defined with $faucam alias) and
    blocks everything else

    Usage: faucam() n/a
           faucam(ip ip ...) opens ip's to faucam'''
    def call(self, macl):
#        if len(self.args) == 0:
        for h in self.args:
            # Open only given hosts to nagios
            h = metacl.string_to_ips(h, context=macl.context)

            macl.acl_in.insert(0, metacl.Rule('permit',
                metacl.Filter(['ip'],
                h,
                macl.context.get_alias('faucam'),
                parent=self), parent=self))
                #'permit ip '+h+' $faucam', context=macl.context, parent=self))
            macl.acl_in.insert(1, metacl.Rule('deny',
                metacl.Filter(['ip'],
                h,
                macl.context.get_alias('any'),
                parent=self), parent=self))
                #'deny ip '+h+' $any', context=macl.context, parent=self))

            macl.acl_out.insert(0, metacl.Rule('permit',
                metacl.Filter(['ip'],
                macl.context.get_alias('faucam'),
                h,
                parent=self), parent=self))
            macl.acl_out.insert(1, metacl.Rule('deny',
                metacl.Filter(['ip'],
                macl.context.get_alias('any'),
                h,
                parent=self), parent=self))


class nagios(Macro):
    '''Opens net or hosts to nagios server (defined with $nagios alias)
    
    Usage: nagios() opens complete network
           nagios(ip ip ...) opens ip's to nagios'''

    dependencies = [faucam]

    def call(self, macl):
        if len(self.args) == 0:
            # Open whole net to nagios
            macl.acl_in.insert(0, metacl.Rule.from_string(
                'permit icmp,tcp,udp local $nagios', context=macl.context, parent=self))

            macl.acl_out.insert(0, metacl.Rule.from_string(
                'permit icmp,tcp,udp $nagios local', context=macl.context, parent=self))
        else:
            for h in self.args:
                # Open only given hosts to nagios
                h = metacl.string_to_ips(h, context=macl.context)
                
                macl.acl_in.insert(0, metacl.Rule('permit', 
                    metacl.Filter(['icmp','tcp','udp'], 
                    h, 
                    macl.context.get_alias('nagios'), 
                    parent=self), parent=self))
                    #'permit icmp,tcp,udp '+h+' $nagios', context=macl.context, parent=self))

                macl.acl_out.insert(0, metacl.Rule('permit', 
                    metacl.Filter(['icmp','tcp','udp'], 
                    macl.context.get_alias('nagios'), 
                    h,
                    parent=self), parent=self))


class block(Macro):
    dependencies = [nagios, lan, dns, domain, dhcp, broadcast, update, nms, faucam]

    def call(self, macl):
        local = macl.context.get_alias('local')
        x = map(lambda x: metacl.string_to_ips(x, context=macl.context), self.args)
        ips = list(itertools.chain(*x))

        macl.acl_out.insert(0,metacl.Rule('deny',
            metacl.Filter(['ip'],
                macl.context.get_alias('any'),
                ips,
                parent=self), parent=self))

        macl.acl_in.insert(0,metacl.Rule('deny',
            metacl.Filter(['ip'],
                ips,
                macl.context.get_alias('any'),
                parent=self), parent=self))
