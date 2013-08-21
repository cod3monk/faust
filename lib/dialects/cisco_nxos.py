#!/usr/bin/env python

from lib import ipaddr_ng
from lib.ipaddr_ng import IPv4Descriptor
from lib.third_party.ipaddr import IPv4Network, IPv6Network, AddressValueError
from lib.third_party.ipaddr import NetmaskValueError
import datetime
import string
import time
from lib.third_party import pxssh, pxscp, memorization, lockfile
import sys
import logging
import re
from lib import metacl
import atexit
import lib
import generic
import random
log = logging.getLogger(__name__)

class Error(generic.Error):
    """Base class for exceptions in this module."""
    pass

class InterfaceNotConfigured(Error):
    """Interface configuration could not be read from router"""
    pass

class ErrorMessageRecived(Error):
    """Command produced an error message"""
    pass

class ErrorTimeout(Error):
    """Command execution timeouted"""
    pass

class ErrorNotConnected(Error):
    """No connection to router exists"""
    pass

@memorization.Memorize
def get_service_dictionary():
    # Build service dictionary cisco output notation (53 = domain)
    f = open(lib.config.get('global','services_file'))
    services = f.readlines()
    f.close()
    prog = re.compile(r"^([a-z0-9\-]+)\s+([0-9]+)/(tcp|udp).*")
    services = map(lambda x: prog.match(x), services)
    # remove unmatched lines
    services = filter(lambda x: x is not None, services)
    # retrieve matched groups (name, port, protocol)
    services = map(lambda x: x.groups(), services)
    # make dict out of list, with format: servicename: port
    services = dict(map(lambda x: [x[0], x[1]], services))

    return services

def replace_ianaports(l):
    '''Takes cisco acls as argument *l* and replaces all IANA port names with it's corresponding 
    numbers.

    Returns the same ACL with numbers instead of port names'''
    services = get_service_dictionary()

    # Replace IANA port names with number values
    for oldportfilter in  re.findall(
        r'''(?:lt|eq) [a-z]+|range (?:[a-z]+ [a-z]+|\d+ [a-z]+|[a-z]+ \d)''', l):
        newportfilter = oldportfilter.split(' ')
        if newportfilter[0] == 'range':
            # we have two operands (e.g. range ssh ntp), but one of them could
            # already be a number (e.g. range ssh 1024 or range 22 http)
            opcount = 2
        else: # f[0] is 'eq', 'gt' or 'lt'
            # Only one operand
            opcount = 1

        # For each operand...
        for i in range(opcount):
            try:
                # i+1 because we ignore the first element (which is one of:
                # ['range', 'eq', 'lt', 'gt'])
                int(newportfilter[i+1])
            except:
                newportfilter[i+1] = services[newportfilter[i+1]]

        # replace l with the newly numbered version:
        l = l.replace(oldportfilter, ' '.join(newportfilter))
    return l

def compile_all(acl, name, timestamp=True):
    '''Takes a :class:`faust2.lib.metacl.ACL` object and returns a cisco ACL string'''
    
    if acl.context == None:
        raise Error('MetaACL object needs context, to be compiled to a Cisco ACL')
    
    acl_string = []
    
    acl_string += map(lambda x: '\n'.join(x), compile_one(acl, name, 'in', 'ipv4', timestamp=timestamp, comments=True))
    acl_string += map(lambda x: '\n'.join(x), compile_one(acl, name, 'out', 'ipv4', timestamp=timestamp, comments=True))
    if 'ipv6' in acl.context.ip_versions:
        acl_string += map(lambda x: '\n'.join(x), compile_one(acl, name, 'in', 'ipv6', timestamp=timestamp, comments=True))
        acl_string += map(lambda x: '\n'.join(x), compile_one(acl, name, 'out', 'ipv6', timestamp=timestamp, comments=True))
    
    return '\n'.join(acl_string)

def compile_one(acl, name, direction, ip_version, timestamp=True, comments=True):
    '''Takes a :class:`faust2.lib.metacl.ACL` object
    
    Returns a tuple containg cisco ACL strings, in format:
    (header, rules, footer)
    can be copy-pasted if concatinated by \\n'''
    
    if not acl.context:
        raise metacl.NeedsContext('Can only be compiled with a context set!')
    
    assert ip_version in metacl.ip_versions, \
        'Protocol has to be either '+str(metacl.ip_versions)
    assert direction in metacl.directions, \
        'Direction has to be one of '+str(metacl.directions)
    
    if ip_version == 'ipv6' and 'ipv6' not in acl.context.ip_versions:
        raise 'Requested ipv6, but acl does not support ipv6.'
    
    header,body,footer = [],[],[]
    
    now = str(datetime.datetime.now())
    
    # Get the Rules
    l = acl.get_rules(direction, ip_version)
    
    # Headers for removing and creating ACL on cisco
    if ip_version == 'ipv4':
        header.append('no ip access-list '+name+'_'+direction.upper())
        header.append('ip access-list '+name+'_'+direction.upper())
    elif ip_version == 'ipv6':
        header.append('no ipv6 access-list '+name+'_'+direction.upper()+'6')
        header.append('ipv6 access-list '+name+'_'+direction.upper()+'6')
    
    if comments:
        if timestamp:
            body.append('remark FAUSt2 ACL generated from '+acl.origin()+' on '+now)
        else:
            body.append('remark FAUSt2 ACL generated from '+acl.origin())
    
    # Reduces remark spamming, by eliminating redundant remarks
    oldorigin = None
    
    # For each Rule
    for r in l:
        # Comment if not already used
        if r.origin() != oldorigin and comments:
            body.append('remark FAUSt2 metacl from '+r.origin())
            oldorigin = r.origin()
        
        # Append cisco acl string
        if ip_version == 'ipv4':
            body += rule_to_acl_ipv4_string(r)
        else:
            body += rule_to_acl_ipv6_string(r)
    
    return header, body, footer

def get_acl_name(routingdomain, vlanid, variant=0):
    '''Returns in and out acl name possibilities'''

    if variant == 0:
        return {'ipv4': {'in': routingdomain+vlanid+'_IN', 
                         'out': routingdomain+vlanid+'_OUT'},
                'ipv6': {'in': routingdomain+vlanid+'_IN6', 
                         'out': routingdomain+vlanid+'_OUT6'}}
    elif variant == 1:
        return {'ipv4': {'in': routingdomain+vlanid+'_in', 
                         'out': routingdomain+vlanid+'_out'},
                'ipv6': {'in': routingdomain+vlanid+'_in6', 
                         'out': routingdomain+vlanid+'_out6'}}
    else:
        randstr = ''.join(random.choice(string.ascii_uppercase) for x in range(3))
        return {'ipv4': {'in': routingdomain+vlanid+'_IN_'+randstr, 
                         'out': routingdomain+vlanid+'_OUT_'+randstr},
                'ipv6': {'in': routingdomain+vlanid+'_IN6_'+randstr, 
                         'out': routingdomain+vlanid+'_OUT6_'+randstr}}

def ip_to_acl_string(ip):
    '''Takes an ipaddr object *ip* and returns cisco acl description'''
    
    if ip in ipaddr_ng.any_:
        return 'any'
    
    if type(ip) is IPv4Network:
        return str(ip.with_prefixlen)
    else:
        return str(ip)

def ports_to_acl_string(ports):
    '''Takes a list of ports and returns a list of cisco acl descriptions'''
    
    if not ports:
        return ['']
    l = []
    for p in ports:
        if p[0] == 'eq':
            l.append(' eq '+str(p[1]))
        elif p[0] == 'range':
            l.append(' range '+str(p[1][0])+' '+str(p[1][1]))
    return l

def rule_to_acl_ipv4_string(self):
    '''Returns a list of strings in cisco acl syntax'''
    acl = []
    # TODO: sort extension
    if len(self.extensions) == 0:
        ext = ''
    else:
        ext = ' '.join(self.extensions)

    for f in filter_to_acl_ipv4_string(self.filter):
        acl.append(
        ' '.join(map(str,[self.action, f, ext])).strip())
    return acl

def rule_to_acl_ipv6_string(self):
    '''Returns a list of strings in cisco acl syntax'''
    acl = []
    # TODO: sort extension
    if len(self.extensions) == 0:
        ext = ''
    else:
        # TODO: sort extension
        if len(self.extensions) == 0:
            ext = ''
        else:
            ext = ''
            for e in self.extensions:
                # IPv6 uses 'echo-request' instead of 'echo'
                if e == 'echo':
                    ext += ' echo-request'
                else:
                    ext += e

    for f in filter_to_acl_ipv6_string(self.filter):
        acl.append(
        ' '.join(map(str,[self.action, f, ext])).strip())
    return acl

def filter_to_acl_ipv4_string(self):
    '''Returns a list with IPv4 filters in cisco acl syntax'''
    
    f = []
    
    for p in self.protocols:
        for s in filter( lambda x: type(x) == IPv4Network, self.sources):
            if s in ipaddr_ng.any_:
                s = 'any'
            else:
                s = ip_to_acl_string(s)
        
            for d in filter( lambda x: type(x) == IPv4Network, self.destinations):
                d = ip_to_acl_string(d)
                
                for sp in ports_to_acl_string(self.sports):
                    for dp in ports_to_acl_string(self.dports):
                            f.append(p+' '+str(s)+sp+' '+str(d)+dp)
    
    return f

def filter_to_acl_ipv6_string(self):
    '''Returns a list with IPv6 filters in cisco acl syntax'''
    
    f = []

    for p in self.protocols:
        # cisco seems to use ipv6 instead of ip for ipv6 rules
        # works with ip aswell, but to look more similar:
        if p == 'ip':
            p = 'ipv6'
        
        for s in filter( lambda x: type(x) == IPv6Network, self.sources):
            if s in ipaddr_ng.any_:
                s = 'any'
            else:
                s = ip_to_acl_string(s)

            for d in filter( lambda x: type(x) == IPv6Network, self.destinations):
                d = ip_to_acl_string(d)

                for sp in ports_to_acl_string(self.sports):
                    for dp in ports_to_acl_string(self.dports):
                            f.append(p+' '+str(s)+sp+' '+str(d)+dp)

    return f

def install(self, timestamp=True):
    '''Installs ACL object *self* to router(s).'''

    vlanid = self.context.vlanid
    routingdomain = self.context.routingdomain
    ifaces = self.context.interfaces
    
    lock = lockfile.Lock(lib.config.get('global','policies_dir')+'/'+routingdomain+'/lock')
    log.info("Aquiring lock...")
    lock.lock()
    log.debug("Lock aquired.")

    # Compiling each direction and IP version
    newacl_rules = {'ipv4': {'in': None, 'out': None},
                    'ipv6': {'in': None, 'out': None}}
    
    for v in self.context.ip_versions:
        for d in metacl.directions:
            # Name can be anything, since the header will be ignored
            header, newacl_rules[v][d], footer = compile_one(self, \
                name='TEMP', direction=d, ip_version=v, \
                timestamp=timestamp)

    for router in self.context.get_router_connections():
        # Get ACLs which are bound to interface (oldacl)
        oldacl_names = router.get_bound_acl_form_interface(ifaces[router.name])

        # Construct new (unique) ACL names to be used for new ACLs
        i = 0
        newacl_names = get_acl_name(routingdomain, vlanid, variant=i)
        while oldacl_names['ipv4']['in'] == newacl_names['ipv4']['in'] or \
              oldacl_names['ipv4']['out'] == newacl_names['ipv4']['out'] or \
              oldacl_names['ipv6']['in'] == newacl_names['ipv6']['in'] or \
              oldacl_names['ipv6']['out'] == newacl_names['ipv6']['out']:
            i += 1
            newacl_names = get_acl_name(routingdomain, vlanid, variant=i)
        
        # Upload new ACLs via SSH SCP:
        import tempfile, os, sys
        f = tempfile.NamedTemporaryFile()
        
        if 'ipv4' in self.context.ip_versions:
            f.write('no ip access-list '+newacl_names['ipv4']['in']+'\n')
            f.write('ip access-list '+newacl_names['ipv4']['in']+'\n')
            f.write('\n'.join(newacl_rules['ipv4']['in'])+'\n')
            f.write('no ip access-list '+newacl_names['ipv4']['out']+'\n')
            f.write('ip access-list '+newacl_names['ipv4']['out']+'\n')
            f.write('\n'.join(newacl_rules['ipv4']['out']))
            f.write('\n')
            
        if 'ipv6' in self.context.ip_versions:
            f.write('no ipv6 access-list '+newacl_names['ipv6']['in']+'\n')
            f.write('ipv6 access-list '+newacl_names['ipv6']['in']+'\n')
            f.write('\n'.join(newacl_rules['ipv6']['in'])+'\n')
            f.write('no ipv6 access-list '+newacl_names['ipv6']['out']+'\n')
            f.write('ipv6 access-list '+newacl_names['ipv6']['out']+'\n')
            f.write('\n'.join(newacl_rules['ipv6']['out']))
            f.write('\n')
        f.flush()

        temp_acl_file_on_router = 'tmp'+routingdomain+vlanid
        
        # Copy file via scp onto router
        if not pxscp.pxscp(src_path=f.name, dst_username=router._username, dst_server=router.hostname, 
            dst_path=temp_acl_file_on_router, password=router._password):
            raise Error('SCP Copy failed! Squeeze might be required on router.')
        
        # Copy file into running-config
        router.execute('copy '+temp_acl_file_on_router+' running-config', 
            ignore=['ACL with given name and type does not exist'])

        # Delete file from router
        router.delete(temp_acl_file_on_router)
        
        # If an error occures, it will raise an exception and not continue
        # with the installation

        # Now that the upload is complete, we will bind the new ACLs to the
        # Vlan interface:
        for v in self.context.ip_versions:
            router.bind_acl_to_interface(ifaces[router.name], newacl_names[v]['in'], 
                newacl_names[v]['out'], ip_version=v)

            # Remove old ACLs if they exist
            if oldacl_names[v]['in'] and oldacl_names[v]['out']:
                router.remove_acl(oldacl_names[v]['in'], ip_version=v)
                router.remove_acl(oldacl_names[v]['out'], ip_version=v)

        log.info('Sucessfuly updated and bound ACLs for VLAN %s on %s' % \
            (vlanid, router.name))
    
    lock.unlock()

class Router(generic.Router):
    """This class abstracts the interaction with the router and aims at
    providing a fault-tollerant way of changing acls and related 
    configurations.
    
    It uses the 'Borg design pattern' to create only one connection per 
    Router."""
    
    __shared_states = {}  # global storage of states (per hostname)
    
    def __init__(self, hostname, *args, **kwargs):
        '''This makes sure, that for each *hostname* only one object exists.
        If another object for the same hostname ist requested, it will return
        an object with the same state as the one created before.
        
        See Borg Design Pattern.'''
        
        if self.__shared_states.has_key(hostname):
            self.__dict__ = self.__shared_states[hostname]
        else:
            self.__shared_states[hostname] = {
                '_client': None,
                '_running': None
            }
            self.__dict__ = self.__shared_states[hostname]
            self._connect(hostname, *args, **kwargs)
    
    def _connect(self, hostname, username, password, port = 22, 
        read_running_config_first=False, name=None):
        """Sets basic information necessasery to connect to router and
        connects."""
        self.hostname = hostname
        self._port = port
        self._username = username
        self._password = password
        if not name:
            self.name = hostname
        else:
            self.name = name

        log.info('Connecting to %s...' % name)
        
        try:                                                            
            self._client = pxssh.pxssh()#logfile=sys.stderr)
            self._client.PROMPT = r'[a-zA-Z0-9\(\)\-]*#'
            self._client.login(hostname, username, password, 
                auto_prompt_reset=False)
        except pxssh.ExceptionPxssh, e:
            self._client = None
            raise Error("SSH login failed: "+str(e))
        except pxssh.pexpect.EOF, e:
            self._client = None
            raise Error("Process terminated unexpectatly. Possible " + \
                "problems maybe a changed host key, lost connection or " + \
                "more? Try to connect via SSH directly.")
        
        log.debug('Connected to %s' % name)
        
        self.execute('term len 0') # disable paging
        #self.execute('term width 0')
        
        # Readout running config and store for future use
        if read_running_config_first:
            self._running = self.execute('sh run')
        else:
            self._running = None

    #TODO this is fracking dum, please get it sorted out!
    def execute(self, command, input=None, error=True, ignore=[]):
        """Executes *command* on router and appends *input*.
        
        *input* may be an string, with each line containing one command or
        a list, with each entry containing one command.
        
        If *error* is set to true, all responses will be checked for errror
        messages (lines starting with ' %'). The function will wait until
        a line ending with '#' is found, signaling a successfull execution.
        
        *ignore* may contain a list of error messages that will be ignored.
        For example: ['Access list not found']"""
        
        if not self._client:
            raise ErrorNotConnected("No router connection available")
        
        if input:
            log.debug('To %s: %s\n%s' % (self.name, command, input))
        else:
            log.debug('To %s: %s' % (self.name, command))
        
        try:
            # We remove leading or trailing whitespaces and \n as this fucks 
            # up the prompt finder (downward compatability)
            command = command.strip()
            assert len(command.split('\n')) == 1, \
                "Commands may only be one line long!"
            
            self._client.sendline(command)
            if not self._client.prompt(timeout=300):
                raise ErrorTimeout("Execution of comamnd and input '"+command+"\n"+input+ \
                    "' timeouted after 5 minutes.")
            
            if type(input) is str:
                input = input.split('\n')
            if input:
                for l in input:
                    self._client.sendline(l)
                    if not self._client.prompt(timeout=300):
                        raise ErrorTimeout("Execution of comamnd and input '"+command+"\n"+input+ \
                            "' timeouted after 5 minutes.")
            out = ''
            
            log.debug(self._client.before)
        
            out = self._client.before
            out = out.split('\r\n')[:-1]
        
            # all([]) -> True, so we need to exclude len(...) -> 0 from raising an 
            # AssertionError
            if len(out) > 0 and error:
                error_lines = filter((lambda x: x.strip().startswith('ERROR: ') and 
                not x[7:] in ignore) or (lambda x: x.strip().startswith('% ') and 
                not x[2:] in ignore), out)
                if error_lines:
                    log.error('Errors from %s: %s' % (self.name, error_lines))
                    raise ErrorMessageRecived("Command "+command+" produced the following error: "+ \
                        ' '.join(error_lines))
            
            log.debug('From %s: %s' % (self.name, out))
        
            return out
        except pxssh.ExceptionPxssh, e:
            raise Error("SSH timeout while executing: '"+command+"' on "+ \
                self.name)
    
    def check_acl_name(self, name):
        """Checks if *name* is a valid name for cisco acls."""
        
        assert ' ' not in name, "Spaces may not be part of an acl name"
        assert '"' not in name and "'" not in name, \
            "Quotationmarks may not be part of an acl name"
        assert name[0] in string.letters, \
            "Acl name must start with alphabetic character"
    
    def read_acl(self, name, ip_version='ipv4'):
        """Reads acl *name* from router and returns String with commands.
        Remarks are not included and IANA port names are replaced by it's
        number values.
        
        By default ipv4 acls are retrieved, if *ip_version* is set to 'ipv6' ipv6 acls
        will be retrieved."""
        
        assert ip_version in metacl.ip_versions, ip_version+" is unsupported"
        self.check_acl_name(name)
        
        if self._running:
            # a running config was retrieved, thus no commands have to be executed
            acl = []

            in_acl = False
            for l in self._running:
                if ip_version == 'ipv4' and l == "ip access-list "+name or \
                   ip_version == 'ipv6' and l == "ipv6 access-list "+name:
                    in_acl = True
                elif len(l)>0 and l[0] != " ":
                    in_acl = False
                if in_acl:
                    l = l.strip()
                    l = l.lstrip(string.digits).strip()
                    # l.startswith('remark') we do not want remarks
                    if l.startswith('permit') or l.startswith('deny'):
                        # removing extra (unneeded) whitespaces
                        l = re.sub('\s+', ' ', l) 
                        
                        # Find and replace IANA portnames with their numbers:
                        l = replace_ianaports(l)
                        
                        acl.append(l)
                        
            return '\n'.join(acl)
        else:
            if not self._client:
                raise ErrorNotConnected("No router connection available")
            
            if ip_version == 'ipv4':
                response = self.execute('show access-list '+name)
            elif ip_version == 'ipv6':
                response = self.execute('show ipv6 access-list '+name)
            
            # Let us see if acl exists... if not -> exception
            assert filter(lambda x: len(x), response[1:]), "ACL "+name+" does not exists"
        
            # Reduce rules to the actual rule, by removing leading indices and 
            # following (123 matches)
            response = map(lambda x: x.strip().lstrip(string.digits).strip(), response)
            response = map(lambda x: x.split(' (')[0], response)
            
            # Take only lines starting with permit, deny or remark
            response = filter(lambda l: l.startswith('permit') or \
                                        l.startswith('deny'), response)
            
            # Find and replace IANA portnames with their numbers:
            response = map(replace_ianaports, response)
            
            return '\n'.join(response)
    
    def write_acl(self, name, rules, ip_version):
        """Writes *rules* to acl *name*.
        
        If *ip_version* is set to 'ipv6', ipv6 acls will be set, 
        otherwise use 'ipv4'."""
        
        if not self._client:
            raise ErrorNotConnected("No router connection available")
        
        assert ip_version in ['ipv4','ipv6'], ip_version+" is unsupported"
        self.check_acl_name(name)
        self.execute('configure terminal')
        if ip_version == 'ipv4':
            self.execute('no ip access-list '+name)
            self.execute('ip access-list '+name, input=rules)
        elif ip_version == 'ipv6':
            # ciscos throw error if ipv6 access-list does not exist, 
            # unlike ipv4
            self.execute('no ipv6 access-list '+name, error=False)
            self.execute('ipv6 access-list '+name, input=rules)
        
        self.execute('end')
    
    def remove_acl(self, name, ip_version='ipv4'):
        """Removes acl *name* from router.
        
        If *ip_version* is set to 'ipv6', ipv6 acls will be removed, 
        otherwise use 'ipv4'."""
        assert ip_version in ['ipv4','ipv6'], ip_version+" is unsupported"
        
        if not self._client:
            raise ErrorNotConnected("No router connection available")
        
        self.execute('configure terminal')
        if ip_version == 'ipv4':
            self.execute('no ip access-list '+name, error=False)
        elif ip_version == 'ipv6':
            self.execute('no ipv6 access-list '+name, error=False)
        self.execute('end')
    
    def get_bound_acl_form_interface(self, interface):
        '''Reads acl names of acls bound to interface.
        
        Return a dictionary of form: returnvalue['protocol']['direction']
        If no ACLs were bound, value will be None'''
        
        acl_names = {'ipv4': {'in': None, 'out': None},
                     'ipv6': {'in': None, 'out': None}}
        
        if self._running:
            # a running config was retrieved, thus no commands have to be executed
            in_interface = False
            for l in self._running:
                if l == "interface "+interface:
                    in_interface = True
                elif len(l)>0 and l[0] != " ":
                    in_interface = False
                if in_interface:
                    l = l.strip()
                    if l.startswith('ip access-group '):
                        l = l[len('ip access-group '):].split(' ')
                        if l[1] == 'in':
                            acl_names['ipv4']['in'] = l[0]
                        elif l[1] == 'out':
                            acl_names['ipv4']['out'] = l[0]
                    elif l.startswith('ipv6 traffic-filter '):
                        l = l[len('ipv6 traffic-filter '):].split(' ')
                        if l[1] == 'in':
                            acl_names['ipv6']['in'] = l[0]
                        elif l[1] == 'out':
                            acl_names['ipv6']['out'] = l[0]
        else:
            if not self._client:
                raise ErrorNotConnected("No router connection available")
            
            try:
                response = self.execute('show running-config interface '+interface+'\n')
            except AssertionError:
                raise InterfaceNotConfigured('%s is not configured on %s' % (interface, self.name))
        
            assert len(response), "Got empty interface configuration for "+ \
                interface+" on "+self.name+", that can not be right..."
        
            for l in response:
                l = l.strip()
                if l.startswith('ip access-group '):
                    l = l[len('ip access-group '):].split(' ')
                    if l[1] == 'in':
                        acl_names['ipv4']['in'] = l[0]
                    elif l[1] == 'out':
                        acl_names['ipv4']['out'] = l[0]
                elif l.startswith('ipv6 traffic-filter '):
                    l = l[len('ipv6 traffic-filter '):].split(' ')
                    if l[1] == 'in':
                        acl_names['ipv6']['in'] = l[0]
                    elif l[1] == 'out':
                        acl_names['ipv6']['out'] = l[0]
        
        return acl_names
    
    def bind_acl_to_interface(self, interface, acl_name_in, acl_name_out, ip_version='ipv4'):
        """Binds acl *acl_name_in* and *acl_name_out* to *interface*.
        
        If *ip* is set to 'ipv6', ipv6 acls will be set, otherwise ipv4."""
        
        if not self._client:
            raise ErrorNotConnected("No router connection available")
        
        assert ip_version in metacl.ip_versions, ip_versions+" is unsupported"
        self.execute('configure terminal')
        self.execute('interface '+interface)
        if ip_version == 'ipv4':
            self.execute('ip access-group '+acl_name_in+' in')
            self.execute('ip access-group '+acl_name_out+' out')
        elif ip_version == 'ipv6':
            self.execute('ipv6 traffic-filter '+acl_name_in+' in')
            self.execute('ipv6 traffic-filter '+acl_name_out+' out')
        self.execute('end')
    
    def unbind_acl_from_interface(self, interface):
        """Rads acls from *interface* and unbinds them.
        ONLY TOUCHES IPv4!
        
        Returns same as get_bound_acl_form_interface(self, interface), 
        befor unbinding"""
        
        if not self._client:
            raise ErrorNotConnected("No router connection available")
        
        acl_in, acl_out, acl_in6, acl_out6 = \
            self.get_bound_acl_form_interface(interface)
        
        self.execute('configure terminal')
        self.execute('interface '+interface)
        if acl_in:
            self.execute('no ip access-group '+acl_in+' in')
        if acl_out:
            self.execute('no ip access-group '+acl_out+' out')
        self.execute('end')
        
        return (acl_in, acl_out, acl_in6, acl_out6)
    
    def delete(self, path):
        """Executes delete command on router

        Returns True if succeeded, otherwise will return False or raise ErrorMessageRecived 
        exception."""

        if not self._client:
            raise ErrorNotConnected("No router connection available")

        command = 'delete '+path
        log.debug('To %s: %s' % (self.name, command))

        try:
            error = True

            # We send "delete $path" to router and wait for a response...
            self._client.sendline(command)
            i = self._client.expect([pxssh.TIMEOUT, self._client.PROMPT, 
                'Do you want to delete ".+" \? \(yes/no/abort\)   \[y\] '], timeout=300)
       
            # We have recieved a prompt, directly after sending the command. That is not good.
            if i==1: # Prompt, Error!
                error = True
       
            # The router is asking for confirmation...
            if i==2: #  Do you want to delete "..." ? (yes/no/abort)   [y] 
                # Send return and wair for a response...
                self._client.sendline('')
                i = self._client.expect([pxssh.TIMEOUT,
                    self._client.PROMPT], timeout=300)

            if i==0: # Timeout
                raise ErrorTimeout("Execution of command and input '"+command+"\n"+input+ \
                    "' timeouted after 5 minutes.")

            # We have recieved a prompt after confirmation, this is good!
            if i==1: # PROMPT
                error = False

            if error:
                raise Error('Delete of '+path+' could not be completed.')

            out = self._client.before
            out = out.split('\r\n')[:-1]

            # all([]) -> True, so we need to exclude len(...) -> 0 from raising an 
            # AssertionError
            if len(out) > 0 and error:
                error_lines = filter(lambda x: x.strip().startswith('% ') and 
                    x.strip()[2:] not in ignore, out)
                if error_lines:
                    log.error('Errors from %s: %s' % (self.name, error_lines))
                    raise ErrorMessageRecived("Command "+command+" produced the following error: "+ \
                        ' '.join(error_lines))

            log.debug('From %s: %s' % (self.name, out))

            return not error
        except pxssh.ExceptionPxssh, e:
            raise Error("SSH timeout while executing: '"+command+"' on "+ \
                self.name)
    
    def close(self):
        """Closes the connection and cleans up.
        This will kill all objects with the same hostname!"""
        
        if not self._client:
            raise ErrorNotConnected("No router connection available")
        
        self._client.close()
        log.debug('Disconnected from %s' % self.name)
    
    @classmethod
    def delete_all(cls):
        '''Will be called on python exit, closes all remaining connections
        and removes their traces.'''
        
        for k in cls.__shared_states.keys():
            Router(k).close()
            del cls.__shared_states[k]

# Register Router.delete_all as exit function
atexit.register(Router.delete_all)
