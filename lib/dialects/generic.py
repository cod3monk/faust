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

from lib import ipaddr_ng
from lib.ipaddr_ng import IPv4Descriptor
from lib.third_party.ipaddr import IPv4Network, IPv6Network, AddressValueError
from lib.third_party.ipaddr import NetmaskValueError
import datetime
import string
import time
from lib.third_party import pxssh
import sys
import logging
import re
from lib import metacl
import atexit
import lib

# A dialect module must provice the following interface:
class Error(Exception):
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

class Router(object):
    """This class abstracts the interaction with the router and aims at
    providing a fault-tollerant way of changing acls and related 
    configurations.

    It uses the 'Borg design pattern' to create only one connection per 
    Router."""

    __shared_states = {}  # global storage for states (per hostname)

    def __init__(self, hostname, *args, **kwargs):
        '''This makes sure, that for each *hostname* only one object exists.
        If another object for the same hostname ist requested, it will return
        an object with the same state as the one created before.

        See Borg Design Pattern.'''

        if self.__shared_states.has_key(hostname):
            self.__dict__ = self.__shared_states[hostname]
        else:
            self.__shared_states[hostname] = {}
            self.__dict__ = self.__shared_states[hostname]
            self._connect(hostname, *args, **kwargs)

    def _connect(self, hostname, username, password, port = 22, 
        read_running_config_first=True):
        """Sets basic information necessasery to connect to router and
        connects."""

        raise Exception("execute method was not "+ \
            "implemented in router dialect")

    #TODO this is fracking dum, please get it sorted out!
    def execute(self, command, input=None, error=True):
        """Executes *command* on router and appends *input*.

        If *error* is set to true, all responses will be checked for errror
        messages (lines starting with ' %'). The function will wait until
        a line ending with '#' is found, signaling a successfull execution."""

        raise Exception("execute method was not "+ \
            "implemented in router dialect")

    def check_acl_name(self, name):
        """Checks if *name* is a valid name for cisco acls."""

        raise Exception("check_acl_name method was not "+ \
            "implemented in router dialect")

    def read_acl(self, name, ip='ipv4'):
        """Reads acl *name* from router and returns String with commands.
        Remarks are not included.

        By default ipv4 acls are retrieved, if *ip* is set to 'ipv6' ipv6 acls
        will be retrieved."""

        raise Exception("read_acl method was not "+ \
            "implemented in router dialect")

    def write_acl(self, name, rules, ip='ipv4'):
        """Writes *rules* to acl *name*.

        If *ip* is set to 'ipv6', ipv6 acls will be set, otherwise ipv4."""

        raise Exception("write_acl method was not "+ \
            "implemented in router dialect")

    def remove_acl(self, name, ip='ipv4'):
        """Removes acl *name* from router.

        If *ip* is set to 'ipv6', ipv6 acls will be removed, otherwise ipv4."""

        raise Exception("remove_acl method was not "+ \
            "implemented in router dialect")

    def get_bound_acl_form_interface(self, interface):
        '''Reads acl names of acls bound to interface.

        Return a dictionary of form: returnvalue['protocol']['direction']
        If no ACLs were bound, value will be None'''

        raise Exception("get_bound_acl_form_interface method was not "+ \
            "implemented in router dialect")

    def bind_acl_to_interface(self, interface, acl_name_in, acl_name_out, ip='ipv4'):
        """Binds acl *acl_name_in* and *acl_name_out* to *interface*.

        If *ip* is set to 'ipv6', ipv6 acls will be set, otherwise ipv4."""

        raise Exception("bind_acl_to_interface method was not "+ \
            "implemented in router dialect")

    def unbind_acl_from_interface(self, interface):
        """Rads acls from *interface* and unbinds them.
        ONLY TOUCHES IPv4!

        Returns same as get_bound_acl_form_interface(self, interface), 
        befor unbinding"""

        raise Exception("unbind_acl_from_interface method was not "+ \
            "implemented in router dialect")

    def close(self):
        raise Exception("OMG!! We'are all gonna die! (close method was not "+\
            "implemented in router dialect and is of utter importance. "+ \
            "Please do so!)")

    @classmethod
    def delete_all(cls):
        '''Will be called on python exit, closes all remaining connections
        and removes their traces.'''

        for k in cls.__shared_states.keys():
            Router(k).close()
            del cls.__shared_states[k]