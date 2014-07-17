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

import fcntl
import os
import config
import inspect

from ipaddr_ng import IPDescriptor


class Trackable(object):

    '''Tracks origin of objects by filename and linenumber'''

    def __init__(self, filename=None, lineno=None, parent=None, sourceline=None):
        self.filename = filename
        self.lineno = lineno
        self.sourceline = sourceline
        if not sourceline:
            self.sourceline = self.get_sourceline()
        self.parent = parent
        if parent:
            self.originate_from(parent)

    def originate_from(self, parent):
        self.filename = parent.filename
        self.lineno = parent.lineno
        self.sourceline = parent.sourceline

    def get_sourceline(self):
        if not self.filename or not self.lineno:
            return "<No filename or lineno found>\n"
        try:
            with open(self.filename) as f:
                data = f.readlines()
                return data[self.lineno - 1]
        except IndexError:
            return "<Could not read line>\n"
        except IOError:
            return "<Could not open file>\n"

    def origin(self, with_sourceline=False):
        base = 'File "%s"' % self.filename
        if self.lineno:
            base += ', line %s' % self.lineno
        if with_sourceline:
            base += ':\n\t%s' % self.get_sourceline()
        return base


def build_alias_list(aliases):
    '''Builds flat list of IP Network aliases.
    *aliases* can either be a space delimited string or a list of strings parsable by
    ipaddr_ng.IPDescriptor

    Returns list of IPv4Network and IPv6Network Objects'''
    r = []

    if type(aliases) is list:
        for ip in aliases:
            r += IPDescriptor(ip)
    elif type(aliases) is str:
        for ip in aliases.split(' '):
            r += IPDescriptor(ip)

    return r


def set_file_rights(path):
    '''Changes group permissions and ownership of file or directory according to configuration.

    If compiled_umask is set, will change group permissions of `path` to given value. If `path` is a
    directory it will also set all executable bits to one.

    If compiled_groupid is set, will change group ownership to given gid.'''
    try:
        umask = int(config.get('global', 'compiled_umask'))
        if os.path.isdir(path):
            import stat
            umask += stat.S_IXUSR + stat.S_IXGRP + stat.S_IXOTH
    except:
        umask = None
    try:
        gid = int(config.get('global', 'compiled_groupid'))
    except:
        gid = None

    # Correcting rights and group ownership, if configured
    if umask:
        import stat
        os.chmod(path, umask)
    if gid:
        os.chown(path, -1, gid)
