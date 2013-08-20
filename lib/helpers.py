#!/usr/bin/env python
import inspect
from ipaddr_ng import IPDescriptor
import fcntl
import os
import config

class Trackable(object):
    '''Tracks origin of objects by filename and linenumber'''
    def __init__(self, filename=None, lineno=None, parent=None, 
        sourceline=None):
        self.filename = filename
        self.lineno = lineno
        self.sourceline = sourceline
        if not sourceline:
            self.sourceline = self.get_sourceline()
        self.parent = parent
        if parent:
            self.originate_from(parent)
        # Somehow not quite working:
        #if not filename and not lineno:
        #    co = CodeOrigin(level=2)
        #    self.filename = co.filename()
        #    self.lineno = co.lineno()
    
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
                return data[self.lineno-1]
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

class CodeOrigin(object):
    """Based on code by Danny Yoo (dyoo@hkn.eecs.berkeley.edu)"""
    
    def __init__(self, level=1):
        """*level* defines which frame on the stack should be looked for.
        level=0 would return this class.
        level=1 of the calling location
        level=2 of the callers calling location
        and so forth.
        """
        
        self.frame = inspect.currentframe()
        while level > 0:
            self.frame = self.frame.f_back
            level -= 1
        
    def lineno(self):
        """Returns the current line number in our program."""
        return self.frame.f_lineno
    
    def filename(self):
        """Returns the filename of the code."""
        return self.frame.f_code.co_filename
    
    def name(self):
        """Returns the name with which the code was defined"""
        return self.frame.f_code.co_name

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
    try:
        umask = int(config.get('global','compiled_umask'))
        if os.path.isdir(path):
            import stat
            umask += stat.S_IXUSR+stat.S_IXGRP+stat.S_IXOTH
    except:
        umask = None
    try:
        gid = int(config.get('global','compiled_groupid'))
    except:
        gid = None
    
    # Correcting rights and group ownership, if configured
    if umask:
        import stat
        os.chmod(path, umask)
    if gid:
        os.chown(path, -1, gid)
