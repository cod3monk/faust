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

import ConfigParser
from os import path, chdir, getcwd
from os.path import isdir, isfile
import logging
import logging.config
import sys

log = logging.getLogger('lib.metacl')
_cp = ConfigParser.SafeConfigParser()


class Error(Exception):
    '''Base config exception class.'''


class ConfigError(Error):
    """Problem parsing the config ini file."""


class ConfigNotLoadedError(Error):
    '''Config was not loaded.'''


def is_loaded():
    return len(_cp.sections()) > 0


def load(config_location='config.ini'):
    """Loads config file and does some checks for validity of configurations.
    Also configures logging.
    
    Changes to directory of config file.

    Returns ConfigParser instance"""

    if len(_cp.read(config_location)) == 0:
        raise ConfigError('File could not be read: %s' % config_location)
    
    logging.config.fileConfig(config_location)
    
    config_dir = path.dirname(path.abspath(config_location))
    log.debug("Configuration directory is: %s" % config_dir)
    
    # Preserver current import paths
    sys.path.insert(0, getcwd())
    # Changing directory to config_dir, thus all paths are now relative to config.ini location
    chdir(config_dir)
    

    if not isfile(_cp.get('global', 'aliases_file')):
        raise ConfigError('aliases_file does not exist or is not set in %s' % config_location)

    if not isfile(_cp.get('global', 'vlans_file')):
        raise ConfigError('vlans_file does not exist or is not set in %s' % config_location)

    if not isfile(_cp.get('global', 'transit_file')):
        raise ConfigError('transit_file does not exist or is not set in %s' % config_location)

    if not isdir(_cp.get('global', 'policies_dir')):
        raise ConfigError('policies_dir does not exist or is not set in %s' % config_location)

    if not _cp.get('global', 'policies_ext'):
        raise ConfigError('policies_ext does not exist or is not set in %s' % config_location)

    if not isdir(_cp.get('global', 'compiled_dir')):
        raise ConfigError('compiled_dir does not exist or is not set in %s' % config_location)

    if not isfile(_cp.get('global', 'routers_file')):
        raise ConfigError('routers_file does not exist or is not set in %s' % config_location)

    if len(_cp.read(_cp.get('global', 'aliases_file'))) == 0:
        raise ConfigError('Routers file could not be read: %s' % _cp.get('global', 'aliases_file'))

    if len(_cp.read(_cp.get('global', 'routers_file'))) == 0:
        raise ConfigError('Aliases file could not be read: %s' % _cp.get('global', 'routers_file'))

    if not isfile(_cp.get('global', 'services_file')):
        raise ConfigError('services_file does not exist or is not set in %s' % config_location)

    if not _cp.get('global', 'use_rcs'):
        raise ConfigError('use_rcs does not exist or is not set in %s' % config_location)

    return _cp


def get(section, option, raw=False, vars=None):
    if not is_loaded():
        raise ConfigNotLoadedError('Config was not loaded, but information requested.')
    return _cp.get(section, option, raw, vars)


def items(section, raw=False, vars=None):
    if not is_loaded():
        raise ConfigNotLoadedError('Config was not loaded, but information requested.')
    return _cp.items(section, raw, vars)


def unload():
    _cp = ConfigParser.SafeConfigParser()