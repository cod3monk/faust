import ConfigParser
from os.path import isdir, isfile
import logging.config

_cp = ConfigParser.SafeConfigParser()

class Error(Exception):
    '''Base config exception class.'''

class ConfigError(Error):
    """Problem parsing the config ini file."""

class ConfigNotLoadedError(Error):
    '''Config was not loaded.'''
    
def is_loaded():
    return len(_cp.sections()) > 0

def load(config_path = 'config.ini'):
    """Loads config file and does some checks for validity of configurations.
    Also configures logging.
    
    Returns ConfigParser instance"""
    #if _cp:
    #    raise ConfigError('Config already loaded!')
    #else:
    #    _cp = ConfigParser.SafeConfigParser()
    
    if len(_cp.read(config_path)) == 0:
        raise ConfigError('File could not be read: '+config_path)
    
    if not isfile(_cp.get('global','aliases_file')):
        raise ConfigError('aliases_file does not exist or is not set in '+config_path)
    
    if not isfile(_cp.get('global','vlans_file')):
        raise ConfigError('vlans_file does not exist or is not set in '+config_path)
    
    if not isfile(_cp.get('global','transit_file')):
        raise ConfigError('transit_file does not exist or is not set in '+config_path)
    
    if not isdir(_cp.get('global','policies_dir')):
        raise ConfigError('policies_dir does not exist or is not set in '+config_path)
        
    if not _cp.get('global','policies_ext'):
        raise ConfigError('policies_ext does not exist or is not set in '+config_path)
    
    if not isdir(_cp.get('global','compiled_dir')):
        raise ConfigError('compiled_dir does not exist or is not set in '+config_path)
    
    if not isfile(_cp.get('global', 'routers_file')):
        raise ConfigError('routers_file does not exist or is not set in '+config_path)
    
    if len(_cp.read(_cp.get('global', 'aliases_file'))) == 0:
        raise ConfigError('Routers file could not be read: '+_cp.get('global', 'aliases_file'))
        
    if len(_cp.read(_cp.get('global', 'routers_file'))) == 0:
        raise ConfigError('Aliases file could not be read: '+_cp.get('global', 'routers_file'))
        
    if not isfile(_cp.get('global', 'services_file')):
        raise ConfigError('services_file does not exist or is not set in '+config_path)
    
    if not _cp.get('global', 'use_rcs'):
        raise ConfigError('use_rcs does not exist or is not set in '+config_path)
    
    #if not isfile(_cp.get('global', 'default_pol')):
    #    raise ConfigError('default_pol does not exist or is not set in '+config_path)
    
    logging.config.fileConfig(config_path)
    
    return _cp

def get(section, option, raw=False, vars=None):
    if not is_loaded():
        raise ConfigNotLoadedError('Config was not loaded, but information requested.')
    return _cp.get(section, option, raw, vars)

def items(section, raw=False, vars=None):
    if not is_loaded():
        raise ConfigNotLoadedError('Config was not loaded, but information requested.')
    return _cp.items(section, raw, vars)