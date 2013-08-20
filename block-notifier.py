#!/usr/bin/env python

from lib import config
import os

config.load()
policies_dir = config.get('global','policies_dir')
policies_ext = config.get('global','policies_ext')

for f in os.listdir(policies_dir):
    dirname = os.path.join(policies_dir, f)
    if os.path.isdir(dirname):
        for f in os.listdir(dirname):
            if f.endswith(policies_ext):
                filename = os.path.join(dirname, f)
                lines = open(filename).readlines()
                blocks = filter(lambda x: x.startswith('block('), lines)
                if blocks:
                    print filename,'containes the following block lines:'
                    print ''.join(map(lambda x: x.strip(), blocks))
                    