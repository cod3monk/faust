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
                    #write each block rule in new line; [:-1] removes last newline
                    print ''.join(map(lambda x: x.strip() + "\n", blocks))[:-1]
