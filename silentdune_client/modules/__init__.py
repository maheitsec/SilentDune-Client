#
# Authors: Robert Abram <robert.abram@entpack.com>,
#
# Copyright (C) 2015 EntPack
# see file 'LICENSE' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
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
#

import logging
import os

from utils.module_loading import import_by_str

_logger = logging.getLogger('sd-client')


def __load_modules__(dir='modules'):

    module_list = list()
    config_list = list()

    # Loop through the directories looking for modules to import.
    for root, dirs, files in os.walk(dir, topdown=True):
        # Skip our directory.
        if root == '.':
            continue

        # Look only at __init__.py files.
        for name in files:
            if name == '__init__.py':

                # Convert path to dotted path.
                mp = root.replace('./', '').replace('/', '.') + '.module_list'

                # Attempt to import 'module_list' from __init__.py file.
                try:
                    ml = import_by_str(mp)
                except ImportError:
                    continue

                for mname, mdict in ml.items():
                    _logger.info('Found module definition "{0}" in path {1}'.format(mname, mp))
                    for key, name in mdict.items():

                        if key == 'module':
                            tpath = mp + '.' + name
                            _logger.info('Adding "{0}" module ({1}).'.format(mname, tpath))
                            module_list.append(tpath)

                        if key == 'config':
                            tpath = mp + '.' + name
                            _logger.info('Adding "{0}" module config ({1}).'.format(mname, tpath))
                            config_list.append(tpath)

    return module_list, config_list












