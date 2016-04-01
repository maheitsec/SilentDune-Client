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

    # Loop through the directories looking for modules to import.
    for root, dirs, files in os.walk(dir, topdown=True):
        # Skip our directory.
        if root == '.':
            continue

        # Look only at __init__.py files.
        for name in files:
            if name == '__init__.py':

                # Convert path to dotted path.
                mp = root.replace('./', '').replace('/', '.')

                # Attempt to import 'module_list' from __init__.py file.
                try:
                    ml = import_by_str(mp + '.module_list')
                except ImportError:
                    continue

                for mname, mdict in ml.items():
                    _logger.debug('Found module definition "{0}" in path {1}'.format(mname, mp))
                    for key, name in mdict.items():

                        if key == 'module':
                            tpath = mp + '.' + name
                            try:
                                mod = import_by_str(tpath)
                                module_list.append(mod())
                                _logger.debug('Adding "{0}" module ({1}).'.format(mname, tpath))
                            except ImportError:
                                _logger.error('Adding "{0}" module failed. ({1}).'.format(mname, tpath))
                                pass

    return module_list












