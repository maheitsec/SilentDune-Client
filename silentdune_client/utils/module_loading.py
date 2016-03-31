#
# Authors: Robert Abram <robert.abram@entpack.com>
#
# Copyright (C) 2015 EntPack
# see file 'COPYING' for use and warranty information
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
import sys
from importlib import import_module
from utils import six

_logger = logging.getLogger('sd-client')


def import_by_str(mod):
    """
    Import a dotted module path and return the attribute/class designated by the
    last name in the path. Raise ImportError if the import failed.
    """

    try:
        mpath, cname = mod.rsplit('.', 1)
    except ValueError:
        msg = '{0} dosen\'t look like a module path.'.format(mod)
        _logger.error(msg)
        six.reraise(ImportError, ImportError(msg), sys.exc_info()[2])

    module = import_module(mpath)

    try:
        return getattr(module, cname)
    except AttributeError:
        msg = 'Module "{0}" does not define a "{1}" attribute/class'.format(mpath, cname)
        _logger.error(msg)
        six.reraise(ImportError, ImportError(msg), sys.exc_info()[2])


class BaseModule (object):
    """
    This is the Virtual module object every module should inherit from.
    Each property and method are virtual and can be overridden as needed.
    """

    # The name of the module and version.
    _name = 'UnknownModule'
    _version = '0.0.1'
    _config = None
    _subparser = None

    #
    # Virtual Installer Hook Methods
    #
    def get_name(self):
        return self._name

    def get_version(self):
        return self._version

    def get_installer_subparser(self):
        return self._subparser

    def get_configuration(self):
        return self._config
