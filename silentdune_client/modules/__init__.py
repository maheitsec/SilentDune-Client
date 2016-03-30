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

import os


def __load_modules__(dir='modules'):
    list = os.listdir(dir)

    # TODO: Call __load_modules__ in each subdirectory.  The goal is to return a list of Module class names.


class BaseModule (object):

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


