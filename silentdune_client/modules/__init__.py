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

from utils.console import ConsoleBase
from utils.module_loading import import_by_str

_logger = logging.getLogger('sd-client')


class BaseModule(ConsoleBase):
    """
    This is the Virtual module object every module should inherit from.
    Each property and method are virtual and can be overridden as needed.
    """

    # The name of the module and version.
    _name = 'UnknownModule'
    _arg_name = 'unknown'  # This is the argparser name for this module
    _config_section = 'unknown'  # This is the configuration file section name
    _version = '0.0.1'
    _config = None
    _enabled = True

    #
    # Virtual Installer Hook Methods
    #
    def get_name(self):
        return self._name

    def get_version(self):
        return self._version

    def add_installer_arguments(self, parser):
        pass

    def get_config(self):
        return self._config

    def disable_module(self):
        self._enabled = False

    def module_enabled(self):
        return self._enabled

    def validate_arguments(self, args):
        """
        Validate command line arguments and save values to our configuration object.
        :param args: An argparse object.
        :return: True if command line arguments are valid, otherwise False.
        """
        return True

    def validate_config(self, config):
        """
        Validate configuration file arguments and save values to our config object.
        :param config: A ConfigParser object.
        :return: True if configuration file values are valid, otherwise False.
        """
        return True

    def prepare_config(self, config):
        """
        Add the module configuration items that need to be saved to the configuration file.
        :param config: A ClientConfiguration object.
        :return: True if configuration file values were prepared correctly, otherwise False.
        """
        return True

    def pre_install(self, installer):
        """
        Called by the installer before the formal install process starts.
        :param installer: The Installer object.
        :return: True if successful, otherwise False.
        """
        return True

    def install_module(self, installer):
        """
        Called by the installer during the formal install process.
        :param installer: The Installer object.
        :return: True if successful, otherwise False.
        """
        return True

    def post_install(self, installer):
        """
        Called by the installer after the formal install process has completed.
        :param installer: The Installer object.
        :return: True if successful, otherwise False.
        """
        return True

    def uninstall_module(self, installer):
        """
        Called by the installer during an uninstall process.
        :param installer: The Installer object.
        :return: True if successful, otherwise False.
        """
        return True


def __load_modules__(dir='modules'):
    """
    Search for modules to load.  Modules must reside under the modules directory and
    have a "module_list" dict defined in the __init__.py file. Each entry in the
    "module_list" must list a Class that subclasses BaseModule.
    """

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












