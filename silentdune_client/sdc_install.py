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

import argparse
import gettext
import logging
import os
import shutil
import sys

import utils.configuration as configuration
from modules import __load_modules__
from utils.configuration import ClientConfiguration
from utils.console import ConsoleBase
from utils.log import setup_logging
from utils.node_info import NodeInformation
from utils.misc import is_process_running, node_info_dump

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0

_logger = logging.getLogger('sd-client')


class Installer(ConsoleBase):

    # Modules dictionary list
    __modules = None
    __config = None

    # parser args
    args = None
    bad_arg = False

    node_info = None

    previous_firewall_service = None

    def __init__(self, args, modules, node_info):

        self.__modules = modules
        self.args = args
        self.node_info = node_info
        self.__config = ClientConfiguration()

    def write_config(self):
        """
        Loop through the modules to set their configuration file items and then save the configuration.
        """
        for mod in self.__modules:
            result = mod.prepare_config(self.__config)

            if not result:
                _logger.error('Preparing configuration file items failed in module {0}.'.format(mod.get_name()))
                return False

        # Write the configuration file out.
        return self.__config.write_config()

    def disable_previous_firewall(self):
        """
        Disable the previous firewall service.
        :return: True if successful, otherwise False.
        """

        # Check to see if the previous firewall service is running.
        if not is_process_running(self.node_info.previous_firewall_service):
            _logger.info('The current firewall service does not seem to be running.')
            return True

        self.cwrite('Stopping the current firewall service...')

        # Stop and Disable the previous firewall service.
        if not self.node_info.stop_service(self.node_info.previous_firewall_service):
            self.cwriteline('[Error]', 'Unable to stop the current firewall service.')
            return False

        self.cwriteline('[OK]', 'Successfully stopped the current firewall service.')

        self.cwrite('Disabling the current firewall service...')

        if not self.node_info.disable_service(self.node_info.previous_firewall_service):
            self.cwriteline('[Error]', 'Unable to disable the current firewall service.')
            return False

        self.cwriteline('[OK]', 'Successfully disabled the current firewall service.')

        return True

    def clean_up(self):
        """
        Use this method to clean up after a failed install
        """
        self.cwrite('Cleaning up...')

        # The following code can only run if we are running under privileged account.
        if self.node_info.root_user:

            # Remove the directories the daemon process uses.
            self.__config.delete_directories()
            _logger.debug('Removed daemon process directories.')

            # Remove the system user the daemon process uses.
            self.__config.delete_user()
            _logger.debug('Removed daemon process system user.')

            # TODO: Remove daemon service init/service config file

            # Check to see if the previous firewall service is running or not
            if not is_process_running(self.node_info.previous_firewall_service):
                self.node_info.enable_service(self.node_info.previous_firewall_service)

            # if we are running as root, delete the configuration directory
            if self.node_info.config_root is not None \
                    and os.path.exists(self.node_info.config_root) \
                    and os.path.realpath(self.node_info.config_root) != '/':
                shutil.rmtree(self.node_info.config_root)

        self.cwriteline('[OK]', 'Finished cleaning up.')

    def start_install(self):
        """
        Begin installing the Silent Dune Client.
        """

        # Check to see that the NodeInformation information gathering was successful.
        if self.node_info.error:
            _logger.error('Gathering information about this node failed.')
            return False

        # See if we haven't determined the configuration root directory.
        if not self.node_info.config_root:
            _logger.error('Error determining the configuration root directory.')
            return False

        # Firewall check
        if not self.node_info.previous_firewall_service:
            return False

        if self.node_info.previous_firewall_service == 'sdc-firewall':
            self.cwriteline('[Error]', 'Silent Dune firewall service is already running, please uninstall first.')
            return False

        #
        # Have each module do their pre install work now.
        #
        for mod in self.__modules:
            if not mod.pre_install(self.node_info):
                return False

        # The following code can only run if we are running under privileged account.
        if self.node_info.root_user:

            # Create the daemon process user
            if not self.__config.create_user():
                return False

            # Create the directories the daemon process uses.
            if not self.__config.create_directories():
                return False

            # Disable the current firewall service
            if not self.disable_previous_firewall():
                return False

            # TODO: Install our firewall service

            # TODO: Enable and start our firewall service

        #
        # Have each module do their install work now.
        #
        for mod in self.__modules:
            if not mod.install_module(self.node_info):
                return False

        if not self.write_config():
            return False

        # TODO: Enable SD-Client service and start service

        # Have each module do their post install work now.
        for mod in self.__modules:
            if not mod.post_install(self.node_info):
                return False

        return True


def run():
    # # Figure out our root path
    # base_path = os.path.dirname(os.path.realpath(sys.argv[0]))
    # if '/install' in base_path:
    #     base_path, tail = os.path.split(base_path)

    # Set global debug value and setup application logging.
    setup_logging('--debug' in sys.argv)

    # See if we need to dump information about this node.
    if '--debug' in sys.argv:
        node_info_dump(sys.argv)

    # Setup i18n - Good for 2.x and 3.x python.
    kwargs = {}
    if sys.version_info[0] < 3:
        kwargs['unicode'] = True
    gettext.install('sdc_install', **kwargs)

    sys.stdout.write('Looking for modules...')

    # Get loadable module list
    module_list = __load_modules__()

    print(module_list)

    # Setup program arguments.
    parser = argparse.ArgumentParser(prog='sdc-install')  # , formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(_('--debug'), help=_('Enable debug output'), default=False, action='store_true')  # noqa

    # Loop through the module objects and add any argparse arguments.
    for mod in module_list:
        mod.add_installer_arguments(parser)

    args = parser.parse_args()

    # Have each module validate arguments.
    for mod in module_list:
        if not mod.validate_arguments(args):
            parser.print_help()
            exit(1)

    node_info = NodeInformation()

    # Instantiate the installer object
    i = Installer(args, module_list, node_info)

    # Begin the install process.
    if not i.start_install():

        # Have each module do their uninstall work now.
        for mod in module_list:
            mod.uninstall_module(i)

        i.clean_up()

        _logger.error('Install aborted.')
        return 1

    return 0


# --- Main Program Call ---
if __name__ == '__main__':
    sys.exit(run())
