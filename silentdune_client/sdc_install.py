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
from utils.configuration import ClientConfiguration
from utils.console import ConsoleBase
from utils.log import setup_logging
from utils.node_info import NodeInformation
from modules import __load_modules__

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0

_logger = logging.getLogger('sd-client')


class Installer(ConsoleBase):

    # Modules dictionary list
    __modules = None

    # parser args
    args = None
    bad_arg = False

    node_info = None

    def __init__(self, args, modules):

        self.__modules = modules
        self.args = args
        self.node_info = NodeInformation()

    def write_config(self):
        """
        Setup the configuration and write it out.
        """

        # Create an empty configuration object, using the default path and filename.
        cc = ClientConfiguration()

        # Loop through the modules and have them set their configuration information
        for mod in self.__modules:
            result = mod.prepare_config(cc)

            if not result:
                _logger.error('Preparing configuration file items failed in module {0}.'.format(mod.get_name()))
                return False

        return cc.write_config()

    def clean_up(self):
        """
        Use this method to clean up after a failed install
        """
        self.cwrite('Cleaning up...')

        # TODO: Remove client service

        # TODO: Restore previous firewall service

        # if we are running as root, delete the configuration directory
        if self.node_info.root_user and self.node_info.config_root is not None and os.path.exists(self.node_info.config_root):
            shutil.rmtree(self.node_info.config_root)

        self.cwriteline('[OK]', 'Finished cleaning up.')
        return

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

        #
        # Have each module do their pre install work now.
        #
        for mod in self.__modules:
            if not mod.pre_install(self.node_info):
                return False

        # The following code can only run if we are running under root.
        if self.node_info.root_user:

            # TODO: Make sure PID path and Log path are created and set to the proper user, group and mask.

            pass


        #
        # Have each module do their install work now.
        #
        for mod in self.__modules:
            if not mod.install_module(self.node_info):
                return False

        if not self.write_config():
            return False

        # TODO: Check firewalld service is running and disable.

        # TODO: Check iptables services are running and disable.

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
    configuration.debug = setup_logging('--debug' in sys.argv)
    _logger.addHandler(configuration.debug)

    # Setup i18n - Good for 2.x and 3.x python.
    kwargs = {}
    if sys.version_info[0] < 3:
        kwargs['unicode'] = True
    gettext.install('sdc_install', **kwargs)

    # Get loadable module list
    module_list = __load_modules__()

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

    # Dump debug information
    if args.debug:
        NodeInformation().node_info_dump(args)

    # Instantiate the installer object
    i = Installer(args, module_list)

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
