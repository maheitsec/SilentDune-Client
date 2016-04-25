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

import pkg_resources


from silentdune_client import modules

_logger = logging.getLogger('sd-client')

TASK_FIREWALL_INSERT_RULE = 201
TASK_FIREWALL_DELETE_RULE = 202
TASK_FIREWALL_RELOAD_RULES = 220

# Define the available Module classes.
module_list = {
    'Silent Dune Firewall Manager': {
        'module': 'SilentDuneClientFirewallModule',
    },
}


class SilentDuneClientFirewallModule(modules.BaseModule):
    """ Silent Dune Server Module """

    def __init__(self):

        # Set our module name
        # self._name = 'SilentDuneClientFirewallModule'
        self._arg_name = 'firewall'
        self._config_section = 'firewall_module'

        # Enable multi-threading
        self.wants_processing_thread = True

        try:
            self._version = pkg_resources.get_distribution(__name__).version
        except:
            self._version = 'unknown'

    def install_module(self, node_info):
        """
        Virtual Override
        """

        # TODO: Look for existing firewall rule files in /etc/silentdune and load them into the kernel.


        return True

    def service_startup(self):
        _logger.debug('{0} thread startup called'.format(self.get_name()))
        return True

    def service_shutdown(self):
        _logger.debug('{0} thread shutdown called'.format(self.get_name()))
        return True

    def process_loop(self, task):
        # _logger.debug('{0} processing loop called'.format(self.get_name()))
        pass

    def process_task(self, task):

        if task:
            _logger.debug('Received task {0} from {1}.'.format(task.get_task_id(), task.get_src_name()))
