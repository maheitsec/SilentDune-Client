#
# Authors: Robert Abram <robert.abram@entpack.com>,
#
# Copyright (C) 2015-2016 EntPack
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

import datetime

from silentdune_client import modules
from silentdune_client.modules import QueueTask
from silentdune_client.modules.firewall.manager import SilentDuneClientFirewallModule, \
    TASK_FIREWALL_INSERT_RULES, TASK_FIREWALL_DELETE_RULES, TASK_FIREWALL_RELOAD_RULES

# Define the available Module classes.
module_list = {
    'Silent Dune Job Module': {
        'module': 'SilentDuneJobModule',
    },
}


class SilentDuneJobModule(modules.BaseModule):
    """ Silent Dune Job Module """

    def __init__(self):

        self._arg_name = 'job'

        # Enable multi-threading
        self.wants_processing_thread = True

    def process_loop(self):
        # TODO: Things to do occasionally; Hash rule files and compare to hashes saved on server to look for tampering.
	#if self.t_seconds > 45:
	#    print "debug 1 message"

	if self.t_seconds > 120:
	    print "debug 2 message"
	    task = QueueTask(TASK_FIREWALL_RELOAD_RULES, 
			    src_module=self.get_name(),
			    dest_module=SilentDuneClientFirewallModule().get_name())
	    self.send_parent_task(task)

        pass

