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

import hashlib
import json
import logging
import os
import pkg_resources
import subprocess

from silentdune_client import modules
from silentdune_client.models.iptables_rules import IPMachineSubset

from subprocess import check_output, CalledProcessError

_logger = logging.getLogger('sd-client')

""" Tell the firewall to reload all rules from disk """
TASK_FIREWALL_RELOAD_RULES = 100

""" Tell the firewall to allow all DNS queries """
TASK_FIREWALL_ALLOW_ALL_DNS_ACCESS = 110
TASK_FIREWALL_DISABLE_ALL_DNS_ACCESS = 111

""" Tell the firewall to allow all HTTP(S) queries """
TASK_FIREWALL_ALLOW_ALL_HTTP_ACCESS = 120
TASK_FIREWALL_DISABLE_ALL_HTTP_ACCESS = 120

TASK_FIREWALL_INSERT_RULE = 201
TASK_FIREWALL_DELETE_RULE = 202


# Define the available Module classes.
module_list = {
    'Silent Dune Firewall Manager': {
        'module': 'SilentDuneClientFirewallModule',
    },
}


class SilentDuneClientFirewallModule(modules.BaseModule):
    """ Silent Dune Server Module """

    priority = 0  # Highest loading priority.

    _rules = None  # List with IPTablesMachineSubset objects.

    def __init__(self):

        # Set our module name
        # self._name = 'SilentDuneClientFirewallModule'
        self._arg_name = 'firewall'
        self._config_section_name = 'firewall_module'

        # Enable multi-threading
        self.wants_processing_thread = True

        try:
            self._version = pkg_resources.get_distribution(__name__).version
        except:
            self._version = 'unknown'

    def install_module(self):
        """
        Virtual Override
        """
        return True

    def service_startup(self):

        _logger.debug('{0} module startup called'.format(self.get_name()))
        self.restore_iptables()
        self.load_rule_bundles()

        return True

    def service_shutdown(self):

        _logger.debug('{0} thread shutdown called'.format(self.get_name()))
        self.save_iptables()

        # Flush iptables
        try:
            check_output(['iptables', '--flush'])
        except CalledProcessError:
            pass

        # Delete chains
        try:
            check_output(['iptables', '--delete-chain'])
        except CalledProcessError:
            pass

    def process_loop(self):
        # _logger.debug('{0} processing loop called'.format(self.get_name()))

        # TODO: Things to do occasionally; Hash rule files and compare to hashes saved on server to look for tampering.

        pass

    def process_task(self, task):

        if task:
            _logger.debug('Received task {0} from {1}.'.format(task.get_task_id(), task.get_sender()))
            t_id = task.get_task_id()

            if t_id == TASK_FIREWALL_RELOAD_RULES:
                _logger.debug('Task event received, reloading firewall rules.')
                self.restore_iptables()

    # TODO: Delete this, we should never load json rules from disk.  All json rules should come from Modules.
    def load_rule_bundles(self):
        """
        Load the json bundle files, each file is a IPMachineSubset json object.
        :return:
        """

        ol = list()
        for file in os.listdir(self.node_info.config_root):
            if '.bundle' in file:
                with open(os.path.join(self.node_info.config_root, file)) as handle:
                    ol.append(IPMachineSubset(handle))

        if len(ol) == 0:
            raise ValueError

        ol.sort(key=lambda x: x.slot)
        self._rules = ol

    def restore_iptables(self):
        """
        Load the iptables save file and load it into the kernel.
        This is only called on startup.
        """
        # Load rule files into kernel
        for v in {u'ipv4', u'ipv6'}:

            file = os.path.join(self.node_info.config_root, u'{0}.rules'.format(v))
            if os.path.exists(file):
                try:
                    with open(file) as handle:
                        data = handle.read()

                    p = subprocess.Popen([self.node_info.iptables_restore, '-c'], stdin=subprocess.PIPE)
                    p.communicate(data)
                    result = p.wait()

                    if result:
                        _logger.error('iptables-restore reported an error loading data.')

                except ValueError:
                    _logger.error('Invalid arguments passed to iptables-restore.')
                except OSError:
                    _logger.error('Loading IPv4 rules into kernel failed.')
            else:
                _logger.error('Rules file ({0}) not found.'.format(file))

                # TODO: The SD Server module should be notified if there is any error loading a rule file.

    def save_iptables(self):
        """
        Dump the iptables information from the kernel and save it to the restore file.
        This is only called on shutdown.
        """

        # Load rule files into kernel
        for v in {u'ipv4', u'ipv6'}:

            file = os.path.join(self.node_info.config_root, u'{0}.rules.2'.format(v))
            try:
                p = subprocess.Popen([self.node_info.iptables_save, '-c'], stdout=subprocess.PIPE)
                data = p.communicate()[0]
                result = p.wait()

                if result:
                    _logger.error('iptables-save reported an error.')
                else:
                    with open(file, 'w') as handle:
                        handle.write(data)

            except ValueError:
                _logger.error('Invalid arguments passed to iptables-save.')
            except OSError:
                _logger.error('Saving IPv4 rules from kernel failed.')

                # TODO: The SD Server module should be notified if there is any error saving a rule file.

    def add_firewall_rule(self, obj):
        """
        Add a IPTablesMachineSubset to the list of rules
        :param obj:
        :return:
        """

        if not isinstance(obj, IPMachineSubset):
            _logger.error('Invalid IPMachineSubset object passed, unable to add to rules.')
            return False

        nmss = hashlib.sha1(obj.to_json())

        # Loop through the current rules and see if the rule already exists.
        for mss in self._rules:
            if hashlib.sha1(mss.to_json()) == nmss:
                _logger.debug('Rule has already been added to rule list.')
                return True

        self._rules.append(obj)
        self._rules.sort(key=lambda x: x.slot)

        return True

    def del_firewall_rule(self, obj):
        """
        Remove a IPTablesMachineSubset from the list of rules
        :param obj:
        :return:
        """

        if not isinstance(obj, IPMachineSubset):
            _logger.error('Invalid IPMachineSubset object passed, unable to add to rules.')
            return False

        nmss = hashlib.sha1(obj.to_json())

        # Loop through the current rules and see if the rule already exists.
        for mss in self._rules:
            if hashlib.sha1(mss.to_json()) == nmss:
                self._rules.pop(mss)
                self._rules.sort(key=lambda x: x.slot)
                return True

        _logger.debug('Rule to remove not found in rules list.')

        return False


    def generate_emergency_rules(self):
        """
        Generate temp admin access only rules and set firewall
        :return:
        """
        pass