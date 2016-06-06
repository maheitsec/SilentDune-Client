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

import hashlib
import logging
import os
import pkg_resources
import subprocess
from subprocess import CalledProcessError

from silentdune_client import modules
from silentdune_client.models.iptables_rules import IPMachineSubset, IPRulesFileWriter

# Import other module's TASK defines, set to None if module is not present.
try:
    from silentdune_client.modules.comm.sd_server import TASK_SEND_SERVER_ALERT
    from silentdune_client.modules.comm.sd_server import TASK_SEND_SERVER_ALERT_2  # noqa
except ImportError:
    TASK_SEND_SERVER_ALERT = None


_logger = logging.getLogger('sd-client')

""" Tell the firewall to reload all rules from disk """
TASK_FIREWALL_RELOAD_RULES = 100

""" Tell the firewall to allow all DNS queries """
TASK_FIREWALL_ALLOW_ALL_DNS_ACCESS = 110
TASK_FIREWALL_DISABLE_ALL_DNS_ACCESS = 111

""" Tell the firewall to allow all HTTP(S) queries """
TASK_FIREWALL_ALLOW_ALL_HTTP_ACCESS = 120
TASK_FIREWALL_DISABLE_ALL_HTTP_ACCESS = 120

TASK_FIREWALL_INSERT_RULES = 201
TASK_FIREWALL_DELETE_RULES = 202


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
            subprocess.call(['iptables', '--flush'])
        except CalledProcessError:
            pass

        # Delete chains
        try:
            subprocess.call(['iptables', '--delete-chain'])
        except CalledProcessError:
            pass

    def process_loop(self):
        # _logger.debug('{0} processing loop called'.format(self.get_name()))

        # TODO: Things to do occasionally; Hash rule files and compare to hashes saved on server to look for tampering.

        pass

    def process_task(self, task):

        if task:

            t_id = task.get_task_id()

            if t_id == TASK_FIREWALL_RELOAD_RULES:
                _logger.debug('{0}: {1}: reloading firewall rules.'.format(
                    self.get_name(), 'TASK_FIREWALL_RELOAD_RULES'))
                self.restore_iptables()

            if t_id == TASK_FIREWALL_INSERT_RULES:
                _logger.debug('{0}: {1}: received rules from module {2}.'.format(
                    self.get_name(), 'TASK_FIREWALL_INSERT_RULES', task.get_sender()))
                self.add_firewall_rule(task.get_data())
                self.write_rules_to_iptables_file()
                self.restore_iptables()

            if t_id == TASK_FIREWALL_DELETE_RULES:
                _logger.debug('{0}: {1}: received rules from module {2}.'.format(
                    self.get_name(), 'TASK_FIREWALL_DELETE_RULES', task.get_sender()))
                self.del_firewall_rule(task.get_data())
                self.write_rules_to_iptables_file()
                self.restore_iptables()

    def load_rule_bundles(self):
        """
        Load the user defined json bundle files, each file is a IPMachineSubset json object.
        :return:
        """
        ol = list()
        for file in os.listdir(self.node_info.config_root):
            if '.bundle' in file:
                try:
                    with open(os.path.join(self.node_info.config_root, file)) as handle:
                        mss = IPMachineSubset(handle)
                        # only load user defined slot range numbers.
                        if 200 < mss.slot < 9000:
                            ol.append(mss)
                except:
                    _logger.error('{0}: Bundle file is corrupt, unable to load {1}.'.format(self.get_name(), file))
                    continue

        if len(ol) > 0:
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

                    if v == u'ipv4':
                        p = subprocess.Popen([self.node_info.iptables_restore, '-c'], stdin=subprocess.PIPE)
                    else:
                        p = subprocess.Popen([self.node_info.ip6tables_restore, '-c'], stdin=subprocess.PIPE)
                    p.communicate(data)
                    result = p.wait()

                    if result:
                        _logger.error('{0}: iptables-restore reported an error loading data.'.format(self.get_name()))

                except ValueError:
                    _logger.error('{0}: Invalid arguments passed to iptables-restore.'.format(self.get_name()))
                except OSError:
                    _logger.error('{0}: Loading IPv4 rules into kernel failed.'.format(self.get_name()))
            else:
                _logger.error('{0}: Rules file ({1}) not found.'.format(self.get_name(), file))

                # TODO: The SD Server module should be notified if there is any error loading a rule file.

    def save_iptables(self):
        """
        Dump the iptables information from the kernel and save it to the restore file.
        This is only called on shutdown.
        """

        # Load rule files into kernel
        for v in {u'ipv4', u'ipv6'}:

            file = os.path.join(self.node_info.config_root, u'{0}.rules'.format(v))
            try:
                if v == u'ipv4':
                    p = subprocess.Popen([self.node_info.iptables_save, '-c'], stdout=subprocess.PIPE)
                else:
                    p = subprocess.Popen([self.node_info.ip6tables_save, '-c'], stdout=subprocess.PIPE)

                data = p.communicate()[0]
                result = p.wait()

                if result:
                    _logger.error('{0}: iptables-save reported an error.'.format(self.get_name()))
                else:
                    with open(file, 'w') as handle:
                        handle.write(data)

            except ValueError:
                _logger.error('{0}: Invalid arguments passed to iptables-save.'.format(self.get_name()))
            except OSError:
                _logger.error('{0}: Saving IPv4 rules from kernel failed.'.format(self.get_name()))

            if TASK_SEND_SERVER_ALERT:
                pass
                # TODO: The SD Server module should be notified if there is any error saving a rule file.

    def add_firewall_rule(self, obj):
        """
        Add a IPTablesMachineSubset to the list of rules
        :param obj:
        :return:
        """
        try:
            nmss = hashlib.sha1(obj.to_json()).hexdigest()

            # Loop through the current rules and see if the rule already exists.
            for mss in self._rules:
                if hashlib.sha1(mss.to_json()).hexdigest() == nmss:
                    # _logger.debug('{0}: Rule has already been added to rule list.'.format(self.get_name()))
                    return True

            self._rules.append(obj)
            self._rules.sort(key=lambda x: x.slot)

            return True

        except AttributeError:

            try:
                # See if we have a list of IPTablesMachineSubset objects. If so, recursively add them.
                if len(obj) > 0:
                    for o in obj:
                        self.add_firewall_rule(o)
                    for mss in self._rules:
                        _logger.debug('{0} Adding rule ({1}): {2}'.format(self.get_name(), mss.slot, mss.name))
                    _logger.debug('{0}: Added {1} IPTablesMachineSubset rules.'.format(self.get_name(), len(obj)))
                    return True
            except TypeError:
                _logger.error('{0} Invalid IPMachineSubset passed, unable to add rules.'.format(self.get_name()))

        return False

    def del_firewall_rule(self, obj):
        """
        Remove a IPTablesMachineSubset from the list of rules
        :param obj:
        :return:
        """

        try:
            nmss = hashlib.sha1(obj.to_json()).hexdigest()

            # Loop through the current rules and see if the rule already exists.
            for mss in self._rules:
                if hashlib.sha1(mss.to_json()).hexdigest() == nmss:
                    self._rules.remove(mss)
                    self._rules.sort(key=lambda x: x.slot)
                    return True

        except AttributeError:

            try:
                # See if we have a list of IPTablesMachineSubset objects. If so, recursively remove them.
                if len(obj) > 0:
                    for o in obj:
                        self.del_firewall_rule(o)
                    _logger.debug('{0}: Removed {1} IPTablesMachineSubset object rules.'.format(
                        self.get_name(), len(obj)))
                    return True
            except TypeError:
                _logger.error('{0}: Invalid IPMachineSubset passed, unable to remove.'.format(self.get_name()))

        return False

    def write_rules_to_iptables_file(self):
        """
        Output to file in iptables format our list of IPTablesMachineSubset objects.
        :return:
        """
        for v in {u'ipv4', u'ipv6'}:
            file = os.path.join(self.node_info.config_root, u'{0}.rules'.format(v))

            _logger.debug('{0}: Writting {1} rules to -> {2}'.format(self.get_name(), v, file))

            writer = IPRulesFileWriter(self._rules)
            writer.write_to_file(file, v)

            if not self.validate_rule_files(v, file):
                return False

        return True

    def validate_rule_files(self, protocol, file):
        """
        Validate multiple iptables rule save files.
        :param files: List of path+filenames to run iptables-restore --test on.
        :return:
        """

        if not self.node_info.root_user:
            _logger.warning('{0}: Unable to validate rules, not running as privileged user.'.format(self.get_name()))
            return True

        # Loop through files and test the validity of the file.
        if not os.path.exists(file):
            _logger.error('{0} {1} save file ({2}) does not exist.'.format(self.get_name(), protocol, file))
            return False

        with open(file) as handle:
            data = handle.read()

        if protocol == u'ipv4':
            p = subprocess.Popen([self.node_info.iptables_restore, '--test'], stdin=subprocess.PIPE)
        else:
            p = subprocess.Popen([self.node_info.ip6tables_restore, '--test'], stdin=subprocess.PIPE)

        p.communicate(data)
        result = p.wait()

        if result:
            _logger.error('{0}: {1} validation failed on iptables save file: {2}'.format(
                self.get_name(), protocol, file))

            if TASK_SEND_SERVER_ALERT:
                # TODO: Notify server of error.
                pass

        return True

    def generate_emergency_rules(self):
        """
        Generate temp admin access only rules and set firewall
        :return:
        """
        pass
