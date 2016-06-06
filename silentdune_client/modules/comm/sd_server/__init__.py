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

import logging
import platform
import pkg_resources
from random import random
import requests
import socket
import sys

from cryptography.fernet import Fernet

from silentdune_client import modules
from silentdune_client.models.node import Node, NodeBundle
from silentdune_client.models.global_preferences import GlobalPreferences
from silentdune_client.modules import QueueTask
from silentdune_client.modules.comm.sd_server.connection import SDSConnection
from silentdune_client.modules.firewall.manager import SilentDuneClientFirewallModule, \
    TASK_FIREWALL_INSERT_RULES, TASK_FIREWALL_DELETE_RULES
from silentdune_client.modules.comm.sd_server.auto_rules import create_tcp_server_conn_rule
from silentdune_client.utils.misc import is_valid_ipv4_address, is_valid_ipv6_address

_logger = logging.getLogger('sd-client')

TASK_SEND_SERVER_ALERT = 500

# Define the available Module classes.
module_list = {
    'Silent Dune Server': {
        'module': 'SilentDuneServerModule',
    },
}


class SilentDuneServerModule(modules.BaseModule):
    """ Silent Dune Server Module """

    # Module properties
    _server = ''
    _port = 0
    _no_tls = False
    _bundle_name = ''
    _user = ''
    _password = ''

    # Server Connection
    _sds_conn = None
    _connected = False
    _connection_start = False

    # Server objects
    _node = None
    _bundle = None
    _node_bundle = None
    _bundle_machine_subsets = None
    _globals = None

    # Timed events.
    _t_connection_retry = 0
    _t_next_check = 0  # Used to calculate next time we should contact the server.
    # Random number of seconds between -30 and 30 to make sure all nodes do not
    # contact the server at the same time.
    _t_random_seconds = int((random() - 0.5) * 60.0)

    priority = 30

    # Status
    _locked = False

    def __init__(self):

        # Set our module name
        # self._name = 'SilentDuneServerModule'
        self._arg_name = 'server'
        self._config_section_name = 'server_module'

        # Enable multi-threading
        self.wants_processing_thread = True

        try:
            self._version = pkg_resources.get_distribution(__name__).version
        except:
            self._version = 'unknown'

    def add_installer_arguments(self, parser):
        """
        Virtual Override
        Add our module's argparser arguments
        """

        # Create a argument group for our module
        group = parser.add_argument_group('server module', 'Silent Dune Server module')

        group.add_argument('--server-mod-disable', action='store_true', help=_('Disable the server module'))  # noqa

        group.add_argument(_('--server'), help=_('Silent Dune server network address (required)'),  # noqa
                        default=None, type=str, metavar='IP')  # noqa
        group.add_argument(_('--server-bundle'), help=_('Firewall bundle to use for this node (required)'),  # noqa
                        default=None, type=str, metavar='BUNDLE')  # noqa
        group.add_argument(_('--server-user'), help=_('Server admin user name (required)'),  # noqa
                        default=None, type=str, metavar='USER')  # noqa
        group.add_argument(_('--server-password'), help=_('Server admin password (required)'),  # noqa
                        default=None, type=str, metavar='PASSWORD')  # noqa
        group.add_argument(_('--server-no-tls'), help=_('Do not use a TLS connection'),  # noqa
                        default=False, action='store_true')  # noqa
        group.add_argument(_('--server-port'), help=_('Use alternate http port'),  # noqa
                        default=0, type=int, metavar='PORT')  # noqa

    def validate_arguments(self, args):
        """
        Virtual Override
        Validate command line arguments and save values to our configuration object.
        :param args: An argparse object.
        """

        # Check for conflicting arguments.
        if '--server-mod-disable' in sys.argv and (
                '--server' in sys.argv or
                '--server-bundle' in sys.argv or
                '--server-user' in sys.argv or
                '--server-password' in sys.argv or
                '--server-no-tls' in sys.argv or
                '--server-port' in sys.argv):
            print('sdc-install: argument --server-mod-disable conficts with other server module arguments.')
            return False

        if args.server_mod_disable:
            self._enabled = False
        else:
            if not args.server:
                print('sdc-install: argument --server is required.')
                return False
            if not args.server_bundle:
                print('sdc-install: argument --server-bundle is required.')
                return False
            if not args.server_user:
                print('sdc-install: argument --server-user is required.')
                return False
            if not args.server_password:
                print('sdc-install: argument --server-password is required.')
                return False

        # Check for valid IPv4 address
        if '.' in args.server:
            if not is_valid_ipv4_address(args.server):
                print('sdc-install: argument --server is invalid ip address')
                return False

        # Check for valid IPv6 address
        if ':' in args.server:
            if not is_valid_ipv6_address(args.server):
                print('sdc-install: argument --server is invalid ip address')
                return False

        self._server = args.server
        self._port = args.server_port
        self._no_tls = args.server_no_tls
        self._bundle_name = args.server_bundle

        # User and password are only used during the install process
        self._user = args.server_user
        self._password = args.server_password

        return True

    def validate_config(self, config):
        """
        Virtual Override
        Validate configuration file arguments and save values to our config object.
        :param config: A ConfigParser object.
        """

        server = config.get(self._config_section_name, 'server')

        # Check for valid IPv4 address
        if '.' in server:
            if not is_valid_ipv4_address(server):
                _logger.error('{0}: Config value for "server" is invalid ip address'.format(self.get_name()))
                return False

        # Check for valid IPv6 address
        if ':' in server:
            if not is_valid_ipv6_address(server):
                _logger.error('{0}: Config value for "server" is invalid ip address'.format(self.get_name()))
                return False

        self._server = config.get(self._config_section_name, 'server')
        self._port = config.get(self._config_section_name, 'port')
        self._no_tls = True if config.get(self._config_section_name, 'use_tls').lower() == 'yes' else False
        self._bundle_name = config.get(self._config_section_name, 'bundle')

        return True

    def prepare_config(self, config):
        """
        Virtual Override
        Return the configuration file structure. Any new configuration items should be added here.
        Note: The order should be reverse of the expected order in the configuration file.
        """

        config.set(self._config_section_name, 'server', self._server)
        config.set(self._config_section_name, 'port', self._port)
        config.set(self._config_section_name, 'use_tls', 'no' if self._no_tls else 'yes')
        config.set(self._config_section_name, 'bundle', self._bundle_name)

        config.set_comment(self._config_section_name, 'server_module',
                           _('; Silent Dune Server Module Configuration\n'))  # noqa
        config.set_comment(self._config_section_name, 'server',
                           _('; The Silent Dune management server to connect with.\n'))  # noqa
        config.set_comment(self._config_section_name, 'port',
                           _('; The port used by the management server. If no port is given this\n'  # noqa
                            '; node will use port 80 or 443 to connect to the management server\n'
                            '; depending on if the --no-tls option was used during the install.\n'))
        config.set_comment(self._config_section_name, 'use_tls',
                           _('; Use a secure connection when communicating with the management server.'))  # noqa
        config.set_comment(self._config_section_name, 'bundle',
                           _('; Name of the Bundle assigned to this node. Changing this value has\n'  # noqa
                             '; no affect. The client always uses the bundle information assigned\n'
                             '; by the server.'))

        return True

    def install_module(self):
        """
        Virtual Override
        Register and download our bundle information from the server.
        """
        self._sds_conn = SDSConnection(self._server, self._no_tls, self._port)

        if not self._sds_conn.connect_with_password(self._user, self._password):
            return False

        self.get_global_preferences()

        if not self._register_node():
            return False

        if not self._get_rule_bundle():
            return False

        if not self._set_node_bundle():
            return False

        # TODO: Get and Upload adapter interface list to server
        # Note: It might be better to call ifconfig instead of using netifaces to get adapter info.

        # self._write_bundleset_to_file()

    # TODO: delete this method
    # def _write_bundleset_to_file(self):
    #
    #     if not self._download_bundleset():
    #         _logger.error('Failed to download firewall rules bundle.')
    #         return False
    #
    #     self._insert_server_connection_rule()
    #
    #     if not self._write_rule_files():
    #         _logger.error('Failed to write firewall rules bundle to file system.')
    #         return False
    #
    #     _logger.info('Successfully downloaded firewall rules bundle.')
    #
    #     return True

    def service_connect_to_server(self):
        """
        Attempt to connect to the silent dune server.
        :return:
        """

        self._connected = False
        self._connection_start = False

        server = self.config.get(self._config_section_name, 'server')
        port = self.config.get(self._config_section_name, 'port')
        no_tls = False if self.config.get(self._config_section_name, 'use_tls').lower() == 'yes' else True

        self._sds_conn = SDSConnection(server, no_tls, port)
        _logger.info('{0}: Server -> {1}:{2} tls: {3}'.format(self.get_name(), server, port, no_tls))

        if self._sds_conn.connect_with_machine_id(self.node_info.machine_id):
            self._connected = True
            self._connection_start = True
            self._node, status_code = self._sds_conn.get_node_by_machine_id(self.node_info.machine_id)
        else:
            _logger.warning('{0}: Failed to connect with server, will attempt reconnection.'.format(self.get_name()))

        return self._connected

    def service_startup(self):
        _logger.debug('{0}: module startup called'.format(self.get_name()))

        if not self.validate_config(self.config):
            _logger.error('{0}: module configuration validation failed.'.format(self.get_name()))
            return False

        self.service_connect_to_server()

        return True

    def service_shutdown(self):
        _logger.debug('{0}: module shutdown called'.format(self.get_name()))

        # Notify the server we are no longer active.
        if self._connected:
            self.update_server_node_info(active=False)

        return True

    def process_loop(self):

        # If we are not connected to the server, try reconnecting every 60 seconds.
        if not self._connected:
            if self.t_seconds > self._t_connection_retry and self.t_seconds % 60 == 0.0:
                self._t_connection_retry = self.t_seconds
                self.service_connect_to_server()

        if self._connected:

            if self._connection_start:

                # Get the global preferences
                self.get_global_preferences()

                # Notify the server we are active now.
                self._node.active = True
                self.update_server_node_info(active=True)

                # Set our lock down mode value.
                self.set_lockdown_mode()

                # Update our firewall with rules from the server.
                self.update_node_firewall_rules_from_server()
                self.set_next_check_time()

                self._connection_start = False

            # Check to see if the node rule bundle information has changed.
            # if self.t_seconds > self._t_bundle_check and self.t_seconds % (self._node.polling_interval * 60) == 0.0:
            if self.t_seconds > self._t_next_check:

                self.set_next_check_time()
                self._node, status_code = self._sds_conn.get_node_by_machine_id(self.node_info.machine_id)

                # Check to see if we need to update our firewall rules bundle.
                if self._node.sync:
                    _logger.info('{0}: Found signal to update the firewall rules bundle.'.format(self.get_name()))

                    self.set_lockdown_mode()
                    self.update_node_firewall_rules_from_server()

                    # Update our information with the server.
                    self.update_server_node_info(sync=False)

    def set_lockdown_mode(self):
        """
        Set the lock down mode
        :return:
        """
        # Check locked down mode.
        if not self._locked and self._node.locked:
            _logger.warning('System is now in lock down mode.')
            self._locked = True

        if self._locked and not self._node.locked:
            _logger.warning('System is no longer in lock down mode.')
            self._locked = False

    def set_next_check_time(self):
        """
        Set the next time we should check the server.
        :return:
        """
        # Setup time for next check.
        # self._t_next_check = self.t_seconds + ((self._node.polling_interval * 60) + self._t_random_seconds)

        # _logger.debug('Next server check in {0} seconds.'.format(
        #    (self._node.polling_interval * 60) + self._t_random_seconds
        # ))

        self._t_next_check = self.t_seconds + 2

    def get_global_preferences(self):

        self._globals, status_code = self._sds_conn.get_global_preferences()

        if not globals or status_code != requests.codes.ok:
            _logger.error('Failed to download global preferences. Err: {0}'.format(status_code))
            self._globals = GlobalPreferences(lockdown_slot_level=120)
            return False

        return True

    def update_server_node_info(self, **kwargs):

        # _logger.debug(self._node.to_json())

        data = {u'machine_id': self._node.machine_id}  # machine_id is always required to update a node data record.

        if 'sync' in kwargs:
            data[u'sync'] = kwargs['sync']
            self._node.sync = kwargs['sync']

        if 'active' in kwargs:
            self._node.active = kwargs['active']
            data[u'active'] = kwargs['active']
        else:
            data[u'active'] = self._node.active

        reply, status_code = self._sds_conn.update_node(self._node.id, data)

        # _logger.debug(self._node.to_json())

        if not self._node or status_code != requests.codes.ok:
            _logger.error('{0}: Failed to update node information.'.format(self.get_name()))
            return False

        return True

    def update_node_firewall_rules_from_server(self):
        """
        Retrieve the node bundle rules from the server and send them to the Firewall module.
        :return:
        """

        # TODO: Save current bundle machine subsets and then look for any orphaned sets and remove them
        # from the firewall.

        if self._bundle_machine_subsets:
            # Until the orphan rule check is in place, just tell the firewall to delete all rules.
            task = QueueTask(TASK_FIREWALL_DELETE_RULES,
                             src_module=self.get_name(),
                             dest_module=SilentDuneClientFirewallModule().get_name(),
                             data=self._bundle_machine_subsets)
            self.send_parent_task(task)

        # Get updated bundle information.
        self._node_bundle, status_code = self._sds_conn.get_node_bundle_by_node_id(self._node.id)
        self._bundle, status_code = self._sds_conn.get_bundle_by_id(self._node_bundle.bundle)

        if not self._download_bundleset():
            _logger.error('{0}: Failed to download firewall rules bundle.'.format(self.get_name()))
            self._connected = False
            return False

        self._insert_server_connection_rule()

        if self._bundle_machine_subsets and len(self._bundle_machine_subsets) > 0:

            # Check to see if we are in lockdown mode. If so filter out all
            if self._locked:
                data = list()
                for i in self._bundle_machine_subsets:
                    if i.slot <= self._globals.lockdown_slot_level or i.slot >= self._globals.rejection_slot_level:
                        data.append(i)
            else:
                data = self._bundle_machine_subsets

            # Notify the firewall module to reload the rules.
            task = QueueTask(TASK_FIREWALL_INSERT_RULES,
                             src_module=self.get_name(),
                             dest_module=SilentDuneClientFirewallModule().get_name(),
                             data=data)
            self.send_parent_task(task)

            # Notify the firewall module to reload the rules.
            # task = QueueTask(TASK_FIREWALL_RELOAD_RULES,
            #                  src_module=self.get_name(),
            #                  dest_module=SilentDuneClientFirewallModule().get_name())
            # self.send_parent_task(task)

            # Reset the node rule bundle check timer
            self._t_next_check = self.t_seconds

        else:
            _logger.error('{0}: No rules downloaded from server, unable to update firewall module.'.format(
                self.get_name()))
            return False

        return True

        # TODO: Port knocker event triggers.  https://github.com/moxie0/knockknock

        # Every 10 seconds, send the firewall module a QueueTask
        # if self._seconds_t > self._event_t and self._seconds_t % 4 == 0.0:
        #     self._event_t = self._seconds_t
        #
        #     _logger.debug('Sending {0} module a task.'.format(type(SilentDuneClientFirewallModule).__name__))
        #
        #     task = QueueTask(TASK_FIREWALL_RELOAD_RULES,
        #                      self.get_name(),
        #                      SilentDuneClientFirewallModule().get_name(),
        #                      None)
        #
        #     self.send_parent_task(task)

    def _register_node(self):
        """
        Contact the server to register this node with the server.
        """
        # Look for existing Node record.
        self._node, status_code = self._sds_conn.get_node_by_machine_id(self.node_info.machine_id)

        if status_code == requests.codes.ok and self._node and self._node.id:
            _logger.warning('{0}: Node already registered, using previously registered node info.'.format(
                self.get_name()))
            return True

        self.cwrite('{0}: Registering Node...  '.format(self.get_name()))

        node = Node(
            platform=self.node_info.firewall_platform,
            os=platform.system().lower(),
            dist=platform.dist()[0],
            dist_version=platform.dist()[1],
            hostname=socket.gethostname(),
            python_version=sys.version.replace('\n', ''),
            machine_id=self.node_info.machine_id,
            fernet_key=Fernet.generate_key().decode('UTF-8'),
            polling_interval=self._globals.polling_interval
        )

        # Attempt to register this node on the SD server.
        self._node, status_code = self._sds_conn.register_node(node)

        if status_code != requests.codes.created or not self._node or self._node.id is None:
            self.cwriteline('[Failed]', 'Register Node failed, unknown reason.')
            return False

        self.cwriteline('[OK]', 'Node successfully registered.')

        return True

    def _get_rule_bundle(self):

        if self._bundle_name:

            self.cwrite('Looking up rule bundle...')

            self._bundle, status_code = self._sds_conn.get_bundle_by_name(self._bundle_name)

            if self._bundle and self._bundle.id > 0:
                self.cwriteline('[OK]', 'Found rule bundle.')
                return True

            self.cwriteline('[Failed]', 'Unable to find rule bundle named "{0}".'.format(self._bundle_name))

            # _logger.warning(_("Unable to find the rule bundle specified. The installer can try to lookup "  # noqa
            #                   "and use the default server rule bundle."))  # noqa
            #
            # self.cwrite(_('Do you want to use the server default rule bundle? [y/N]:'))  # noqa
            # result = sys.stdin.read(1)
            #
            # if result not in {'y', 'Y'}:
            #     _logger.debug('User aborting installation process.')
            #     return False

        self.cwrite('Looking up the server default rule bundle...')

        self._bundle, status_code = self._sds_conn.get_default_bundle()

        if not self._bundle or self._bundle.id is None:
            self.cwriteline('[Failed]', 'Default bundle lookup failed.')
            return False

        self.cwriteline('[OK]', 'Found default rule bundle.')

        return True

    def _set_node_bundle(self):

        self.cwrite('Setting Node rule bundle...')

        data = NodeBundle(node=self._node.id, bundle=self._bundle.id)

        self._node_bundle, status_code = self._sds_conn.create_node_bundle(data)

        if not self._node_bundle:
            self.cwriteline('[Failed]', 'Unable to set Node rule bundle.')
            return False

        self.cwriteline('[OK]', 'Node rule bundle successfully set.')
        return True

    def _download_bundleset(self):

        self.cwrite('Downloading bundle set rules...')

        # Get the machineset IDs assigned to the bundle
        self._bundle_machine_subsets, status_code = self._sds_conn.get_bundle_machine_subsets(self._node_bundle)
        if self._bundle_machine_subsets is None:
            self.cwriteline('[Failed]', 'No bundle machine subsets found.')
            return False

        return True

    def _insert_server_connection_rule(self):
        """
        Create machine subset to allow this node to access the Silent Dune server and then insert it into the bundle.
        :return:
        """
        ms = create_tcp_server_conn_rule(self._server, self._port, slot=120, desc='Silent Dune Server Access')

        ol = list()
        ol.append(ms)

        for ms in self._bundle_machine_subsets:
            ol.append(ms)

        self._bundle_machine_subsets = ol

    # TODO: Move this method to the Firewall module.
    # def _write_rule_files(self):
    #     """
    #     Write to file bundle rules in iptables save file format.
    #     :return:
    #     """
    #
    #     files = self._sds_conn.write_bundle_to_file(self.node_info.config_root, self._bundle_machine_subsets)
    #
    #     if len(files) == 0:
    #         self.cwriteline('[Error]', 'Failed to write bundle set to file.')
    #         return False
    #
    #     self.cwriteline('[OK]', 'Successfully wrote bundle set rules to file.')
    #
    #     self._validate_rule_files(files)
    #
    #     return True

    # TODO: Move this method to the Firewall module.
    # def _validate_rule_files(self, files):
    #     """
    #     Validate multiple iptables rule save files.
    #     :param files: List of path+filenames to run iptables-restore --test on.
    #     :return:
    #     """
    #
    #     if not self.node_info.root_user:
    #         _logger.warning('Unable to validate rules, not running as privileged user.')
    #         return True
    #
    #     self.cwrite('Validating bundle set rules...')
    #
    #     # Loop through files and test the validity of the file.
    #     for file in iter(files):
    #
    #         if not os.path.exists(file):
    #             _logger.critical('Rule file does not exist.')
    #             return False
    #
    #         cmd = '{0} --test < "{1}"'.format(self.node_info.iptables_restore, file)
    #
    #         try:
    #             # TODO: Change this to a process.call and just look at the return code.
    #             check_output(cmd, shell=True)
    #         except CalledProcessError:
    #             self.cwriteline('[Failed]', 'Rule set iptables test failed "{0}"'.format(file))
    #             # TODO: Enable this return later.
    #             # return False
    #
    #     self.cwriteline('[OK]', 'Rule validation successfull.')
    #
    #     return True


