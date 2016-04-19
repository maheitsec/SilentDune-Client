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
import pkg_resources
import platform
import requests
import socket
import sys
from subprocess import check_output, CalledProcessError

from silentdune_client.modules.comm.sd_server.json_models import Node, NodeBundle
from silentdune_client.modules.comm.sd_server.connection import SDSConnection
from silentdune_client.modules import BaseModule
from silentdune_client.utils.misc import is_valid_ipv4_address, is_valid_ipv6_address

_logger = logging.getLogger('sd-client')

# Define the available Module classes.
module_list = {
    'Silent Dune Server': {
        'module': 'SilentDuneServerModule',
    },
}


class SilentDuneServerModule(BaseModule):
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

    # Server objects
    _node = None
    _bundle = None
    _node_bundle = None
    _bundle_machine_subsets = None

    def __init__(self):

        # Set our module name
        self._name = 'SilentDuneServerModule'
        self._arg_name = 'server'
        self._config_section = 'server_module'

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

        group.add_argument(_('--server'), help=_('Silent Dune server network address (required)'),
                        default=None, type=str, metavar='IP')  # noqa
        group.add_argument(_('--server-bundle'), help=_('Firewall bundle to use for this node (required)'),
                        default=None, type=str, metavar='BUNDLE')  # noqa
        group.add_argument(_('--server-user'), help=_('Server admin user name (required)'),
                        default=None, type=str, metavar='USER')  # noqa
        group.add_argument(_('--server-password'), help=_('Server admin password (required)'),
                        default=None, type=str, metavar='PASSWORD')  # noqa
        group.add_argument(_('--server-no-tls'), help=_('Do not use a TLS connection'),
                        default=False, action='store_true')  # noqa
        group.add_argument(_('--server-port'), help=_('Use alternate http port'),
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

        server = config.get(self._config_section, 'server')

        # Check for valid IPv4 address
        if '.' in server:
            if not is_valid_ipv4_address(server):
                _logger.error('Config value for "server" is invalid ip address')
                return False

        # Check for valid IPv6 address
        if ':' in server:
            if not is_valid_ipv6_address(server):
                _logger.error('Config value for "server" is invalid ip address')
                return False

        self._server = config.get(self._config_section, 'server')
        self._port = config.get(self._config_section, 'port')
        self._no_tls = True if config.get(self._config_section, 'no_tls').lower() == 'yes' else False
        self._bundle_name = config.get(self._config_section, 'bundle')

        return True

    def prepare_config(self, config):
        """
        Virtual Override
        Return the configuration file structure. Any new configuration items should be added here.
        Note: The order should be reverse of the expected order in the configuration file.
        """

        config.set(self._config_section, 'server', self._server)
        config.set(self._config_section, 'port', self._port)
        config.set(self._config_section, 'use_tls', 'no' if self._no_tls else 'yes')
        config.set(self._config_section, 'bundle', self._bundle_name)

        config.set_comment(self._config_section, 'server_module',
                           _('; Silent Dune Server Module Configuration\n'))  # noqa
        config.set_comment(self._config_section, 'server',
                           _('; The Silent Dune management server to connect with.\n'))  # noqa
        config.set_comment(self._config_section, 'port',
                           _('; The port used by the management server. If no port is given this\n'  # noqa
                            '; node will use port 80 or 443 to connect to the management server\n'
                            '; depending on if the --no-tls option was used during the install.\n'))
        config.set_comment(self._config_section, 'use_tls',
                           _('; Use a secure connection when communicating with the management server.'))  # noqa
        config.set_comment(self._config_section, 'bundle',
                           _('; Name of the Bundle assigned to this node. Changing this value has\n'  # noqa
                             '; no affect. The client always uses the bundle information assigned\n'
                             '; by the server.'))

        return True

    def install_module(self, node_info):
        """
        Virtual Override
        Register and download our bundle information from the server.
        """
        self._sds_conn = SDSConnection(self._server, self._no_tls, self._port)

        if not self._sds_conn.connect_with_password(self._user, self._password):
            return False

        if not self._register_node(node_info):
            return False

        if not self._get_rule_bundle():
            return False

        if not self._set_node_bundle():
            return False

        # TODO: Get and Upload adapter interface list to server
        # Note: It might be better to call ifconfig instead of using netifaces to get adapter info.

        # TODO: Download the bundle rules in the daemon process.
        # if not self._download_bundleset(node_info):
        #     return False

        return True

    def _register_node(self, node_info):
        """
        Contact the server to register this node with the server.
        """

        # Look for existing Node record first.
        self._node, status_code = self._sds_conn.get_node_by_machine_id(node_info.machine_id)

        if status_code != requests.codes.ok:
            return False

        if self._node:
            _logger.warning('Node already registered, using previously registered node information.')
        else:

            self.cwrite('Registering Node...  ')

            node = Node(
                platform=node_info.firewall_platform,
                os=platform.system().lower(),
                dist=platform.dist()[0],
                dist_version=platform.dist()[1],
                hostname=socket.gethostname(),
                python_version=sys.version.replace('\n', ''),
                machine_id=node_info.machine_id,
            )

            # Attempt to register this node on the SD server.
            self._node, status_code = self._sds_conn.register_node(node)

            if not self._node or self._node.id is None:
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

            _logger.warning(_("Unable to find the rule bundle specified. The installer can try to lookup "  # noqa
                              "and use the default server rule bundle."))  # noqa

            self.cwrite(_('Do you want to use the server default rule bundle? [y/N]:'))  # noqa
            result = sys.stdin.read(1)

            if result not in {'y', 'Y'}:
                _logger.debug('User aborting installation process.')
                return False

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

        self._node_bundle, status_code = self._sds_conn.create_or_update_node_bundle(data)

        if not self._node_bundle:
            self.cwriteline('[Failed]', 'Unable to set Node rule bundle.')
            return False

        self.cwriteline('[OK]', 'Node rule bundle successfully set.')
        return True

    def _download_bundleset(self, node_info):

        self.cwrite('Downloading bundle set rules...')

        # Get the machineset IDs assigned to the bundle
        self._bundle_machine_subsets, status_code = self._sds_conn.get_bundle_machine_subsets(self._node_bundle)
        if self._bundle_machine_subsets is None:
            self.cwriteline('[Failed]', 'No bundle machine subsets found.')
            return False

        files = self._sds_conn.write_bundle_chainsets(node_info.config_root, self._bundle_machine_subsets)

        if len(files) == 0:
            return False

        self.cwriteline('[OK]', 'Successfully downloaded bundle set rules.')

        if not node_info.root_user:
            _logger.warning('Unable to validate rules, not running as privileged user.')
            return True

        self.cwrite('Validating bundle set rules...')

        # Loop through files and test the validity of the file.
        for file in iter(files):

            if not os.path.exists(file):
                _logger.critical('Rule file does not exist.')
                return False

            cmd = '{0} --test < "{1}"'.format(node_info.iptables_restore, file)

            try:
                check_output(cmd, shell=True)
            except CalledProcessError:
                self.cwriteline('[Failed]', 'Rule set iptables test failed "{0}"'.format(file))

        self.cwriteline('[OK]', 'Rule validation successfull.')

        return True
