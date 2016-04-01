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
import platform
import shutil
import socket
import sys
from subprocess import check_output, CalledProcessError

import requests

# TODO: Change up sd_server module to a loadable module for the installer.
from modules.comm.sd_server.json_models import Node, NodeBundle
from modules.comm.sd_server.connection import SDSConnection

from utils.configuration import BaseConfig
from utils.console import ConsoleBase
from utils.log import setup_logging
from utils.misc import which, determine_config_root
from utils.node_info import get_machine_id, write_machine_id, node_info_dump
from modules import __load_modules__
from utils.module_loading import import_by_str


try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0

_logger = logging.getLogger('sd-client')


class Installer(ConsoleBase):
    # parser args
    args = None
    bad_arg = False

    # External programs
    _ps = None
    _pgrep = None
    _iptables_exec = None
    _iptables_save = None
    _iptables_restore = None

    # Communication
    # _oauth_crypt_token = None
    # _cookies = None
    _sds_conn = None

    # Configuration Items
    _root_user = False
    _config_root = None
    _config_p = None
    _machine_id = None

    # Upstart
    _ups_installed = False

    # Systemd
    _sysd_installed = False

    # sysvinit
    _sysv_installed = False

    # Previous firewall service
    _ufw = False
    _firewalld = False
    _iptables = False

    # Firewall_platform - Currently only iptables is supported.
    _firewall_platform = 'iptables'

    # Node object
    _node = None
    _bundle = None
    _node_bundle = None
    _bundle_machine_subsets = None

    def __init__(self, args):

        self._config_p = ConfigParser(allow_no_value=True)
        self.args = args
        self.debug = args.debug  # Save debug value for cwrite methods.
        self._sds_conn = SDSConnection(args.debug, args.server, args.no_tls, args.port)

    def _check_args(self):
        """
        Validate the command line arguments.
        """

        self.bad_arg = False

        # Check parameters exist and are sane.
        if self.args.server is None:
            _logger.error('Silent Dune server name or ip address parameter required.')
            self.bad_arg = True

        if len(self.args.server) > 500:
            _logger.error('Server parameter is too long.')
            self.bad_arg = True

        if self.args.bundle is not None and len(self.args.bundle) > 50:
            _logger.error('Bundle parameter is too long.')
            self.bad_arg = True

        return not self.bad_arg

    def _check_for_external_progs(self):

        # Check for external programs here
        self._ps = which('ps')
        self._pgrep = which('pgrep')
        self._iptables_exec = which('iptables')
        self._iptables_save = which('iptables-save')
        self._iptables_restore = which('iptables-restore')

        if self._ps is None or self._pgrep is None:
            _logger.critical('Unable to determine which services are running on this machine.')
            return False

        if self._iptables is None or self._iptables_save is None or self._iptables_restore is None:
            _logger.critical('Unable to find iptables executables.')
            return False

        return True

    def _init_system_check(self):
        """
        Determine which init system is running on this system.
        """

        self.cwrite('Determining Init system...  ')

        # See if this system is an upstart setup.
        self._ups_installed = which('initctl') is not None and os.path.isfile(which('initctl'))

        # See if this system is a systemd setup.
        self._sysd_installed = which('systemctl') is not None and os.path.exists('/run/systemd/system')

        # See if this system is a sysvinit setup.
        self._sysv_installed = which('service') is not None and not self._sysd_installed and not self._ups_installed

        # If we didn't detect the init system, abort.
        if not self._ups_installed and not self._sysd_installed and not self._sysv_installed:
            _logger.critical('Unable to detect init system used on this machine.')
            return False

        if self._ups_installed:
            self.cwriteline('[OK]', 'Detected Upstart based init system.')
        if self._sysd_installed:
            self.cwriteline('[OK]', 'Detected Systemd based init system.')
        if self._sysv_installed:
            self.cwriteline('[OK]', 'Detected sysvinit based init system.')

        return True

    def _firewall_check(self):
        """
        Determine which firewall service is running on this system.
        """

        self.cwrite('Checking for firewall service...  ')

        pgrep = self._pgrep

        # Check to see if ufw is running
        if self._ups_installed:

            prog = which('ufw')

            if prog:

                try:
                    pid = check_output('{0} -f "{1}"'.format(pgrep, prog), shell=True)[:]

                    if pid and len(pid) > 1:
                        self._ufw = True
                        self.cwriteline('[OK]', 'Detected running ufw (uncomplicated firewall) instance.')

                except CalledProcessError:
                    pass

            else:
                _logger.debug('ufw executable not found.')

        # Check to see if firewalld is running
        if self._sysd_installed:

            prog = which('firewalld')

            if prog:

                try:
                    pid = check_output('{0} -f "{1}"'.format(pgrep, prog), shell=True)[:]

                    if pid and len(pid) > 1:
                        self._firewalld = True
                        self.cwriteline('[OK]', 'Detected running firewalld instance.')

                except CalledProcessError:
                    pass

            else:
                _logger.debug('firewalld executable not found.')

        # The iptables service could be running regardless of the init system used on this machine.
        # Test for a running iptables instance.
        if not self._ufw and not self._firewalld:

            # Check the iptables service status
            # TODO: Need a different check for each init system
            try:
                output = check_output('service iptables status', shell=True)[:]

                if output and len(output) > 1 and \
                        'unrecognized service' not in output and 'Table:' in output:
                    self._iptables = True
                    self.cwriteline('[OK]', 'Detected running iptables instance.')

            except CalledProcessError:
                pass

        # check to see that we detected a running firewall service
        if not self._ufw and not self._firewalld and not self._iptables:

            # We were unable to detect the running firewall service.  Its a bad thing, but maybe
            # we should let the user decided if they want to continue.

            _logger.warning(_("Unable to detect the running firewall service.  You may continue, but "  # noqa
                              "unexpected results can occur if more than one firewall service is running. "  # noqa
                              "This may lead to your machine not being properly secured."))  # noqa

            self.cwrite(_('Do you want to continue with this install? [y/N]:'))  # noqa
            result = sys.stdin.read(1)

            if result not in {'y', 'Y'}:
                _logger.debug('User aborting installation process.')
                return False

        return True

    def _register_node(self):

        # Look for existing Node record first.
        self._node, status_code = self._sds_conn.get_node_by_machine_id(self._machine_id)

        if status_code != requests.codes.ok:
            return False

        if self._node:
            _logger.warning('Node already registered, using previously registered node information.')
            # TODO: Maybe we should query the user here. Multiple nodes with the same machine_id will be a problem.
        else:

            self.cwrite('Registering Node...  ')

            nobj = Node(
                platform=self._firewall_platform,
                os=platform.system().lower(),
                dist=platform.dist()[0],
                dist_version=platform.dist()[1],
                hostname=socket.gethostname(),
                python_version=sys.version.replace('\n', ''),
                machine_id=self._machine_id,
            )

            # Attempt to register this node on the SD server.
            self._node, status_code = self._sds_conn.register_node(nobj)

            if not self._node or self._node.id is None:
                self.cwriteline('[Failed]', 'Register Node failed, unknown reason.')
                return False

            self.cwriteline('[OK]', 'Node successfully registered.')

        return True

    def _get_rule_bundle(self):

        if self.args.bundle:

            self.cwrite('Looking up rule bundle...')

            self._bundle, status_code = self._sds_conn.get_bundle_by_name(self.args.bundle)

            if self._bundle and self._bundle.id > 0:
                self.cwriteline('[OK]', 'Found rule bundle.')
                print(self._bundle.to_json())
                return True

            self.cwriteline('[Failed]', 'Unable to find rule bundle named "{0}".'.format(self.args.bundle))

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

    def _download_bundleset(self):

        self.cwrite('Downloading bundle set rules...')

        # Get the chainset IDs assigned to the bundle
        self._bundle_machine_subsets, status_code = self._sds_conn.get_bundle_machine_subsets(self._node_bundle)
        if self._bundle_machine_subsets is None:
            self.cwriteline('[Failed]', 'No bundle machine subsets found.')
            return False

        files = self._sds_conn.write_bundle_chainsets(self._config_root, self._bundle_machine_subsets)

        if len(files) == 0:
            return False

        self.cwriteline('[OK]', 'Successfully downloaded bundle set rules.')

        if not self._root_user:
            self.cwriteline('*** Unable to validate rules, not running as privileged user. ***')
            return True

        self.cwrite('Validating bundle set rules...')

        # Loop through files and test the validity of the file.
        for file in iter(files):

            if not os.path.exists(file):
                _logger.critical('Rule file does not exist.')
                return False

            cmd = '{0} --test < "{1}"'.format(self._iptables_restore, file)

            try:
                check_output(cmd, shell=True)
            except CalledProcessError:
                self.cwriteline('[Failed]', 'Rule set iptables test failed "{0}"'.format(file))

        self.cwriteline('[OK]', 'Rule validation successfull.')

        return True

    def write_config(self):
        """
        Setup the configuration and write it out.
        """
        # Create an empty configuration object, using the default path and filename.
        sdcc = BaseConfig()

        config = sdcc.create_blank_config()

        # Check to see if we are using a home directory.
        home = os.path.join(os.path.expanduser('~'), '.silentdune')
        if self._config_root == home:
            # Change the default path for pid and log file to home directory.
            config.set('settings', 'pidfile', os.path.join(home, 'sdc.pid'))
            config.set('settings', 'logfile', os.path.join(home, 'sdc.log'))

        # Set the previous firewall service
        pfws = 'unknown'

        if self._ufw:
            pfws = 'ufw'
        elif self._firewalld:
            pfws = 'firewalld'
        elif self._iptables:
            pfws = 'iptables'

        config.set('settings', 'previous_firewall_service', pfws)

        _logger.debug('Setting config bundle name to: {0}'.format(self._bundle.name))
        # Set the node bundle name
        config.set('settings', 'server', self.args.server)

        config.set('settings', 'port', '' if self.args.port == -1 else str(self.args.port))
        config.set('settings', 'use_tls', "no" if self.args.no_tls else "yes")

        return sdcc.write_config(config)

    def clean_up(self):
        """
        Use this method to clean up after a failed install
        """
        self.cwrite('Cleaning up...')

        # TODO: Remove client service

        # TODO: Restore previous firewall service

        # if we are running as root, delete the configuration directory
        if self._root_user and self._config_root is not None and os.path.exists(self._config_root):
            shutil.rmtree(self._config_root)

        self.cwriteline('[OK]', 'Finished cleaning up.')
        return

    def start_install(self):
        """
        Begin installing the Silent Dune Client.
        """

        if not self._check_for_external_progs():
            return False

        self._config_root = determine_config_root()
        if not self._config_root:
            return False

        # Determine the unique machine id for this client
        self._machine_id = get_machine_id()
        if not self._machine_id:
            self._machine_id = write_machine_id()
        if not self._machine_id:
            return False

        if not self._check_args():
            return False

        if not self._init_system_check():
            return False

        if not self._firewall_check():
            return False

        if not self._sds_conn.connect_with_password(self.args.user, self.args.password):
            return False

        if not self._register_node():
            return False

        if not self._get_rule_bundle():
            return False

        if not self._set_node_bundle():
            return False

        # TODO: Get and Upload adapter interface list to server
        # Note: It might be better to call ifconfig instead of using netifaces to get adapter info.

        if not self._download_bundleset():
            return False

        if not self.write_config():
            return False

        # TODO: Make sure PID path and Log path are created and set to the proper user, group and mask.

        # TODO: Check firewalld service is running and disable.

        # TODO: Check iptables services are running and disable.

        # TODO: Enable SD-Client service and start service

        return True


def run():
    # # Figure out our root directory
    # base_path = os.path.dirname(os.path.realpath(sys.argv[0]))
    # if '/install' in base_path:
    #     base_path, tail = os.path.split(base_path)

    # Setup application logging
    _logger.addHandler(setup_logging('--debug' in sys.argv))

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
    # parser.add_argument(_('server'), help=_('Silent Dune server'), default=None, type=str)  # noqa
    # parser.add_argument(
    #     '-b', _('--bundle'), help=_('Firewall bundle to use for this node'), default=None, type=str)  # noqa
    # parser.add_argument('-u', _('--user'), help=_('Server admin user id'), default=None, type=str)  # noqa
    # parser.add_argument('-p', _('--password'), help=_('Server admin password'), default=None, type=str)  # noqa
    # parser.add_argument(
    #     _('--no-tls'), help=_('Do not use an secure connection'), default=False, action='store_true')  # noqa
    # parser.add_argument(_('--port'), help=_('Use alternate http port'), default=-1, type=int)  # noqa

    # Loop through the module objects and add any argparse arguments.
    for mod in module_list:
        mod.add_installer_arguments(parser)

    args = parser.parse_args()

    for mod in module_list:
        mod.validate_arguments(args)

    # Dump debug information
    if args.debug:
        node_info_dump(args)

    return 0

    # i = Installer(args)
    #
    # if not i.start_install():
    #     i.clean_up()
    #     _logger.error('Install aborted.')
    #     return 1
    #
    # return 0


# --- Main Program Call ---
if __name__ == '__main__':
    sys.exit(run())