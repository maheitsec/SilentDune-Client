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
import random
import shutil
import socket
import string
import sys
from subprocess import check_output, CalledProcessError

from utilities import which, setup_logging, CWrite

from server import SDSConnection
from json_models import *

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0

_logger = logging.getLogger('sd-client')


class Installer (CWrite):

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
    _machine_id = ''.join(random.choice('abcdef'+string.digits) for _ in range(32))

    # Upstart
    _ups_installed = False

    # Systemd
    _sysd_installed = False

    # sysvinit
    _sysv_installed = False

    # Current firewall service
    _ufw = False
    _firewalld = False
    _iptables = False

    # Firewall_platform - Currently only iptables is supported.
    _firewall_platform = 'iptables'

    # Node object
    _node = None
    _bundle = None
    _node_bundle = None
    _bundle_chainsets = None

    def __init__(self, args):

        self._config_p = ConfigParser(allow_no_value=True)        
        self.args = args
        self.debug = args.debug   # Save debug value for cwrite methods.
        self._sds_conn = SDSConnection(args.debug, args.server, args.nossl, args.port)

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

    def _determine_config_root(self):
        """
        Determine where we are going to write the SD client configuration file.
        """

        home = os.path.expanduser('~')
        root_failed = False
        home_failed = False

        self._config_root = '/etc/silentdune'

        # Test to see if we are running as root
        if os.getuid() == 0:
            test_file = os.path.join(self._config_root, 'test.tmp')

            try:
                if not os.path.exists(self._config_root):
                    os.makedirs(self._config_root)
                h = open(test_file, 'w')
                h.close()
                os.remove(test_file)

            except OSError:
                root_failed = True

            self._root_user = True

        else:
            root_failed = True

        # If root access has failed, try the current user's home directory
        if root_failed:
            self._config_root = os.path.join(home, '.silentdune')
            test_file = os.path.join(self._config_root, 'test.tmp')

            try:
                if not os.path.exists(self._config_root):
                    os.makedirs(self._config_root)
                h = open(test_file, 'w')
                h.close()
                os.remove(test_file)

            except OSError:
                home_failed = True

        # Check if both locations failed.
        if root_failed and home_failed:
            _logger.critical('Unable to determine a writable configuration path for the client.')
            return False

        if root_failed and not home_failed:
            _logger.warning('Not running as root, setting configuration path to "{0}"'.format(self._config_root))
            _logger.warning('Since we are not running as root, system firewall settings will not be changed.')

            _logger.debug('Configuration root set to "{0}"'.format(self._config_root))

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

            if prog is not None:

                try:
                    pid = check_output('{0} -f "{1}"'.format(pgrep, prog), shell=True)[:]

                    if pid is not None and len(pid) > 1:
                        self._ufw = True
                        self.cwriteline('[OK]', 'Detected running ufw (uncomplicated firewall) instance.')

                except CalledProcessError:
                    pass

            else:
                _logger.debug('ufw executable not found.')

        # Check to see if firewalld is running
        if self._sysd_installed:

            prog = which('firewalld')

            if prog is not None:

                try:
                    pid = check_output('{0} -f "{1}"'.format(pgrep, prog), shell=True)[:]

                    if pid is not None and len(pid) > 1:
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

                if output is not None and len(output) > 1 and \
                                'unrecognized service' not in output and 'Table:' in output:
                    self._iptables = True
                    self.cwriteline('[OK]', 'Detected running iptables instance.')

            except CalledProcessError:
                pass

        # check to see that we detected a running firewall service
        if not self._ufw and not self._firewalld and not self._iptables:

            # We were unable to detect the running firewall service.  Its a bad thing, but maybe
            # we should let the user decided if they want to continue.

            _logger.warning(_("Unable to detect the running firewall service.  You may continue, but unexpected "
                              "results can occur if more than one firewall service is running.  This may lead to "
                              "your machine not being properly secured."))

            self.cwrite('Do you want to continue with this install? [y/N]:')
            result = sys.stdin.read(1)

            if result not in {'y', 'Y'}:
                _logger.debug('User aborting installation process.')
                return False

        return True

    def _get_machine_id(self):
        """
        Find the machine unique identifier or generate one for this machine.
        """

        tmp_id = None

        _logger.debug('Looking up the machine-id value.')

        # See if we can find a machine-id file on this machine
        for p in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
            if os.path.isfile(p):
                with open(p) as h:
                    tmp_id = h.readline().strip('\n')

        # If we don't find an existing machine-id, write our new one out to self._config_root/machine-id
        if tmp_id is not None and len(tmp_id) > 24:
            self._machine_id = tmp_id
        else:
            with open(os.path.join(self._config_root, 'machine-id'), 'w') as h:
                h.write(self._machine_id + '\n')

        return True

    def _register_node(self):

        # Look for existing Node record first.
        self._node = self._sds_conn.get_node_by_machine_id(self._machine_id)

        if self._node is not None:
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
            self._node = self._sds_conn.register_node(nobj)

            if not self._node or self._node.id is None:
                self.cwriteline('[Failed]', 'Register Node failed, unknown reason.')
                return False

            self.cwriteline('[OK]', 'Node successfully registered.')

        return True

    def _get_rule_bundle(self):

        if self.args.bundle is not None:

            self.cwrite('Looking up rule bundle...')

            self._bundle = self._sds_conn.get_bundle_by_name(self.args.bundle)

            if self._bundle and self._bundle.id > 0:
                self.cwriteline('[OK]', 'Found rule bundle.')
                print(self._bundle.to_json())
                return True

            self.cwriteline('[Failed]', 'Unable to find rule bundle named "{0}".'.format(self.args.bundle))

            _logger.warning(_("Unable to find the rule bundle specified. The installer can try to lookup "
                              "and use the default server rule bundle."))

            self.cwrite('Do you want to use the server default rule bundle or abort install? [y/N]:')
            result = sys.stdin.read(1)

            if result not in {'y', 'Y'}:
                _logger.debug('User aborting installation process.')
                return False

        self.cwrite('Looking up the server default rule bundle...')

        self._bundle = self._sds_conn.get_default_bundle()

        if not self._bundle or self._bundle.id is None:
            self.cwriteline('[Failed]', 'Default bundle lookup failed.')
            return False

        self.cwriteline('[OK]', 'Found default rule bundle.')

        return True

    def _set_node_bundle(self):

        self.cwrite('Setting Node rule bundle...')

        data = NodeBundle(node=self._node.id, bundle=self._bundle.id)

        self._node_bundle = self._sds_conn.create_or_update_node_bundle(data)

        if not self._node_bundle:
            self.cwriteline('[Failed]', 'Unable to set Node rule bundle.')
            return False

        self.cwriteline('[OK]', 'Node rule bundle successfully set.')
        return True

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

        if not self._determine_config_root():
            return False

        if not self._get_machine_id():
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

        # Get the chainset IDs assigned to the bundle
        self._bundle_chainsets = self._sds_conn.get_bundle_chainsets(self._node_bundle)
        if self._bundle_chainsets is None:
            return False

        self._sds_conn.write_bundle_chainsets('./', self._bundle_chainsets)

        # TODO: Download rule sets from SD Server

        # TODO: Check firewalld service is running and disable.

        # TODO: Check iptables services are running and disable.

        # TODO: Enable SD-Client service and start service

        return True


def debug_dump(args):
    """
    Output the system information.
    """
    _logger.debug(args)

    # Basic system detections
    _logger.debug('System = {0}'.format(platform.system()))

    # Current distribution
    _logger.debug('Distribution = {0}'.format(platform.dist()[0]))
    _logger.debug('Distribution Version = {0}'.format(platform.dist()[1]))

    # Python version
    _logger.debug('Python Version: {0}'.format(sys.version.replace('\n', '')))


def main():

    # # Figure out our root directory
    # base_path = os.path.dirname(os.path.realpath(sys.argv[0]))
    # if '/install' in base_path:
    #     base_path, tail = os.path.split(base_path)

    # Setup i18n - Good for 2.x and 3.x python.
    kwargs = {}
    if sys.version_info[0] < 3:
        kwargs['unicode'] = True
    gettext.install('sdc_install', **kwargs)

    # Setup program arguments.
    parser = argparse.ArgumentParser(prog='sd-client-install')
    parser.add_argument(_('server'), help=_('Silent Dune server'), default=None, type=str)
    parser.add_argument('-b', _('--bundle'), help=_('Firewall bundle to use for this node'), default=None, type=str)
    parser.add_argument('-u', _('--user'), help=_('Server admin user id'), default=None, type=str)
    parser.add_argument('-p', _('--password'), help=_('Server admin password'), default=None, type=str)
    parser.add_argument(_('--nossl'), help=_('Do not use an SSL connection'), default=False, action='store_true')
    parser.add_argument(_('--port'), help=_('Use alternate port'), default=-1, type=int)
    parser.add_argument(_('--debug'), help=_('Enable debug output'), default=False, action='store_true')
    args = parser.parse_args()

    # Setup logging now that we know the debug parameter
    _logger.addHandler(setup_logging(args.debug))

    # Dump debug information
    if args.debug:
        debug_dump(args)

    i = Installer(args)

    if not i.start_install():
        i.clean_up()
        _logger.error('Install aborted.')
        return 1

    return 0


# --- Main Program Call ---
if __name__ == '__main__':
    sys.exit(main())
