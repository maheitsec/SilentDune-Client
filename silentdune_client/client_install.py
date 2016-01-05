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

import os
import sys
import logging
import gettext
import argparse
import random
import string
import socket
import requests
import shutil
import platform
from subprocess import check_output, CalledProcessError

from lib.utilities import which, setup_logging, CWrite
from lib.server import SDSConnection, Node

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0

_logger = logging.getLogger('sd-client')


class Installer (CWrite):

    # parser args
    args = None
    badparm = False

    # External programs
    _ps = None
    _pgrep = None

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

    def __init__(self, args):

        self._config_p = ConfigParser(allow_no_value=True)        
        self.args = args
        self.debug = args.debug   # Save debug value for cwrite methods.
        self._sds_conn = SDSConnection(args.debug, args.server, args.nossl, args.port)

    # Check command line parameters.
    def _check_parameters(self):

        self.badparm = False

        # Check parameters exist and are sane.
        if self.args.server is None:
            _logger.error('Silent Dune server name or ip address parameter required.')
            self.badparm = True

        if len(self.args.server) > 500:
            _logger.error('Server parameter is too long.')
            self.badparm = True

        if self.args.bundle is None:
            _logger.error('Silent Dune firewall bundle parameter required.')
            self.badparm = True

        if len(self.args.bundle) > 50:
            _logger.error('Bundle parameter is too long.')
            self.badparm = True

        return not self.badparm

    # Determine where we are going to write the SD client configuration file.
    def _determine_config_root(self):

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

    # Check which init system is running on this system.
    def _init_system_check(self):

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

    # Determine which firewall service is running on this system.
    def _firewall_check(self):

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

                except CalledProcessError:
                    pass

            else:
                _logger.debug('firewalld executable not found.')

        # The iptables service could be running regardless of the init system used on this machine.
        # Test for a running iptables instance.
        if not self._ufw and not self._firewalld and os.path.isfile('/etc/init.d/iptables'):

            # Check the iptables service status
            # TODO: Probably need a different check for each init system
            try:
                output = check_output('service iptables status', shell=True)[:]

                if output is not None and len(output) > 1 and \
                                'unrecognized service' not in output and 'Table:' in output:
                    self._iptables = True

            except CalledProcessError:
                pass

        # check to see that we detected a running firewall service
        if not self._ufw and not self._firewalld and not self._iptables:

            # We were unable to detect the running firewall service.  Its a bad thing, but maybe
            # we should let the user decided if they want to continue.

            _logger.warning(_("""Unable to detect the running firewall service.  You may continue, but unexpected
                             results can occur if more than one firewall service is running.  This may lead to
                             your machine not being properly secured."""))

            self.cwrite('Do you want to continue this install? [y/N]:')
            result = sys.stdin.read(1)

            if result not in {'y', 'Y'}:
                _logger.debug('User aborting installation process.')
                return False

        if self._ufw:
            self.cwriteline('[OK]', 'Detected running ufw (uncomplicated firewall) instance.')

        if self._firewalld:
            self.cwriteline('[OK]', 'Detected running firewalld instance.')

        if self._iptables:
            self.cwriteline('[OK]', 'Detected running iptables instance.')

        return True

    # Get the machine unique identifier or generate one for this machine.
    def _get_machine_id(self):

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

    def clean_up(self):

        # Use this method to clean up after a failed install
        self.cwrite('Cleaning up...')

        # if we are running as root, delete the configuration directory
        if self._root_user and self._config_root is not None and os.path.exists(self._config_root):
            shutil.rmtree(self._config_root)

        self.cwriteline('[OK]', 'Finished cleaning up.')
        return

    def start_install(self):

        # Check for external programs here
        self._ps = which('ps')
        self._pgrep = which('pgrep')

        if self._ps is None or self._pgrep is None:
            _logger.critical('Unable to determine which services are running on this machine.')
            return False

        if not self._determine_config_root():
            return False

        if not self._get_machine_id():
            return False

        if not self._check_parameters():
            return False

        if not self._init_system_check():
            return False

        if not self._firewall_check():
            return False

        if not self._sds_conn.connect_with_password(self.args.user, self.args.password):
            return False

        data = Node(
                platform=self._firewall_platform,
                os=platform.system().lower(),
                dist=platform.dist()[0],
                dist_version=platform.dist()[1],
                hostname=socket.gethostname(),
                python_version=sys.version.replace('\n', ''),
                machine_id=self._machine_id,
        )

        # Attempt to register this node on the SD server.
        self._node = self._sds_conn.register_node(data)

        if not self._node or self._node.id is None:
            return False

        return True

# TODO: Get interface list
    def get_interfaces(self):

        # use netifaces to get list of interfaces for this client

        return True

# TODO: Check for iptables executable (iptables package)

# TODO: Download rule sets from SD Server



# TODO: Check firewalld service is running and disable.

# TODO: Check iptables services are running and disable.

# TODO: Enable SD-Client service and start service


def debug_dump(args):
    # Output the command line arguments
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
    parser.add_argument(_('bundle'), help=_('Firewall bundle to use for this node'), default=None, type=str)
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
