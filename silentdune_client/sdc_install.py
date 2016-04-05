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
from subprocess import check_output, CalledProcessError

import utils.configuration as configuration
from utils.configuration import ClientConfiguration
from utils.console import ConsoleBase
from utils.log import setup_logging
from utils.misc import which, determine_config_root
from utils.node_info import get_machine_id, write_machine_id, node_info_dump
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

    # External programs
    ps = None
    pgrep = None
    iptables_exec = None
    iptables_save = None
    iptables_restore = None

    # Configuration Items
    root_user = False
    config_root = None
    config_p = None
    machine_id = None

    # Upstart
    ups_installed = False

    # Systemd
    sysd_installed = False

    # sysvinit
    sysv_installed = False

    # Previous firewall service
    ufw = False
    firewalld = False
    iptables = False

    # Firewall_platform - Currently only iptables is supported.
    firewall_platform = 'iptables'

    def __init__(self, args, modules):

        self.__modules = modules

        self.config_p = ConfigParser(allow_no_value=True)
        self.args = args

    def _check_for_external_progs(self):

        # Check for external programs here
        self.ps = which('ps')
        self.pgrep = which('pgrep')
        self.iptables_exec = which('iptables')
        self.iptables_save = which('iptables-save')
        self.iptables_restore = which('iptables-restore')

        if self.ps is None or self.pgrep is None:
            _logger.critical('Unable to determine which services are running on this machine.')
            return False

        if self.iptables is None or self.iptables_save is None or self.iptables_restore is None:
            _logger.critical('Unable to find iptables executables.')
            return False

        return True

    def _init_system_check(self):
        """
        Determine which init system is running on this system.
        """

        self.cwrite('Determining Init system...  ')

        # See if this system is an upstart setup.
        self.ups_installed = which('initctl') is not None and os.path.isfile(which('initctl'))

        # See if this system is a systemd setup.
        self.sysd_installed = which('systemctl') is not None and os.path.exists('/run/systemd/system')

        # See if this system is a sysvinit setup.
        self.sysv_installed = which('service') is not None and not self.sysd_installed and not self.ups_installed

        # If we didn't detect the init system, abort.
        if not self.ups_installed and not self.sysd_installed and not self.sysv_installed:
            _logger.critical('Unable to detect init system used on this machine.')
            return False

        if self.ups_installed:
            self.cwriteline('[OK]', 'Detected Upstart based init system.')
        if self.sysd_installed:
            self.cwriteline('[OK]', 'Detected Systemd based init system.')
        if self.sysv_installed:
            self.cwriteline('[OK]', 'Detected sysvinit based init system.')

        return True

    def _firewall_check(self):
        """
        Determine which firewall service is running on this system.
        """

        self.cwrite('Checking for firewall service...  ')

        pgrep = self.pgrep

        # Check to see if ufw is running
        if self.ups_installed:

            prog = which('ufw')

            if prog:

                try:
                    pid = check_output('{0} -f "{1}"'.format(pgrep, prog), shell=True)[:]

                    if pid and len(pid) > 1:
                        self.ufw = True
                        self.cwriteline('[OK]', 'Detected running ufw (uncomplicated firewall) instance.')

                except CalledProcessError:
                    pass

            else:
                _logger.debug('ufw executable not found.')

        # Check to see if firewalld is running
        if self.sysd_installed:

            prog = which('firewalld')

            if prog:

                try:
                    pid = check_output('{0} -f "{1}"'.format(pgrep, prog), shell=True)[:]

                    if pid and len(pid) > 1:
                        self.firewalld = True
                        self.cwriteline('[OK]', 'Detected running firewalld instance.')

                except CalledProcessError:
                    pass

            else:
                _logger.debug('firewalld executable not found.')

        # The iptables service could be running regardless of the init system used on this machine.
        # Test for a running iptables instance.
        if not self.ufw and not self.firewalld:

            # Check the iptables service status
            # TODO: Need a different check for each init system
            try:
                output = check_output('service iptables status', shell=True)[:]

                if output and len(output) > 1 and \
                        'unrecognized service' not in output and 'Table:' in output:
                    self.iptables = True
                    self.cwriteline('[OK]', 'Detected running iptables instance.')

            except CalledProcessError:
                pass

        # check to see that we detected a running firewall service
        if not self.ufw and not self.firewalld and not self.iptables:

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

    def write_config(self):
        """
        Setup the configuration and write it out.
        """

        # Create an empty configuration object, using the default path and filename.
        cc = ClientConfiguration()

        # Check to see if we are using a home directory.
        home = os.path.join(os.path.expanduser('~'), '.silentdune')
        if self.config_root == home:
            # Change the default path for pid and log file to home directory.
            cc.set('settings', 'pidfile', os.path.join(home, 'sdc.pid'))
            cc.set('settings', 'logfile', os.path.join(home, 'sdc.log'))

        # Set the previous firewall service
        pfws = 'unknown'

        if self.ufw:
            pfws = 'ufw'
        elif self.firewalld:
            pfws = 'firewalld'
        elif self.iptables:
            pfws = 'iptables'

        cc.set('settings', 'previous_firewall_service', pfws)

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
        if self.root_user and self.config_root is not None and os.path.exists(self.config_root):
            shutil.rmtree(self.config_root)

        self.cwriteline('[OK]', 'Finished cleaning up.')
        return

    def start_install(self):
        """
        Begin installing the Silent Dune Client.
        """

        if not self._check_for_external_progs():
            return False

        self.config_root = determine_config_root()
        if not self.config_root:
            return False

        # Have each module do their pre install work now.
        for mod in self.__modules:
            if not mod.pre_install(self):
                return False

        # Determine the unique machine id for this client
        self.machine_id = get_machine_id()
        if not self.machine_id:
            self.machine_id = write_machine_id()
        if not self.machine_id:
            return False

        if not self._init_system_check():
            return False

        if not self._firewall_check():
            return False

        # Have each module do their install work now.
        for mod in self.__modules:
            if not mod.install_module(self):
                return False

        if not self.write_config():
            return False

        # TODO: Make sure PID path and Log path are created and set to the proper user, group and mask.

        # TODO: Check firewalld service is running and disable.

        # TODO: Check iptables services are running and disable.

        # TODO: Enable SD-Client service and start service

        # Have each module do their post install work now.
        for mod in self.__modules:
            if not mod.post_install(self):
                return False

        return True


def run():
    # # Figure out our root directory
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

    # Have each module validate arguments.
    for mod in module_list:
        if not mod.validate_arguments(args):
            parser.print_help()
            exit(1)

    # Dump debug information
    if args.debug:
        node_info_dump(args)

    i = Installer(args, module_list)

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
