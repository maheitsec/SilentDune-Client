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

import logging
import os
import platform
import random
import string
import sys
from subprocess import check_output, CalledProcessError


from utils.console import ConsoleBase
from utils.misc import which, determine_config_root

_logger = logging.getLogger('sd-client')


class NodeInformation(ConsoleBase):

    # External programs
    ps = None
    pgrep = None
    sed = None
    iptables_exec = None
    iptables_save = None
    iptables_restore = None

    # Configuration Items
    root_user = False
    config_root = None
    machine_id = None
    pid_file = None
    log_file = None

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

    error = False

    def __init__(self):

        # Gather information about this node.
        self.config_root = determine_config_root()
        if not self.config_root:
            error = True
            return

        # Change the default path for pid and log file to home directory.
        self.pid_file = os.path.join(self.config_root, 'sdc.pid')
        self.log_file = os.path.join(self.config_root, 'sdc.log')

        if not self._check_for_external_progs():
            self.error = True
        elif not self._init_system_check():
            self.error = True
        elif not self._firewall_check():
            self.error = True
        elif not self._get_machine_id():
            self.error = True

    def _check_for_external_progs(self):
        """
        Find external programs used by this client.
        """

        self.ps = which('ps')
        self.pgrep = which('pgrep')
        self.sed = which('sed')
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
                output = check_output(['service', 'iptables status'], shell=True)[:]

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

    def _get_machine_id(self):
        """
        Find the machine unique identifier or generate one for this machine.
        """

        m_id = None
        f = os.path.join(self.config_root , 'machine-id')

        _logger.debug('Looking up the machine-id value.')

        # See if we have an exiting machine-id file in our config root
        if os.path.exists(f):
            with open(f, 'r') as handle:
                m_id = handle.readline().strip('\n')

        if not m_id:

            # See if we can find a machine-id file on this machine
            for p in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
                if os.path.isfile(p):
                    with open(p) as handle:
                        m_id = handle.readline().strip('\n')

        # If we can't find an existing machine id, make one up.
        if not m_id:
            m_id = self._write_machine_id()

        self.machine_id = m_id

        return True

    def _write_machine_id(self):
        """
        Create a new unique machine id for this node.
        """
        _logger.debug('Creating unique machine-id value.')

        m_id = ''.join(random.choice('abcdef' + string.digits) for _ in range(32))

        with open(os.path.join(self.config_root, 'machine-id'), 'w') as h:
            h.write(m_id + '\n')

        return m_id

    def node_info_dump(self, args):
        """
        Output information about this node.
        """
        _logger.debug(args)

        # Basic system detections
        _logger.debug('System = {0}'.format(platform.system()))

        # Current distribution
        _logger.debug('Distribution = {0}'.format(platform.dist()[0]))
        _logger.debug('Distribution Version = {0}'.format(platform.dist()[1]))

        # Python version
        _logger.debug('Python Version: {0}'.format(sys.version.replace('\n', '')))

    def _run_service_command(self, cmd, name):
        """
        Helper function for running system service commands.
        """
        cmd = None

        # Sys V service
        if self.sysv_installed:
            prog = 'service'
            args = '{0} {1}'.format(name, cmd)

        # SystemD
        if self.sysd_installed:
            prog = 'systemctl'
            args = '{0} {1}'.format(cmd, name)

        if self.ups_installed:
            prog = '{0}'.format(cmd)
            args = '{1}'.format(name)

        try:
            check_output([prog, args])
            return True
        except CalledProcessError:
            _logger.error('Program "{0} {1}" did not run successfully.'.format(prog, args))

        return False

    def start_service(self, name):
        """
        Start a system service.
        :param name: Name of service
        :return: True if successful, otherwise False
        """
        return self._run_service_command('start', name)

    def stop_service(self, name):
        """
        Stop a system service.
        :param name: Name of service
        :return: True if successful, otherwise False
        """
        return self._run_service_command('stop', name)

    def disable_service(self, name):
        """
        Disable a system service.
        :param name: Name of service
        :return: True if successful, otherwise False
        """
        # Sys V
        if self.sysv_installed:
            return self._run_service_command('disable', name)

        # System D mask service
        if self.sysd_installed:
            return self._run_service_command('mask', name)

        if self.ups_installed:
            # Upstart requires an override file to disable the service
            try:
                check_output(['echo', '"manual" >> /etc/init/{0}.override'.format(name)])
                return True
            except CalledProcessError:
                _logger.error('Unable to create upstart service override file.')

        return False

    def enable_service(self, name):
        """
        Enable a system service.
        :param name: Name of service
        :return: True if successful, otherwise False
        """
        # Sys V
        if self.sysv_installed:
            return self._run_service_command('enable', name)

        # System D mask service
        if self.sysd_installed:
            return self._run_service_command('unmask', name)

        if self.ups_installed:

            file = '/etc/init/{0}.override'.format(name)
            # Check to see if the override file exists.
            if os.path.exists(file):
                os.remove(file)
            else:
                try:
                    check_output([self.sed, "-i '/manual/d' '/etc/init/{0}'".format(name)])
                    return True
                except CalledProcessError:
                    _logger.error('Enabling upstart service failed.')

        return False
