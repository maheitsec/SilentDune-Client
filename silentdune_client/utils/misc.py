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
import socket
import sys
from subprocess import check_output, CalledProcessError

_logger = logging.getLogger('sd-client')


def which(program):
    """
    Find the path for a given program
    http://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
    """

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None


def node_info_dump(args):
    """
    Output information about this machine.
    """
    # Basic system detections
    _logger.debug('System = {0}'.format(platform.system()))

    # Current distribution
    _logger.debug('Distribution = {0}'.format(platform.dist()[0]))
    _logger.debug('Distribution Version = {0}'.format(platform.dist()[1]))

    # Python version
    _logger.debug('Python Version: {0}'.format(sys.version.replace('\n', '')))

    _logger.debug(args)


def determine_config_root():
    """
    Determine where we are going to write the SD node configuration file.
    """

    home = os.path.expanduser('~')
    root_failed = False
    home_failed = False

    config_root = '/etc/silentdune'

    # Test to see if we are running as root
    if os.getuid() == 0:
        test_file = os.path.join(config_root, 'test.tmp')

        try:
            if not os.path.exists(config_root):
                os.makedirs(config_root)
            h = open(test_file, 'w')
            h.close()
            os.remove(test_file)

        except OSError:
            root_failed = True

    else:
        root_failed = True

    # If root access has failed, try the current user's home directory
    if root_failed:
        config_root = os.path.join(home, '.silentdune')
        test_file = os.path.join(config_root, 'test.tmp')

        try:
            if not os.path.exists(config_root):
                os.makedirs(config_root)
            h = open(test_file, 'w')
            h.close()
            os.remove(test_file)

        except OSError:
            home_failed = True

    # Check if both locations failed.
    if root_failed and home_failed:
        _logger.critical('Unable to determine a writable configuration path for this node.')
        return None

    return config_root


def get_init_system():
    """
    Return the active init system on this node.
    :return:
    """
    # See if this system is an upstart setup.
    if which('initctl') is not None and os.path.isfile(which('initctl')):
        return 'upstart'

    # See if this system is a systemd setup.
    if which('systemctl') is not None and os.path.exists('/run/systemd/system'):
        return 'systemd'

    # See if this system is a sysvinit setup, must be after upstart and systemd detection.
    if which('service') is not None:
        return 'sysv'

    return None


def is_process_running(name):
    """
    Determine if the specified process is running.
    :param name: Name of service.
    :return: True if service is running, False if not found.
    """
    pgrep = which('pgrep')
    prog = which(name)

    if not prog:
        return False

    try:
        pid = check_output('{0} -f "{1}"'.format(pgrep, prog), shell=True)[:]
        if pid:
            return True
    except CalledProcessError:
        pass

    return False


def get_active_firewall():
    """
    Determine which firewall service is running on this system.
    :return: Firewall service name
    """
    if is_process_running('ufw'):
        return 'ufw'

    if is_process_running('firewalld'):
        return 'firewalld'

    if is_process_running('iptables'):
        return 'iptables'

    if is_process_running('sdc-firewall'):
        return 'sdc-firewall'

    return None


# http://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python
def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

