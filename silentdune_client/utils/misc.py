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
import socket

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

    if root_failed and not home_failed:
        _logger.warning('Not running as root, setting configuration path to "{0}"'.format(config_root))
        _logger.warning('Since we are not running as root, system firewall settings will not be changed.')

        _logger.debug('Configuration root set to "{0}"'.format(config_root))

    return config_root


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
