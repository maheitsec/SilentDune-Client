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
import platform
import random
import string

_logger = logging.getLogger('sd-client')


class CWrite(object):
    """
    Output messages to the console.
    """

    debug = False

    # http://stackoverflow.com/questions/11245381/formatting-console-output

    def cwrite(self, message, debug_msg=None):
        """
        Write a message to stdout or to debug logger with no linefeed.
        """

        if self.debug:
            if debug_msg is None:
                _logger.debug(message)
            else:
                _logger.debug(debug_msg)
        else:
            sys.stdout.write(message)
            sys.stdout.flush()

    def cwriteline(self, message, debug_msg=None):
        """
        Write a message to stdout or to debug logger with linefeed.
        """

        if self.debug:
            if debug_msg is None:
                _logger.debug(message)
            else:
                _logger.debug(debug_msg)
        else:
            print(message)
            sys.stdout.flush()


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


def setup_logging(debug=False):
    """
    Setup python logging
    """

    # Set our logging options now that we have the program arguments.
    if debug:
        logging.basicConfig(filename=os.devnull,
                            datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
        # Setup logging formatter
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    else:
        logging.basicConfig(filename=os.devnull,
                            datefmt='%Y-%m-%d %H:%M:%S', level=logging.WARNING)
        # Setup logging formatter
        formatter = logging.Formatter('%(levelname)s: %(message)s')

    # Setup logging handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # Set logger handler
    # _logger.addHandler(handler)

    return handler


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


def get_machine_id():
    """
    Find the machine unique identifier or generate one for this machine.
    """

    m_id = None
    f = os.path.join(determine_config_root(), 'machine-id')

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

    return m_id


def write_machine_id():
    """
    Create a new unique machine id for this node.
    """
    _logger.debug('Creating unique machine-id value.')

    m_id = ''.join(random.choice('abcdef' + string.digits) for _ in range(32))

    with open(os.path.join(determine_config_root(), 'machine-id'), 'w') as h:
        h.write(m_id + '\n')

    return m_id
