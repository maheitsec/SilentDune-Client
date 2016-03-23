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

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0

_logger = logging.getLogger('sd-client')


class CWrite(object):

    debug = False

    # http://stackoverflow.com/questions/11245381/formatting-console-output

    # Write a message to stdout or to debug logger with no linefeed.
    def cwrite(self, message, debug_msg=None):

        if self.debug:
            if debug_msg is None:
                _logger.debug(message)
            else:
                _logger.debug(debug_msg)
        else:
            sys.stdout.write(message)
            sys.stdout.flush()

    # Write a message to stdout or to debug logger with linefeed.
    def cwriteline(self, message, debug_msg=None):

        if self.debug:
            if debug_msg is None:
                _logger.debug(message)
            else:
                _logger.debug(debug_msg)
        else:
            print(message)
            sys.stdout.flush()


# http://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
def which(program):

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
    Determine where we are going to write the SD client configuration file.
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
        _logger.critical('Unable to determine a writable configuration path for the client.')
        return None

    if root_failed and not home_failed:
        _logger.warning('Not running as root, setting configuration path to "{0}"'.format(config_root))
        _logger.warning('Since we are not running as root, system firewall settings will not be changed.')

        _logger.debug('Configuration root set to "{0}"'.format(config_root))

    return config_root


def read_config_file(file):
    """
    Read the configuration file
    """

    config = ConfigParser()

    # If empty parameter, figure out the location of the configuration file.
    if not file:
        file = os.path.join(determine_config_root(), 'sdc.conf')

    if os.path.isfile(file):
        config.read(file)
        _logger.debug('Using config file: {0}'.format(file))
        return config
    else:
        _logger.error('Config file ({0}) not found'.format(file))

    return None


def write_config_file(obj, include, file=None):
    """
    Write the configuration file from the object, only writing out the values from the include list.
    """

    config = ConfigParser()
    config.add_section('Client')

    for attr, value in obj.__dict__.items():
        if attr in include:
            config.set('Client', attr, value if value else '')

    # If empty parameter, figure out the location of the configuration file.
    if not file:
        file = os.path.join(determine_config_root(), 'sdc.conf')

    with open(file, 'wb') as h:
        config.write(h)

    return config

