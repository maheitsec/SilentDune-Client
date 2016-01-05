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

_logger = logging.getLogger('sd-client')


class CWrite:

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
