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
import sys

_logger = logging.getLogger('sd-client')


def setup_logging(debug=False, logfile=None):
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

    # If we have a logfile, send output to it.
    if logfile:
        # Setup file logging handler
        handler = logging.FileHandler(logfile)
        handler.setFormatter(formatter)
        _logger.addHandler(handler)
    else:
        # Setup stream logging handler
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        _logger.addHandler(handler)

    return handler
