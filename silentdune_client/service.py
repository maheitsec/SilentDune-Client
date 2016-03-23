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

import sys
import os
import socket
import logging
import signal
import argparse
import gettext
import multiprocessing

from daemon import Daemon
from utilities import *

_logger = logging.getLogger('sd-client')

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0


class SDCDaemon(Daemon):

    def process_tasks(self, qu):

        _logger.debug('Silent Dune client daemon started.')

        while True:

            try:
                task = qu.get(1.0)
            except multiprocessing.TimeoutError:
                continue

        _logger.debug('Slient Dune client thread closed cleanly')


def run():

    def signal_term_handler(signal, frame):

        if not daemon.stopProcessing:
            _logger.warning("got SIGTERM, quitting")
        daemon.stopProcessing = True

    # Setup i18n - Good for 2.x and 3.x python.
    kwargs = {}
    if sys.version_info[0] < 3:
        kwargs['unicode'] = True
    gettext.install('sdc_install', **kwargs)

    # Setup program arguments.
    parser = argparse.ArgumentParser(prog='sdc-service')
    sp = parser.add_subparsers()
    sp.add_parser('start', help=_('Starts %(prog) daemon'))  # noqa
    sp.add_parser('stop', help=_('Stops %(prog) daemon'))  # noqa
    sp.add_parser('restart', help=_('Restarts %(prog) daemon'))  # noqa
    parser.add_argument('-c', '--config', help=_('Use config file'), default=None, type=str)  # noqa
    parser.add_argument('--debug', help=_('Enable debug output'), default=False, action='store_true')  # noqa
    args = parser.parse_args()

    # Setup logging now that we know the debug parameter
    _logger.addHandler(setup_logging(args.debug))

    # Dump debug information
    if args.debug:
        debug_dump(args)

    # Read the configuration file
    config = read_config_file(args.config)

    daemon = SDCDaemon(args)

    return 0


# --- Main Program Call ---
if __name__ == '__main__':
    sys.exit(run())
