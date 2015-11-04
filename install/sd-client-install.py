#
# Authors: Robert Abram <robert.abram@entpack.com>
#
# Copyright (C) 2015 EntPack
# see file 'LICENSE' for use and warranty information
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

import gettext
import platform
import argparse
import os
import sys
import logging

if __name__ == '__main__':

    logger = None

    # TODO: Setup a set of paths to look for the translations and validate one for use
    # Translations path
    po_path = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), '../po')
    # gettext.install('sdc_install', po_path, unicode=1)
    _ = gettext.translation('sdc_install', po_path, fallback=False).ugettext

    # Setup arguments to program
    parser = argparse.ArgumentParser()
    parser.add_argument(_('--server'), help=_('Silent Dune server'), default=None, type=str)
    parser.add_argument(_('--user'), help=_('Authorized Silent Dune user name'), type=int, nargs=1)
    parser.add_argument(_('--password'), help=_('Password for authorized user'), default=None, type=str)
    parser.add_argument(_('--bundle'), help=_('Password for authorized user'), default=None, type=str)
    parser.add_argument(_('--debug'), help=_('Enable debug output'), default=False, action='store_true')
    args = parser.parse_args()

    # Set our logging options now that we have the program arguments. Set primary logger to os.devnull and let
    # child loggers handle logging output.
    # https://docs.python.org/3.5/library/logging.html#logrecord-attributes
    if args.debug:
        logging.basicConfig(filename=os.devnull,
                            datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
        # Setup logging formatter
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s (%(funcName)s)')
    else:
        logging.basicConfig(filename=os.devnull,
                            datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
        # Setup logging formatter
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

    # Setup logging handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # Setup logger
    logger = logging.getLogger()
    logger.addHandler(handler)

    # Output the command line arguments
    logger.debug(args)

    # Basic system detections
    logging.debug('System = {0}'.format(platform.system()))
    dist = platform.dist()
    logging.debug('Distribution = {0}'.format(dist[0]))
    logging.debug('Distribution Version = {0}'.format(dist[1]))

    sys.exit(0)


# TODO: Check parameters (SD Server, User, Password, Ring Group ID)

# TODO: Contact SD Server and register

# TODO: Download rule sets from SD Server

# TODO: Check for iptables executable (iptables package)

# TODO: Check firewalld service is running and disable.

# TODO: Check iptables services are running and disable.

# TODO: Enable SD-Client service and start service

 
