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

from silentdune_client.utils.misc import determine_config_root

_logger = logging.getLogger('sd-client')


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


def node_info_dump(args):
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
