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
from collections import OrderedDict

from utils.misc import determine_config_root

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0

_logger = logging.getLogger('sd-client')


class ClientConfiguration(object):

    _config_root = None
    _config_file = None
    _config_section = 'settings'  # This is the configuration file section name
    _config = OrderedDict()

    def __init__(self, config_file=None):

        self._config_root = determine_config_root()

        if not config_file:
            self._config_file = os.path.join(self._config_root, 'sdc.conf')

        # Setup the default values for the base settings
        self.set('settings', 'pidfile', '/var/run/silentdune/sdc.pid')

        self.set('settings', 'user', 'silentdune')
        self.set('settings', 'group', 'silentdune')
        self.set('settings', 'previous_firewall_service', '')
        self.set('settings', 'logfile', '/var/log/silentdune/sdc.log')

        # Set the section heading comments
        self.set_comment('settings', 'settings', (_('; Silent Dune Client Configuration File\n'  # noqa
                                                    '; This file was automatically generated by the installer.\n')))

        # Set the section item comments
        self.set_comment('settings', 'pidfile', _('; The path and file name for the PID file.\n'))  # noqa
        self.set_comment('settings', 'user', _('; The local user the service should run as.\n'  # noqa
                       '; Default: silentdune.\n'))
        self.set_comment('settings', 'group', _('; The local group the service should run as.\n'  # noqa
                        '; Default: silentdune.\n'))
        self.set_comment('settings', 'previous_firewall_service',
                         _('; The previous firewall service. Warning: Changing \n'  # noqa
                                            '; this value may compromise security on this system\n'
                                            '; if the Silent Dune client is uninstalled.\n'))

    def set(self, section, key, val):
        """
        Set a configuration value in the section specified.
        """
        if section not in self._config:
            self._config[section] = OrderedDict()

        self._config[section][key] = val

    def set_comment(self, section, key, comment):
        """
        Set the comments for a given key in the section specified.
        """

        if 'comments' not in self._config[section]:
            self._config[section]['comments'] = OrderedDict()

        self._config[section]['comments'][key] = comment

    def validate_config_file(self):
        """
        Check to see if the configuration file exists, is readable and valid.
        """

        if not os.path.exists(self._config_file):
            _logger.debug('Configuration file ({0}) does not exist.'.format(self._config_file))
            return None

        config = ConfigParser(dict_type=OrderedDict)

        try:
            config.read(self._config_file)
        except ConfigParser.Error:
            _logger.debug('Configuration file is invalid.')
            return None

        return config

    def read_config(self):
        """
        Read the configuration file.
        """
        # Return the saved configuration loaded by validate_config_file().
        return self.validate_config_file()

    def write_config(self):
        """
        Write out the configuration to a file, we do NOT use ConfigParser to write out the config.
        :param config: Must be a ConfigParser object.
        """
        try:

            with open(self._config_file, 'w') as handle:

                # Loop through each section
                for name, section in self._config.items():
                    _logger.debug('Config: writing section: {0}'.format(name))

                    # Write out the section name
                    handle.write('[' + name + ']\n')

                    # Write any section header comments
                    if name in section['comments']:
                        comment = section['comments'][name]
                        handle.write(comment.rstrip() + '\n\n')

                    # Write each section item out
                    for (key, value) in section.items():

                        if key == 'comments':
                            continue

                        _logger.debug('Config: Key {0}={1}'.format(key, value))

                        # Write item comments if found.
                        if key in section['comments']:
                            comment = section['comments'][key]
                            handle.write(comment.rstrip() + '\n')

                        handle.write(key + '=' + str(value) + '\n\n')
        except IOError:
            return False

        return True
