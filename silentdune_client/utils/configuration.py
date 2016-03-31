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


class BaseConfig(object):

    _config_root = None
    _config_file = None
    _config = None

    def __init__(self, config_file=None):

        self._config_root = determine_config_root()

        if not config_file:
            self._config_file = os.path.join(self._config_root, 'sdc.conf')

    def _prepare_config(self):
        """
        Return the configuration file structure. Any new configuration items should be added here.
        Note: The order should be reverse of the expected order in the configuration file.
        """

        settings = OrderedDict()

        settings['pidfile'] = '/var/run/silentdune/sdc.pid'
        settings['user'] = 'silentdune'
        settings['group'] = 'silentdune'
        settings['server'] = ''
        settings['port'] = ''
        settings['use_tls'] = 'yes'
        settings['previous_firewall_service'] = ''
        settings['logfile'] = '/var/log/silentdune/sdc.log'

        config = OrderedDict()

        # Define the configuration section for this module
        config['settings'] = settings

        return config

    def _get_comments_by_key(self, key):
        """
        Return the configuration comments for the given key.
        Note: Each comment line must start with '; ' and end with '\n'.
        """

        return {
            'settings': (_('; Silent Dune Client Configuration File\n'  # noqa
                           '; This file was automatically generated by the installer.\n')),
            'pidfile': (_('; The path and file name for the PID file.\n')),  # noqa
            'user': (_('; The local user the service should run as.\n'  # noqa
                       '; Default: silentdune.\n')),
            'group': (_('; The local group the service should run as.\n'  # noqa
                        '; Default: silentdune.\n')),
            'server': (_('; The Silent Dune management server to connect with.\n')),  # noqa
            'port': (_('; The port used by the management server. If no port is given this\n'  # noqa
                       '; node will use port 80 or 443 to connect to the management server\n'
                       '; depending on if the --no-tls option was used during the install.\n')),
            'use_tls': (_('; Use a secure connection when communicating with the management server.')),  # noqa
            'previous_firewall_service': (_('; The previous firewall service. Warning: Changing \n'  # noqa
                                            '; this value may compromise security on this system\n'
                                            '; if the Silent Dune client is uninstalled.\n')),
        }.get(key, '\n')

    def validate_config_file(self):
        """
        Check to see if the configuration file exists, is readable and valid.
        """

        if not os.path.exists(self._config_file):
            _logger.debug('Configuration file ({0}) does not exist.'.format(self._config_file))
            return False

        config = ConfigParser(dict_type=OrderedDict)

        try:
            config.read(self._config_file)
        except ConfigParser.Error:
            _logger.debug('Configuration file is invalid.')
            return False

        # Save the configuration for later
        self._config = config

        return True

    def create_blank_config(self, config=None):
        """
        Create a new blank configuration.
        """

        if not config:
            config = ConfigParser(dict_type=OrderedDict)

        struct = self._prepare_config()

        for section, items in struct.items():

            # Add new section to the ConfigParser object
            config.add_section(section)

            # Loop through the items in the dict, adding them to the ConfigParser object.
            for (key, value) in items.items():
                config.set(section, key, value)

        return config

    def read_config(self):
        """
        Read the configuration file.
        """

        if not self.validate_config_file():
            return None

        # Return the saved configuration loaded by validate_config_file().
        return self._config

    def write_config(self, config):
        """
        Write out the configuration to a file, we do NOT use ConfigParser to write out the config.
        :param config: Must be a ConfigParser object.
        """

        try:

            with open(self._config_file, 'w') as handle:

                # Loop through each section
                for section in config.sections():
                    _logger.debug('Config: writing section: {0}'.format(section))

                    comment = self._get_comments_by_key(section)
                    handle.write(comment.rstrip() + '\n\n')
                    handle.write('[' + section + ']\n\n')

                    for (key, value) in config.items(section):
                        _logger.debug('Config: Key {0}={1}'.format(key, value))

                        comment = self._get_comments_by_key(key)
                        handle.write(comment.rstrip() + '\n')
                        handle.write(key + '=' + value + '\n\n')
        except IOError:
            return False

        return True
