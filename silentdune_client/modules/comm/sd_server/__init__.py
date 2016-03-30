#
# Authors: Robert Abram <robert.abram@entpack.com>,
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

from collections import OrderedDict
import pkg_resources

from silentdune_client.utils.configuration import BaseConfig
from silentdune_client.modules import BaseModule


class SilentDuneServerModule(BaseModule):
    """ Silent Dune Server Module """

    def __init__(self):

        # Set our module name
        self._name = 'SilentDuneServerModule'

        # Set our BaseConfig derived object here.
        self._config = SilentDuneServerConfig()

        try:
            self._version = pkg_resources.get_distribution(__name__).version
        except:
            self._version = 'unknown'


class SilentDuneServerConfig(BaseConfig):
    """ Silent Dune Server Module Configuration """

    def _prepare_config(self):
        """
        Return the configuration file structure. Any new configuration items should be added here.
        Note: The order should be reverse of the expected order in the configuration file.
        """

        settings = OrderedDict()

        settings['server'] = ''
        settings['port'] = ''
        settings['use_tls'] = 'yes'

        config = OrderedDict()

        # Define the configuration section for this module
        config['server_module'] = settings

        return config

    def _get_comments_by_key(self, key):
        """
        Return the configuration comments for the given key.
        Note: Each comment line must start with '; ' and end with '\n'.
        """

        return {
            'server_module': (_('; Silent Dune Server Module Configuration\n')),  # noqa
            'server': (_('; The Silent Dune management server to connect with.\n')),  # noqa
            'port': (_('; The port used by the management server. If no port is given this\n'  # noqa
                       '; node will use port 80 or 443 to connect to the management server\n'
                       '; depending on if the --no-tls option was used during the install.\n')),
            'use_tls': (_('; Use a secure connection when communicating with the management server.')),  # noqa
        }.get(key, '\n')


