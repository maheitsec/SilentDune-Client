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
import socket

import requests

from utilities import CWrite

_logger = logging.getLogger('sd-client')


class Node:

    id = None
    platform = None          # Firewall platform, IE: iptables
    os = None            # System, IE: linux, windows, macos, freebsd, netbsd.
    dist = None              # Distribution Name.
    dist_version = None      # Distribution Version.
    hostname = None
    python_version = None
    machine_id = None        # Unique machine ID.
    last_connection = None   # Last connection datetime stamp.
    node_sync = False        # It True, server is requesting this Node to push it's information to the server.
    notes = None             # Notes about this node

    def __init__(self, *args, **kwargs):
        """
        If parameter values in args, then the value is expected to be a dictionary from a node json response
        from the server.

        If parameter values are in kwargs, then they are named parameters passed when the object is instantiated.
        """
        if len(args) is not 0:
            for key, value in args[0].items():
                self.__dict__[key] = value
                # print('{0} : {1}'.format(key, value))

        else:
            for key, value in kwargs.items():
                self.__dict__[key] = value
                # print('{0} : {1}'.format(key, value))


class SDSConnection(CWrite):

    # Security
    _oauth_crypt_token = None
    _cookies = None
    authenticated = False

    # Connection Information
    _server = None
    _url = None
    _nossl = False
    _port = -1
    _user = None
    _password = None
    _ip = None

    def __init__(self, debug, server, nossl, port):

        self.debug = debug        
        self._server = server
        self._nossl = nossl
        self._port = port

    def _build_url(self):

        # Build base URL
        self._url = 'https://' if not self._nossl else 'http://'
        self._url += self._server
        self._url += '' if self._port == -1 else ':{0}'.format(self._port)

    # The purpose of this method is to authenticate the user and password against the SD server and
    # retrieve the encrypted Oauth2 token.
    def connect_with_password(self, username, password):

        if not username or not password:
            _logger.error('Invalid parameter passed.')
            raise ValueError

        self.authenticated = False

        _logger.debug('test debug')
        self.cwrite('Resolving server...  ')

        try:
            self._ip = socket.gethostbyname(self._server)
        except socket.error:
            _logger.error('Unable to resolve server ({0})'.format(self._server))
            return False

        self.cwriteline('[OK]', 'Server successfully resolved.')

        self.cwrite('Attempting to authenticate with SD server...  ')

        # Make a GET request so we can get the CSRF token.
        try:

            self._build_url()
            rq = requests.get('{0}/accounts/login/'.format(self._url))

            if rq.status_code != requests.codes.ok:
                _logger.error('Unable to retrieve CSRF token ({0})'.format(rq.status_code))
                return False

            csrf = rq.cookies['csrftoken']

        except Exception:
            _logger.error('CSRF token request attempt failed.')
            return False

        try:

            # Make a POST authentication request to get the encrypted oauth2 token
            rq = requests.post('{0}/accounts/login/'.format(self._url),
                               cookies=rq.cookies,
                               data={'grant_type': 'password', 'username': username, 'password': password,
                                     'csrfmiddlewaretoken': csrf})

            if rq.status_code != requests.codes.ok:
                _logger.error('Unable to authenticate to server ({0})'.format(rq.status_code))
                return False

        except requests.RequestException:
            _logger.error('Authentication request attempt failed')
            return False

        if rq.json() is None:
            _logger.error('Unknown error occurred parsing server response.')

        # Convert reply into JSON
        reply = rq.json()

        # Check reply status value
        if reply['status'] != 'OK':
            _logger.error('Server authentication request failed.')
            return False

        # Save token and cookies for later use
        self._oauth_crypt_token = rq.cookies['token']
        self._cookies = rq.cookies

        self.cwriteline('[OK]', 'Successfully authenticated with server.')

        self.authenticated = True

        return True

    def lookup_node_by_machine_id(self, machine_id):

        if not self.authenticated:
            _logger.error('Not authenticated to SD server.')
            return None

        try:

            self._build_url()
            rq = requests.get('{0}/api/nodes/?machine_id={1}'.format(self._url, machine_id),
                              cookies=dict(token=self._oauth_crypt_token))

        except requests.RequestException:
            _logger.error('Node lookup request failed.')

        if rq.status_code != requests.codes.ok:
            _logger.error('Lookup Node failed, unknown response.')
            return None

        reply = rq.json()

        if reply is None:
            return None

        # Use the first array element which is our node values
        return Node(reply[0])

    def register_node(self, node):

        self.cwrite('Registering Node...  ')

        if type(node) is not Node:
            _logger.error('Node parameter is not a Node object.')
            return None

        if not self.authenticated:
            _logger.error('Not authenticated to SD server.')
            return None

        # Setup a dictionary with the Node properties
        data = dict()
        for key, value in node.__dict__.items():
            if not key.startswith("__") and key is not 'id' and value is not None:
                data[key] = value

        try:
            self._build_url()
            rq = requests.post('{0}/api/nodes/'.format(self._url),
                                cookies=dict(token=self._oauth_crypt_token),
                                json=data)

        except requests.RequestException:
            _logger.error('Node registration request failed.')
            return None

        # Check to see if we received the proper response code
        if rq.status_code != requests.codes.created:

            # 400 means the node record might already exist, lets look for it.
            if rq.status_code == requests.codes.bad_request:

                node = self.lookup_node_by_machine_id(node.machine_id)

                if node is not None:
                    _logger.warning('Node already exists on server.')

                return node

            else:
                _logger.error('Register Node failed, unknown response.')
                return None

        # Get the ID of the registered node
        node.id = rq.json()['id']

        # for key, value in node.__dict__.items():
        #     if not key.startswith("__"):
        #         print('{0} = {1}'.format(key, value))

        self.cwriteline('[OK]', 'Node successfully registered.')

        return node




