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
import io

from utilities import CWrite
from json_models import *

_logger = logging.getLogger('sd-client')


class SDSConnection (CWrite):

    # Security
    _oauth_crypt_token = None
    _cookies = None
    authenticated = False

    # Connection Information
    _server = None
    _base_url = None
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

    def _build_base_url(self):

        # Build base URL
        self._base_url = 'https://' if not self._nossl else 'http://'
        self._base_url += self._server
        self._base_url += '' if self._port == -1 else ':{0}'.format(self._port)

    def _make_json_request(self, reqtype, url, data=None):

        reply = None
        status_code = None
        rq = None

        if not self.authenticated:
            _logger.error('Not authenticated to SD server.')
            return reply, status_code, rq

        try:

            self._build_base_url()
            u = '{0}{1}'.format(self._base_url, url)

            if reqtype is 'GET':
                rq = requests.get(u, cookies=dict(token=self._oauth_crypt_token))
            elif reqtype is 'POST':
                rq = requests.post(u, data=data, cookies=dict(token=self._oauth_crypt_token))
            elif reqtype is 'PUT':
                rq = requests.put(u, data=data, cookies=dict(token=self._oauth_crypt_token))
            elif reqtype is 'DELETE':
                rq = requests.delete(u, cookies=dict(token=self._oauth_crypt_token))
            elif reqtype is 'HEAD':
                rq = requests.head(u, cookies=dict(token=self._oauth_crypt_token))
            elif reqtype is 'OPTIONS':
                rq = requests.options(u, cookies=dict(token=self._oauth_crypt_token))

        except requests.Timeout:
            _logger.error('Server request timeout.')
        except requests.ConnectionError:
            _logger.error('Server connection error.')
        except requests.RequestException:
            _logger.error('Server request failed.')
        else:

            try:
                reply = rq.json()
            except ValueError:
                pass

            status_code = rq.status_code

        return reply, status_code, rq

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

            self._build_base_url()
            rq = requests.get('{0}/accounts/login/'.format(self._base_url))

            if rq.status_code != requests.codes.ok:
                _logger.error('Unable to retrieve CSRF token ({0})'.format(rq.status_code))
                return False

            csrf = rq.cookies['csrftoken']

        except Exception:
            _logger.error('CSRF token request attempt failed.')
            return False

        try:

            # Make a POST authentication request to get the encrypted oauth2 token
            rq = requests.post('{0}/accounts/login/'.format(self._base_url),
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

    def get_node_by_machine_id(self, machine_id):
        """
        Request Node object from server filtered by machine_id value.
        :param machine_id:
        :return Node object:
        """

        url = '/api/nodes/?machine_id={0}'.format(machine_id)

        reply, status_code, rq = self._make_json_request('GET', url)

        if reply is not None and status_code == requests.codes.ok:
            return Node(reply[0])

        _logger.error('Node lookup request failed.')

        return None

    def register_node(self, node):
        """
        Register Node on server.
        :param node:
        :return Node:
        """
        if isinstance(node, None):
            _logger.critical('Node parameter is not valid in register_node method.')
            return None

        reply, status_code, rq = self._make_json_request('POST', '/api/nodes/', node.to_dict())

        if reply is not None and status_code is not None:

            # 201 means the node record was created successfully.
            if status_code == requests.codes.created:
                # Get the ID of the registered node
                node.id = rq.json()['id']

                return Node

        return None

    def get_bundle_by_name(self, name):
        """
        Request Bundle object from server filtered by name value.
        :param name:
        :return Bundle:
        """

        url = '/api/bundles/?name={0}'.format(name)

        reply, status_code, rq = self._make_json_request('GET', url)

        if reply is not None and status_code == requests.codes.ok and len(reply) > 0:
            return Bundle(reply[0])

        return None

    def get_default_bundle(self):
        """
        Request Bundle object from server filtered by name value.
        :param name:
        :return Bundle:
        """

        url = '/api/bundles/?default'

        reply, status_code, rq = self._make_json_request('GET', url)

        if reply is not None and status_code == requests.codes.ok and len(reply) > 0:
            return Bundle(reply[0])

        return None

    def create_or_update_node_bundle(self, nb):

        # if isinstance(nb, NodeBundle):  <-- Not working, unsure why.
        if nb is None:
            _logger.critical('NodeBundle parameter is not valid in create_or_update_node_bundle method.')
            return None

        url = '/api/nodes/{0}/bundle/'.format(nb.node)

        # NodeBundleViewSet will update or create with a POST request.
        reply, status_code, rq = self._make_json_request('POST', url, nb.to_dict())

        if reply is not None and \
                (status_code == requests.codes.created or status_code == requests.codes.ok):
            return NodeBundle(reply)

        return None

    def get_bundle_chainsets(self, nb):

        # if isinstance(nb, NodeBundle):  <-- Not working, unsure why.
        if nb is None:
            _logger.critical('NodeBundle parameter is not valid in create_or_update_node_bundle method.')
            return None

        url = '/api/bundles/{0}/chainsets/'.format(nb.bundle)

        reply, status_code, rq = self._make_json_request('GET', url)

        if reply is not None and status_code == requests.codes.ok:
            # chainsets = [IPBundleChainSet(id=id, chainset=chainset) for id, chainset in reply[0].items()]
            # return chainsets
            for i, c in reply[0].items():

                url = '/api/iptables/chainsets/{0}/'.format(c)

                reply, status_code, rq = self._make_json_request('GET', url)

                if reply is not None and status_code == requests.codes.ok:

                    chainset = IPChainSet(reply)

                    with io.open('rule4.txt', 'w') as h:
                        chainset.write(h, u'ipv4')
                        h.flush()

                    with io.open('rule6.txt', 'w') as h:
                        chainset.write(h, u'ipv6')
                        h.flush()



        return None
