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

from silentdune_client.models.json_base import JsonObject


class Node(JsonObject):
    """
    Represents the NodeSerializer json schema
    """
    id = None  # PK value
    platform = None  # Firewall platform, IE: iptables
    os = None  # System, IE: linux, windows, macos, freebsd, netbsd.
    dist = None  # Distribution Name.
    dist_version = None  # Distribution Version.
    hostname = None
    python_version = None
    machine_id = None  # Unique machine ID.
    last_connection = None  # Last connection datetime stamp.
    node_sync = False  # If True, server is requesting this Node to push it's information to the server.
    notes = None  # Notes about this node


class NodeBundle(JsonObject):
    """
    Represents the NodeBundleSerializer json schema
    """
    id = None  # PK value
    node = None  # Node ID value
    bundle = None  # Bundle ID value