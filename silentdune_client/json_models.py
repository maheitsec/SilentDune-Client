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

import json


class JsonObject(object):

    _json_data = False

    def __init__(self, *args, **kwargs):
        """
        If parameter values in args, then the value is expected to be a dictionary from a node json response
        from the server.

        If parameter values are in kwargs, then they are named parameters passed when the object is instantiated.
        """
        if args is not None and len(args) is not 0 and args[0] is not None:
            self._json_data = True
            for key, value in args[0].items():
                self.__dict__[key] = value
                # print('{0} : {1}'.format(key, value))

        else:
            for key, value in kwargs.items():
                self.__dict__[key] = value
                # print('{0} : {1}'.format(key, value))

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True)

    def to_dict(self):
        data = dict()
        for key, value in self.__dict__.items():
            if not key.startswith("__") and value is not None:
                data[key] = value
        return data

    def dict_to_obj_array(self, cls, data):

        if data is None:
            return None

        # Convert dict to array of objects of type cls
        ol = list()

        for x in range(0, len(data)):
            ol.append(cls(data[x]))

        return ol


class Bundle(JsonObject):
    """
    Represents the BundleSerializer json schema
    """
    id = None
    platform = None
    name = None
    desc = None
    notes = None
    default = False


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


class IPBundleChainSet(JsonObject):
    """
    Represents the IPBundleSetSerializer json schema
    """
    id = None
    chainset = None


class IPChainSet(JsonObject):
    """
    Represents the IPChainSetSerializer json schema
    """
    id = None  # PK value
    name = None
    desc = None
    notes = None
    platform = None
    slot = None
    sortId = None
    chains = None  # Array of IPChain objects

    def __init__(self, *args, **kwargs):
        super(IPChainSet, self).__init__(args[0], kwargs)
        self.chains = self.dict_to_obj_array(IPChain, self.chains)

    def write(self, handle, version):

        if self.chains is not None:
            for o in self.chains:
                o.write(handle, version)


class IPChain(JsonObject):
    """
    Represents the IPChainSerializer json schema
    """
    id = None  # PK value
    name = None  # iptables table name
    rings = None  # Array of IPRing objects

    def __init__(self, *args, **kwargs):
        super(IPChain, self).__init__(args[0], kwargs)
        self.rings = self.dict_to_obj_array(IPRing, self.rings)

    def write(self, handle, version):

        if self.rings is not None:
            for o in self.rings:
                o.write(handle, version)


class IPRing(JsonObject):
    """
    Represents the IPRingSerializer json schema
    """
    id = None  # PK value
    name = None
    version = None  # Transport version ipv4 or ipv6
    rules = None  # Array of IPRule objects

    def __init__(self, *args, **kwargs):
        super(IPRing, self).__init__(args[0], kwargs)
        self.rules = self.dict_to_obj_array(IPRule, self.rules)

    def write(self, handle, version):

        # Only write out rules if the versions match
        if version == self.version and self.rules is not None:
            for o in self.rules:

                s = u'-A {0}'.format(self.name.upper())
                handle.write(s)

                # Write out the rule
                o.write(handle)

                # Add line feed
                handle.write(u'\n')


class IPRule(JsonObject):
    """
    Represents the IPRuleSerializer json schema
    """
    id = None  # PK value
    enabled = None  # Is rule active
    sortId = None
    desc = None
    ifaceIn = None  # single IPIFaceIn object
    ifaceOut = None  # single IPIFaceOut object
    protocol = None  # Array of IPProtocol objects
    source = None  # Array of IPSource objects
    destination = None  # Array of IPDestination objects
    fragment = None  # Single IPFragment object
    matches = None  # Array of IPMatches objects
    jump = None  # Single IPJump object

    def __init__(self, *args, **kwargs):
        super(IPRule, self).__init__(args[0], kwargs)
        self.ifaceIn = None if self.ifaceIn is None else IPIFaceIn(self.ifaceIn)
        self.ifaceOut = None if self.ifaceOut is None else IPIFaceOut(self.ifaceOut)
        self.protocol = self.dict_to_obj_array(IPProtocol, self.protocol)
        self.source = self.dict_to_obj_array(IPSource, self.source)
        self.destination = self.dict_to_obj_array(IPDestination, self.destination)
        self.fragment = None if self.fragment is None else IPFragment(self.fragment)
        self.matches = self.dict_to_obj_array(IPMatch, self.matches)
        self.jump = None if self.jump is None else IPJump(self.jump)

    def write(self, handle):

        if self.fragment is not None and self.fragment.id is not None:
            self.fragment.write(handle)

        if self.ifaceIn is not None and self.ifaceIn.id is not None:
            self.ifaceIn.write(handle)

        if self.ifaceOut is not None and self.ifaceOut.id is not None:
            self.ifaceOut.write(handle)

        if self.protocol is not None:
            for o in self.protocol:
                o.write(handle)

        if self.source is not None:
            for o in self.source:
                o.write(handle)

        if self.destination is not None:
            for o in self.destination:
                o.write(handle)

        if self.matches is not None:
            for o in self.matches:
                o.write(handle)

        if self.jump is not None and self.jump.id is not None:
            self.jump.write(handle)


class IPFragment(JsonObject):
    """
    Represents the IPFragmentSerializer json schema
    """
    id = None  # PK value
    fragment = None  # Fragment packet
    invert = None  # Invert value

    def write(self, handle):

        if self.fragment is True:
            s = u' {0}-f'.format(u'! ' if self.invert is True else u'')
            handle.write(s)


class IPProtocol(JsonObject):
    """
    Represents the IPProtocolSerializer json schema
    """
    id = None  # PK value
    name = None
    invert = None  # Invert name value

    def write(self, handle):
        s = u' -p{0} {1}'.format(u' !' if self.invert is True else u'', self.name)
        handle.write(s)


class IPSource(JsonObject):
    """
    Represents the IPSourceSerializer json schema
    """
    id = None  # PK value
    address = None  # Network address
    mask = None  # Network mask value
    invert = None  # Invert address value

    def write(self, handle):
        s = u' -s{0} {1}/{2}'.format(u' !' if self.invert is True else u'', self.address, self.mask)
        handle.write(s)


class IPDestination(JsonObject):
    """
    Represents the IPDestinationSerializer json schema
    """
    id = None  # PK value
    address = None  # Network address
    mask = None  # Network mask value
    invert = None  # Invert address value

    def write(self, handle):
        s = u' -d{0} {1}/{2}'.format(u' !' if self.invert is True else u'', self.address, self.mask)
        handle.write(s)


class IPMatch(JsonObject):
    """
    Represents the IPMatchSerializer json schema
    """
    id = None  # PK value
    name = None  # Match name
    options = None  # Array of IPMatchOptions objects

    def __init__(self, *args, **kwargs):
        super(IPMatch, self).__init__(args[0], kwargs)
        self.options = self.dict_to_obj_array(IPMatchOptions, self.options)

    def write(self, handle):
        s = u' -m {0}'.format(self.name)
        handle.write(s)

        for o in self.options:
            o.write(handle)


class IPMatchOptions(JsonObject):
    """
    Represents the IPMatchOptionsSerializer json schema
    """
    id = None  # PK value
    option = None  # Option name
    value = None  # Option value
    invert = None  # Invert option value

    def write(self, handle):
        s = u'{0} {1} {2}'.format(u' !' if self.invert is True else u'', self.option, self.value)
        handle.write(s)


class IPIFaceOut(JsonObject):
    """
    Represents the IPIFaceOutSerializer json schema
    """
    id = None  # PK value
    name = None  # Match name
    invert = None  # Invert name value

    def write(self, handle):
        s = u' -o{0} {1}'.format(u' !' if self.invert is True else u'', self.name)
        handle.write(s)


class IPIFaceIn(JsonObject):
    """
    Represents the IPIFaceInSerializer json schema
    """
    id = None  # PK value
    name = None  # Match name
    invert = None  # Invert name value

    def write(self, handle):
        s = u' -i{0} {1}'.format(u' !' if self.invert is True else u'', self.name)
        handle.write(s)


class IPJump(JsonObject):
    """
    Represents the IPJumpSerializer json schema
    """
    id = None  # PK value
    target = None
    params = None  # Array of IPJumpOption objects

    def __init__(self, *args, **kwargs):
        super(IPJump, self).__init__(args[0], kwargs)
        self.params = self.dict_to_obj_array(IPJumpOptions, self.params)

    def write(self, handle):
        s = u' -j {0}'.format(self.target)
        handle.write(s)

        for o in self.params:
            o.write(handle)


class IPJumpOptions(JsonObject):
    """
    Represents the IPJumpOptionsSerializer json schema
    """
    id = None  # PK value
    name = None  # Option name
    value = None  # Option value

    def write(self, handle):
        s = u' {0} {1}'.format(self.name, self.value)
        handle.write(s)
