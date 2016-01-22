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

import io
import json
import logging
import operator
from datetime import datetime

_logger = logging.getLogger('sd-client')


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
        """
        # Convert dict to array of objects of type cls
        """
        if data is None:
            return None

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


class IPRulesFileWriter(object):
    """
    Object for writing iptables rules to a file
    """
    _chainsets = None

    def __init__(self, chainsets):
        self._chainsets = chainsets
        
    def _get_base_table_chains(self, table):
        """
        Return the builtin chains for the table specified and return the list.
        """
        chains = []

        if table == u'filter':
            chains = [u'INPUT', u'FORWARD', u'OUTPUT']
        elif table == u'nat':
            chains = [u'PREROUTING', u'OUTPUT', u'POSTROUTING']
        elif table == u'raw':
            chains = [u'PREROUTING', u'OUTPUT']
        elif table == u'mangle':
            chains = [u'PREROUTING', u'INPUT', u'FORWARD', u'OUTPUT', u'POSTROUTING']
        elif table == u'security':
            chains = [u'INPUT', u'FORWARD', u'OUTPUT']

        return chains

    def _output_rules(self, stream, version):
        """
        We will have one or more chainsets to loop through with each chainset having
        one or more IPChain objects.  We want to capture all of the IPChain objects,
        then loop through each one, match it to the iptables table we are looking at and then
        produce the data needed for writing the rules out.
        """

        # Loop through the iptables tables and write the rules for each one out.
        for table in {u'filter', 'nat', 'raw', 'mangle', 'security'}:

            bases = self._get_base_table_chains(table)

            # See if there is at least rule for this table and the built-in chains for the table.
            if not self._check_for_table_rules(bases, table, version):
                continue

            # Start outputing the rulings in iptables save file format
            s = u'# Generated by SilentDune Client on {0}\n'.format(
                    datetime.now().strftime(u'%a %b %d %H:%M:%S %Y'))
            s += u'*{0}\n'.format(table)  # Write out table name.
            stream.write(s)

            # Loop through and write out the builtin chain names for this table.
            for base in bases:
                s = u':{0} ACCEPT [0:0]\n'.format(base)
                stream.write(s)

            cnames = dict()

            # Loop through the chainsets and get the chain objects for each one.
            for chainset in iter(self._chainsets):
                if chainset.chains is not None:  # Make sure we don't have an empty IPChain list.
                    for chain in iter(chainset.chains):

                        # Only work with the IPChain objects that match the iptables table name.
                        if chain.name == table:

                            for base in bases:
                                cnames.update(chain.get_chain_names(chainset.slot, base, version))

            # Sort cnames by key (base iptables chain name), changes cnames from dict() to list of tuples.
            cnames = sorted(cnames.items(), key=operator.itemgetter(0))

            # Chain definitions need to be written in order of base chain name and slot id
            for base in bases:

                # Write out the chain definitions
                for key, val in cnames:
                    if val == base:
                        s = u':{0} - [0:0]\n'.format(key)
                        stream.write(s)

            # Chain jumps need to be written in order of base chain name and slot id
            for base in bases:

                # Write out the chain jumps
                for key, val in cnames:
                    if val == base:
                        s = u'-A {0} -j {1}\n'.format(val, key)  # val hold base chain name
                        stream.write(s)

            # Chain rules need to be written in order of base chain name and slot id
            for base in bases:

                # Write out the chain jumps, key contains the custom chain name.
                for key, val in cnames:
                    for chainset in iter(self._chainsets):
                        if chainset.chains is not None:  # Make sure we don't have an empty IPChain list.
                            chainset.write(stream, version, table, chainset.slot, key, base)

            s = u'COMMIT\n'
            stream.write(s)
            s = u'# Table {0} end\n'.format(table)
            stream.write(s)

            stream.flush()

    def _check_for_table_rules(self, chains, table, version):
        """
        We need to see if there is a IPRing object that matches the builtin chain and table
        in any of the chainsets we have. We are just looking for any match here.
        """
        cinfo = dict()

        # Loop through the iptables built-in table names.
        for c in chains:
            for cs in self._chainsets:
                if cs.check_for_chainset_rules(version, table, c):
                    return True  # Return true if we found a rule.

        return False

    def _output_rules_old(self, stream, version):

        if self._chainsets is None:
            _logger.error('Unable to write rules out, chainsets is None.')
            return False

        # Loop through the iptables tables and write the rules for each one out.
        for t in {u'filter', 'nat', 'raw', 'mangle', 'security'}:
            
            try:
                chains = self._get_base_table_chains(t)

                # TODO: Rewrite, loop and get a list of IPChain objects that match the table,
                # then prepare output for that table.

                # We will have one or more chainsets to loop through with each chainset having
                # one or more IPChain objects.  We want to capture all of the IPChain objects,
                # then loop through each one to produce the data needed for writing the rules out.





                # Now we need to see if there is a IPRing object that matches the builtin chain and table
                # in any of the chainsets we have. We are just looking for any match here.
                cinfo = dict()
                for c in chains:
                    for ol in self._chainsets:
                        name = ol.check_for_chain_rules(version, t, c)
                        if name is not None:
                            cinfo[c] = name

                # If we do not have any rules for this table, just loop.
                rules = False
                for k, c in cinfo.items():
                    if c is not None:
                        rules = True

                if not rules:
                    continue

                # Start outputing the rulings in iptables save file format
                s = u'# Generated by SilentDune Client on {0}\n'.format(
                        datetime.now().strftime(u'%a %b %d %H:%M:%S %Y'))
                s += u'*{0}\n'.format(t)  # Write out table name.
                stream.write(s)

                # Loop through and write out the builtin chain names for this table.
                for c in chains:
                    s = u':{0} ACCEPT [0:0]\n'.format(c)
                    stream.write(s)

                # TODO: Missing chains in output.
                # Loop through and write out the chain names for the chains we have rules for.
                for c in chains:
                    for ol in self._chainsets:
                        name = ol.check_for_chain_rules(version, t, c)
                        if name is not None:
                            s = u':{0} - [0:0]\n'.format(name)
                            stream.write(s)

                # Now loop and write out the first jump for the chains we have rules for.
                for k, c in cinfo.items():
                    if c is not None:
                        s = u'-A {0} -j {1}\n'.format(k, c)
                        stream.write(s)

                for ol in self._chainsets:
                    ol.write(stream, version, t)  # Write out the Chain rules.

                # TODO: Look and see if we have another chainset and write a jump line.

                s = u'COMMIT\n'
                stream.write(s)
                s = u'# Table {0} end\n'.format(t)
                stream.write(s)

                stream.flush()
                
            except IOError:
                return False

        # s = u':{0} ACCEPT [0:0]\n'.format(self.name.upper())
        # stream.write(s)

    def write_to_stream(self, stream, version):
        """
        Write iptables rules to a stream.
        :param stream: File stream stream
        :return: True if successful or False if failure.
        """
        return self._output_rules(stream)

    def write_to_file(self, file, version):
        """
        Write iptables rules to a stream.
        :param file: String with file path and name to write iptables rules to.
        :return: True if successful or False if failure.
        """
        with io.open(file, 'w') as stream:
            return self._output_rules(stream, version)


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

    def check_for_chainset_rules(self, version, table, base):

        if self.chains is not None:
            for c in iter(self.chains):  # Call child objects write_chain method.
                if c.name == table:  # Only call if the table name matches.
                    if c.check_for_chain_rules(version, base):
                        return True  # If we found a rule, just return True immediately.
        return False

    def write(self, stream, version, table, slot, chain, base):

        if self.chains is not None:
            for c in iter(self.chains):  # Call child objects write method.
                if c.name == table:  # Only call if the table name matches.
                    c.write(stream, version, table, slot, chain, base)


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

    def get_chain_prefix(self, name):

        if name.lower() == u'prerouting':
            return u'PRE'
        if name.lower() == u'postrouting':
            return u'POST'
        if name.lower() == u'forward':
            return u'FWD'
        if name.lower() == u'input':
            return u'IN'
        if name.lower() == u'output':
            return u'OUT'

        return None

    def get_chain_names(self, slot, cname, version):

        cnames = dict()

        # Build the suffix for the iptables Chain name.
        suffix = u'_{0}_{1}'.format(slot, self.id)

        # loop through the IPRing objects and build the iptables chain names.
        if self.rings is not None:
            for r in iter(self.rings):
                if r.version == version and r.name.lower() == cname.lower():
                    cnames[u'{0}{1}'.format(self.get_chain_prefix(r.name), suffix)] = cname  # save base chain name.

        return cnames

    def check_for_chain_rules(self, version, base):
        """
        Return True if there is a match by version and name
        """
        if self.rings is not None:
            for r in iter(self.rings):
                if r.version == version and r.name.upper() == base.upper():
                    return True

        return False

    def write(self, stream, version, table, slot, chain, base):

        # Build the suffix for the iptables Chain name.
        suffix = u'_{0}_{1}'.format(slot, self.id)

        if self.rings is not None:
            for r in iter(self.rings):  # Call child objects write method.
                n = u'{0}{1}'.format(self.get_chain_prefix(r.name), suffix)
                if r.version == version and r.name.lower() == base.lower() and chain == n:
                    r.write(stream, version, suffix, chain)


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

    def write(self, stream, version, suffix, chain):

        # Only write out rules if the versions match
        if version == self.version and self.rules is not None:
            for o in iter(self.rules):

                # iptables Chain name that the rule is attached to, matches the Chain name from write_chain.
                s = u'-A {0}'.format(chain)
                stream.write(s)

                # Write out the rule
                o.write(stream)

                # Add line feed
                stream.write(u'\n')


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

    def write(self, stream):

        if self.fragment is not None and self.fragment.id is not None:
            self.fragment.write(stream)

        if self.ifaceIn is not None and self.ifaceIn.id is not None:
            self.ifaceIn.write(stream)

        if self.ifaceOut is not None and self.ifaceOut.id is not None:
            self.ifaceOut.write(stream)

        if self.protocol is not None:  # Call child objects write method.
            for o in iter(self.protocol):
                o.write(stream)

        if self.source is not None:  # Call child objects write method.
            for o in iter(self.source):
                o.write(stream)

        if self.destination is not None:  # Call child objects write method.
            for o in iter(self.destination):
                o.write(stream)

        if self.matches is not None:  # Call child objects write method.
            for o in iter(self.matches):
                o.write(stream)

        if self.jump is not None and self.jump.id is not None:
            self.jump.write(stream)


class IPFragment(JsonObject):
    """
    Represents the IPFragmentSerializer json schema
    """
    id = None  # PK value
    fragment = None  # Fragment packet
    invert = None  # Invert value

    def write(self, stream):

        if self.fragment is True:
            s = u' {0}-f'.format(u'! ' if self.invert is True else u'')
            stream.write(s)


class IPProtocol(JsonObject):
    """
    Represents the IPProtocolSerializer json schema
    """
    id = None  # PK value
    name = None
    invert = None  # Invert name value

    def write(self, stream):
        s = u' -p{0} {1}'.format(u' !' if self.invert is True else u'', self.name)
        stream.write(s)


class IPSource(JsonObject):
    """
    Represents the IPSourceSerializer json schema
    """
    id = None  # PK value
    address = None  # Network address
    mask = None  # Network mask value
    invert = None  # Invert address value

    def write(self, stream):
        s = u' -s{0} {1}/{2}'.format(u' !' if self.invert is True else u'', self.address, self.mask)
        stream.write(s)


class IPDestination(JsonObject):
    """
    Represents the IPDestinationSerializer json schema
    """
    id = None  # PK value
    address = None  # Network address
    mask = None  # Network mask value
    invert = None  # Invert address value

    def write(self, stream):
        s = u' -d{0} {1}/{2}'.format(u' !' if self.invert is True else u'', self.address, self.mask)
        stream.write(s)


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

    def write(self, stream):
        s = u' -m {0}'.format(self.name)
        stream.write(s)

        for o in iter(self.options):  # Call child objects write method.
            o.write(stream)


class IPMatchOptions(JsonObject):
    """
    Represents the IPMatchOptionsSerializer json schema
    """
    id = None  # PK value
    option = None  # Option name
    value = None  # Option value
    invert = None  # Invert option value
    sortId = None

    def write(self, stream):
        s = u'{0} {1} {2}'.format(u' !' if self.invert is True else u'', self.option, self.value)
        stream.write(s)


class IPIFaceOut(JsonObject):
    """
    Represents the IPIFaceOutSerializer json schema
    """
    id = None  # PK value
    name = None  # Match name
    invert = None  # Invert name value

    def write(self, stream):
        s = u' -o{0} {1}'.format(u' !' if self.invert is True else u'', self.name)
        stream.write(s)


class IPIFaceIn(JsonObject):
    """
    Represents the IPIFaceInSerializer json schema
    """
    id = None  # PK value
    name = None  # Match name
    invert = None  # Invert name value

    def write(self, stream):
        s = u' -i{0} {1}'.format(u' !' if self.invert is True else u'', self.name)
        stream.write(s)


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

    def write(self, stream):
        s = u' -j {0}'.format(self.target)
        stream.write(s)

        for o in iter(self.params):  # Call child objects write method.
            o.write(stream)


class IPJumpOptions(JsonObject):
    """
    Represents the IPJumpOptionsSerializer json schema
    """
    id = None  # PK value
    name = None  # Option name
    value = None  # Option value

    def write(self, stream):
        s = u' {0} {1}'.format(self.name, self.value)
        stream.write(s)
