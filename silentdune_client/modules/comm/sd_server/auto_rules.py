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


from silentdune_client.utils import iptables_builder as ipb


def create_server_conn_rule(addr, port):
    """
    Create a rule that allows access to the given addr and port.
    :param addr:
    :param port:
    :return:
    """

    # Example: a = ipb.get_match(name='state', options=[ipb.get_match_option('--state', 'ESTABLISHED')])

    return ipb.get_machine_subset(
        'Allow access to Silent Dune server.',
        10,
        [
            ipb.get_chain(
                'filter',
                [
                    ipb.get_ring(
                        'input',
                        'ipv4',
                        [
                            ipb.get_rule(
                                ip_protocol_name='tcp', source_address=addr, matches=[
                                    ipb.get_match('state', [ipb.get_jump_option('--state', 'ESTABLISHED'), ], ),
                                    ipb.get_match('tcp', [ipb.get_match_option('--sport', port), ], ),
                                ],
                                jump=ipb.get_jump(target='ACCEPT')
                            )]),
                    ipb.get_ring(
                        'output',
                        'ipv4',
                        [
                            ipb.get_rule(
                                ip_protocol_name='tcp', dest_address=addr, matches=[
                                    ipb.get_match('state',
                                                  [ipb.get_jump_option('--state', 'NEW,ESTABLISHED'), ], ),
                                    ipb.get_match('tcp', [ipb.get_match_option('--dport', port), ], ),
                                ],
                                jump=ipb.get_jump(target='ACCEPT')
                            )
                        ]
                    ),
                ]
            )
        ]
    )
