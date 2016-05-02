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


from silentdune_client.builders import iptables as ipt
from silentdune_client.utils.misc import is_valid_ipv4_address, is_valid_ipv6_address


def create_tcp_server_conn_rule(addr, port, transport=ipt.TRANSPORT_AUTO, desc=''):
    """
    Create a rule that allows access to the given addr and port.
    :param addr: IP address, not host name.
    :param port:
    :return:
    """

    # Example: a = ipt.get_match(name='state', options=[ipt.get_match_option('--state', 'ESTABLISHED')])

    if transport == ipt.TRANSPORT_AUTO:
        if is_valid_ipv6_address(addr):
            transport = ipt.TRANSPORT_IPV6
        elif is_valid_ipv4_address(addr):
            transport = ipt.TRANSPORT_IPV4
        else:
            raise ValueError
    elif transport == ipt.TRANSPORT_IPV4:
        if not is_valid_ipv4_address(addr):
            raise ValueError
    elif transport == ipt.TRANSPORT_IPV6:
        if not is_valid_ipv6_address(addr):
            raise ValueError
    else:
        raise ValueError

    return ipt.get_machine_subset(
        desc,
        10,
        [
            ipt.get_chain(
                'filter',
                [
                    ipt.get_ring(
                        'input',
                        transport,
                        [
                            ipt.get_rule(
                                ip_protocol_name='tcp', source_address=addr, matches=[
                                    ipt.get_match('state', [ipt.get_jump_option('--state', 'ESTABLISHED'), ], ),
                                    ipt.get_match('tcp', [ipt.get_match_option('--sport', port), ], ),
                                ],
                                jump=ipt.get_jump(target='ACCEPT')
                            )]),
                    ipt.get_ring(
                        'output',
                        transport,
                        [
                            ipt.get_rule(
                                ip_protocol_name='tcp', dest_address=addr, matches=[
                                    ipt.get_match('state',
                                                  [ipt.get_jump_option('--state', 'NEW,ESTABLISHED'), ], ),
                                    ipt.get_match('tcp', [ipt.get_match_option('--dport', port), ], ),
                                ],
                                jump=ipt.get_jump(target='ACCEPT')
                            )
                        ]
                    ),
                ]
            )
        ]
    )
