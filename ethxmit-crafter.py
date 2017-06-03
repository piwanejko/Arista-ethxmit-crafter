#!/usr/local/bin/python3

# Copyright (c) 2017, Atende Software
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

""" Ethxmit can be used on Arista switches for traffic generation. Supported packet types are stored in _PACKET_TYPES
    value. Script is generating full bash command that can be used for sending crafted packets on dedicated interface.
    Example:
        $ ./ethxmit-crafter.py -s 10.5.116.25 -d 224.0.0.22 -t 1 -i vlan3899 -T igmp_join 227.5.255.255 4
        
        sudo ethxmit --ip-src=10.5.116.25 --ip-dst=224.0.0.22 -D 0100.5e00.07FF --ttl=1 --ip-protocol=2 -s 54 
        --data-type=raw --data-value=2200F6F80000000104000000E305FFFF vlan3899
"""

import argparse
import re
import sys
import ipaddress


def validate_multicast_ip(ip_addr):
    if re.match("^([0-9]{1,3}\.){3}[0-9]{1,3}$", ip_addr):
        splited_ip = ip_addr.split('.')
        if not int(splited_ip[0]) in range(224, 240):
            return False
        if not int(splited_ip[1]) in range(0, 256):
            return False
        if not int(splited_ip[2]) in range(0, 256):
            return False
        if not int(splited_ip[3]) in range(0, 256):
            return False
        return True
    else:
        return False


def igmp_join(packet_data):
    """ Function is creating payload for IGMP Join/Leave packet for single multicast group.
        IGMP report format (RFC 3376):
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Type = 0x22  |    Reserved   |           Checksum            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |           Reserved            |  Number of Group Records (M)  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                        Group Record [1]                       .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      
      and group record:
      
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Multicast Address                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    # Validating multicast address and IGMP group record type
    if len(packet_data) == 2:
        if not validate_multicast_ip(packet_data[0]):
            print('Wrong multicast IP address, correct range: 224.0.0.0-239.255.255.255')
            sys.exit()
        if not int(packet_data[1]) in range(1, 7):
            print('Wrong group record type value, must be in range 1-6')
        # Constant fields
        igmp_type = 0x22
        group_records_count = 0x1
        aux_data_len = 0x0

        mc_address = ipaddress.IPv4Address(packet_data[0])
        record_type = int(packet_data[1])

        payload_no_checksum = '{:02X}{}{:04X}{:02X}{:02X}{}{:08X}'.format(igmp_type, 10*'0', group_records_count,
                                                                          record_type, aux_data_len, 4*'0',
                                                                          int(mc_address))
        igmp_checksum = checksum(payload_no_checksum)
        payload_with_checksum = '{}{:04X}{}'.format(payload_no_checksum[:4], igmp_checksum, payload_no_checksum[8:])
        return payload_with_checksum

    else:
        print('Missing IGMP join specific data, required: multicast_group_ip, group_record_type')
        sys.exit()


def checksum(payload):
    """ Function for checksum calculation of Hex payload. Payload is separated to two byte values that are added.
        If sum is higher than 2^16 carry bits are added to 16 bit base until final value is 16bit.
        Finally bits are flipped and checksum is returned.
    """
    octets = []
    while payload:
        octets.append(payload[:4])
        payload = payload[4:]

    summary = 0x0
    for octet in octets:
        summary += int(octet, 16)

    while summary > 65536:
        summary = (summary >> 16) + (summary & 0xFFFF)
    return (~ summary) & 0xFFFF


def parse_arguments():
    """ Parsing arguments.
    """
    parser = argparse.ArgumentParser(description='Script for crafting packets using ethxmit.')
    parser.add_argument('-s', dest='src_ip', help='Source IP', required=True)
    parser.add_argument('-d', dest='dst_ip', help='Destination IP', required=True)
    parser.add_argument('-D', dest='dst_mac', help='Destination MAC (default ffff.ffff.ffff)', required=False,
                        default='ffff.ffff.ffff')
    parser.add_argument('-t', '--ttl', help='Packet TTL', choices=range(1, 256), required=True, type=int,
                        metavar='(1-255)')
    parser.add_argument('-i', dest='interface', help='Output interface', required=True)
    parser.add_argument('-T', '--ptype', help='Packet type', choices=_PACKET_TYPES.keys(), required=True)
    parser.add_argument('DATA', help='Specific packet data', nargs='*')
    initial_args = parser.parse_args()

    # Validating IP and MAC addresses using regexp
    if not (re.match("^([0-9]{1,3}\.){3}[0-9]{1,3}$", initial_args.src_ip) and
            re.match("^([0-9]{1,3}\.){3}[0-9]{1,3}$", initial_args.dst_ip) and
            re.match("^([a-fA-F0-9]{4}\.){2}[a-fA-F0-9]{4}$", initial_args.dst_mac)):
        print("Wrong parameters")
        sys.exit()
    else:
        return initial_args


def craft_payload(parsed_args):
    """ Calling right function, given in ptype(-T) arg.
    """
    return _PACKET_TYPES[parsed_args.ptype](parsed_args.DATA)


def print_ethxmit_command(parsed_args, raw_payload):
    # If destination IP is multicast and dst_mac is broadcast, replace destination MAC address
    if validate_multicast_ip(parsed_args.DATA[0]) and parsed_args.dst_mac == 'ffff.ffff.ffff':
        mc_ip = ipaddress.IPv4Address(parsed_args.DATA[0])
        bits_for_dst_mac = '{:06X}'.format(int(mc_ip) & 0x7FF)
        parsed_args.dst_mac = '0100.5e{}.{}'.format(bits_for_dst_mac[:2], bits_for_dst_mac[2:])

    # Ethernet header + IP header + payload(bytes) + FCS
    packet_size = 34 + int(len(raw_payload)/2) + 4
    print('sudo ethxmit --ip-src={} --ip-dst={} -D {} --ttl={} --ip-protocol=2 -s {} --data-type=raw --data-value={} {}'
          ''.format(parsed_args.src_ip, parsed_args.dst_ip, parsed_args.dst_mac, parsed_args.ttl, packet_size,
                    raw_payload, parsed_args.interface))

# Supported packet types.
_PACKET_TYPES = {'igmp_join': igmp_join}

# Proceeded if ran as a script
if __name__ == '__main__':
    args = parse_arguments()
    packet_payload = craft_payload(args)
    print_ethxmit_command(args, packet_payload)
