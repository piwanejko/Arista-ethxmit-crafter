Ethxmit can be used on Arista switches for traffic generation. Supported packet types are stored in _PACKET_TYPES value. Script is generating full bash command that can be used for sending crafted packets on dedicated interface.
Example:
    $ ./ethxmit-crafter.py -s 10.5.116.25 -d 224.0.0.22 -t 1 -i vlan3899 -T igmp_join 227.5.255.255 4

    sudo ethxmit --ip-src=10.5.116.25 --ip-dst=224.0.0.22 -D 0100.5e00.07FF --ttl=1 --ip-protocol=2 -s 54 --data-type=raw --data-value=2200F6F80000000104000000E305FFFF vlan3899