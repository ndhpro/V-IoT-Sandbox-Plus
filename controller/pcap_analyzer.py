import ipaddress
import sys

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


def is_ip_local(ipaddr):
    """Returns True if ip address is in local range.
    :param ipaddr: String IP address.
    :returns: True x False.
    """
    ip = int(ipaddress.ip_address(ipaddr))

    # 10.x.x.x
    if ip >= 167772160 and ip < 184549376:
        return True

    # 172.16.0.0 - 172.31.255.255
    if ip >= 2886729728 and ip < 2887778304:
        return True

    # 192.168.x.x
    if ip >= 3232235520 and ip < 3232301056:
        return True

    if ip >= 3758096384:
        return True

    return False


def process_pcap(file_name):
    # print('Opening {}...'.format(file_name))
    fl = True
    ret = set()

    try:
        for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
            ether_pkt = Ether(pkt_data)
            if 'type' not in ether_pkt.fields:
                # LLC frames will have 'len' instead of 'type'.
                # We disregard those
                continue

            if ether_pkt.type != 0x0800:
                # disregard non-IPv4 packets
                continue

            ip_pkt = ether_pkt[IP]
            if not is_ip_local(str(ip_pkt.dst)):
                ret.add(ip_pkt.dst)
    except Exception as e:
        fl = False
        print(e)

    return ret, fl


if __name__ == "__main__":
    ip_list = process_pcap(sys.argv[1])
    with open('ip_list.txt', 'w') as f:
        for ip in ip_list:
            f.write(ip + '\n')
