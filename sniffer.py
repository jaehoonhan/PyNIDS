import socket
from general.pcap import Pcap
from general.textwrapper import format_multi_line
from protocols.ethernet import Ethernet
from protocols.ipv4 import IPv4
from protocols.icmp import ICMP
from protocols.tcp import TCP
from protocols.udp import UDP

line_width = 60
LINEBREAK = ''.join(['_' for _ in range(line_width)])
TAB_1 = '   - '
TAB_2 = '       - '
TAB_3 = '           - '
TAB_4 = '               - '

DATA_TAB_1 = '    '
DATA_TAB_2 = '         '
DATA_TAB_3 = '             '
DATA_TAB_4 = '                 '

def main():
    
    pcap = Pcap('capture.pcap')
    # Make a socket connection to make a copy of raw packet info
    # *AF_PACKET is a socket type exlusive to Linux.
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)

        print(LINEBREAK + '\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac,
              eth.src_mac, eth.proto))

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(
                ipv4.version, ipv4.header_length, ipv4.ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto,
                  ipv4.src, ipv4.target))

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                print(TAB_2 + 'ICMP Packet:')
                print(TAB_3 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type,
                      icmp.code, icmp.checksum))
                print(TAB_3 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                print(TAB_2 + 'TCP Segment:')
                print(
                    TAB_3 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print(
                    TAB_3 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_3 + 'Flags:')
                print(TAB_4 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg,
                      tcp.flag_ack, tcp.flag_psh))
                print(TAB_4 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst,
                      tcp.flag_syn, tcp.flag_fin))
                 
                if len(tcp.data) > 0:
                    if tcp.src_port != 80 or tcp.dest_port != 80:
                        print(TAB_3 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                print(TAB_2 + 'UDP Segment:')
                print(TAB_3 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(
                    udp.src_port, udp.dest_port, udp.size))

            # Other IPv4
            else:
                print(TAB_2 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, ipv4.data))

        else:
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, eth.data))

    pcap.close()


main()
