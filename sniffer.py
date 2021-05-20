import socket
import struct
import textwrap

def main():
    # Make a socket connection to make a copy of raw packet info
    # *AF_PACKET is a socket type exlusive to Linux. 
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536) # Buffer size is 65536 (max)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame: ')
        print('Destination: {}, Source: {}, Protocol: {}'.format())


# Unpack ethernet frame
def ethernet_frame(data):
 
    # Take the first 14 bytes of data (frame header)
    # Convert the bytes from big to little endian with !
    # Take the first 6 bytes, 6 bytes, and an unsigned short
    # These values are the destination MAC, source MAC, and EtherType
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])

    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# Return properly formatted MAC address
def get_mac_addr(bytes_addr):
    # Format MAC address bytes into two digits joined by colons
    bytes_str = map('{:02X}'.format, bytes_addr)
    return ':'.join(bytes_str)


# Unpack IPV4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    # Bit shift Ip by 4 bits to get the version
    version = version_header_length >> 4
    # Header size = 20 or 26 bytes
    # Bit AND with b1111 to get header length
    header_length = (version_header_length & 15)
    # IP packet mandatory header info is within first 20 bytes of packet
    # According to the IP packet structure we can manipulate the binary data to get the following:
    #   - Pad (ignore) the first 8 bytes (First two 'rows' of header)
    #   - Unpack next 1 byte (Time to Live) as Unsigned Char
    #   - Unpack next 1 byte (Protocal number) as Unsigned Char
    #   - Pad next 2 bytes (Header Checksum)
    #   - Unpack next 4 byte (Source IP) as char array
    #   - Unpack next 4 byte (Destination IP) as char array
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4_format(src), ipv4_format(target), data[header_length:]

# Returns properly formatted IPv4 address
def ipv4_format(addr):
    return '.'.join(map(str, ))


# Unpack ICMP Packet
def icmp_packet(data):
    # ICMP Header size = 4 bytes
    #   - Format first 1 bstyte (TCMP Type) as unsigned char
    #   - Format next 1 byte (Code) as unsigned char
    #   - Format next 2 bytes (Checksum) as usigned short
    # (We keep checksum here because it is useful for network analysis)
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment
def tcp_segment(data):
    # TCP header size = 20 or 26 bytes
    #   - Unpack first 2 bytes (Source port) as unsigned short
    #   - Unpack next 2 bytes (Des_port) as unsigned short
    #   - Unpack next 4 bytes (Sequence) as unsigned long
    #   - Unpack next 4 bytes (ACK)
    #   - Unpack next 2 bytes (Offset flags)
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    # Manipulate bits in offset to get flags
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin

