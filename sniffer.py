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
    # Header length could be 20 or 26 bytes
    # We will ignore the optional extra 6 bytes of header data,
    # but we still need to know the length to get payload info later
    # Bit AND with b1111 to get header length
    header_length = (version_header_length & 15)
    # IP packet mandatory header info is within first 20 bytes of packet
    # format:  Ignore the first 8 bytes
    #          Assign 1 Unsigned Char (1byte) to Time to Live
    #          Assign 1 Unsigned Char to to Protocal
    #          Ignore next 2 bytes (Header Checksum)
    #          Assign 4 byte char array to Source IP
    #          Assign 4 byte char array to Destination IP
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4_format(src), ipv4_format(target), data[header_length:]

# Returns properly formatted IPv4 address
# def ipv4_format(addr):
#     return '.'.join(map(str, ))

