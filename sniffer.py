import socket
import struct
import textwrap

def main():
    # Make a socket connection to make a copy of raw packet info, compatible with most machines
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
    
    bytes_str = map('{:02X}'.format, bytes_addr)
    return ':'.join(bytes_str)



