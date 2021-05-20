import socket
import struct
from general.mac_addr import get_mac_addr


class Ethernet:
    # Frame header size = 14 bytes

    def __init__(self, raw_data):
        
        # According to the Ethernet frame, we should get the following by manipulating bytes
        # - Convert bytes from big to little endian with !
        # - Unpack first 6 bytes (Destination MAC) as char array
        # - Unpack next  6 bytes (Source MAC) as char array
        # - Unpack next  2 bytes (EtherType)
        dest, src, ether_type = struct.unpack('! 6s 6s H', raw_data[:14])

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(ether_type)
        self.data = raw_data[14:]
