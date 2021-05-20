import struct


class IPv4:
    # IP Header size = 20 or 26 bytes

    def __init__(self, raw_data):
        
        version_header_length = raw_data[0]
        # Bit shift Ip by 4 bits to get the version
        self.version = version_header_length >> 4
        # Bit AND with b1111 to get header length
        self.header_length = (version_header_length & 15) * 4
        # Unpack:
        #   - Ignore the first 8 bytes (First two 'rows' of header)
        #   - next 1 byte (Time to Live) as Unsigned Char
        #   - next 1 byte (Protocal number) as Unsigned Char
        #   - ignore next 2 bytes (Header Checksum)
        #   - next 4 byte (Source IP) as char array
        #   - next 4 byte (Destination IP) as char array
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.reformat_ipv4(src)
        self.target = self.reformat_ipv4(target)
        self.data = raw_data[self.header_length:]

    # Returns properly formatted IPv4 address
    def reformat_ipv4(self, addr):
        return '.'.join(map(str, addr))