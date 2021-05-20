import struct


class ICMP:
    # ICMP Header size = 4 bytes

    def __init__(self, raw_data):

        #   - Unpack first 1 byte (TCMP Type) as unsigned char
        #   - Unpack next  1 byte (Code) as unsigned char
        #   - Unpack next  2 bytes (Checksum) as usigned short
        # (We keep checksum here because it is useful for network analysis)
        type, code, checksum = struct.unpack('! B B H', raw_data[:4])

        self.type = type
        self.code = code
        self.checksum = checksum
        self.data = raw_data[4:]
