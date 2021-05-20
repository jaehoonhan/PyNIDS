import struct


class TCP:
    # TCP header size = 20 or 26 bytes

    def __init__(self, raw_data):
        # Unpack:
        # - first 2 bytes (Source port) as unsigned short
        # - next  2 bytes (Des_port) as unsigned short
        # - next  4 bytes (Sequence) as unsigned long
        # - next  4 bytes (ACK)
        # - next  2 bytes (Offset flags)
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack(
            '! H H L L H', raw_data[:14])

        # Manipulate bits in offset to get flags
        offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1

        self.data = raw_data[offset:]
