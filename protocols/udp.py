import struct


class UDP:

    
    def __init__(self, raw_data):
        
        # Unpack:
        # - 2 bytes unsigned short (Source port)
        # - 2 bytes unsigned short (Destination port)
        # - 2 bytes unsigned short (Length)
        # - ignore 2 bytes (Checksum)
        self.src_port, self.dest_port, self.size = struct.unpack(
            '! H H H 2x', raw_data[:8])
        self.data = raw_data[8:]