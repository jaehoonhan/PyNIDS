# Return properly formatted MAC address
def get_mac_addr(bytes_addr):
    # Format MAC address bytes into two digits joined by colons
    bytes_str = map('{:02X}'.format, bytes_addr)
    return ':'.join(bytes_str)