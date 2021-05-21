#from ..protocols.tcp import TCP
from general.config import *

class TCP_Scan:

    def __init__(self, filename):
        with open(filename) as f:
            self.bad_ports = f.readlines()
        self.bap_ports = [x.strip() for x in self.bad_ports] 
    
    def check_bad_port(self, tcp):
        check = False
        if tcp.src_port in self.bad_ports:
            print(TAB_1 + "**WARNING: POTENTIALLY MALICIOUS SOURCE PORT**")
            check = True
        if tcp.dest_port in self.bad_ports:
            print(TAB_1 + "**WARNING: POTENTIALLY MALICIOUS TARGET PORT**")
            check = True
        
        return check