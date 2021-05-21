#from ..protocols.ipv4 import IPv4
from general.config import *

class IP_Scan:

    def __init__(self, filename):
        with open(filename) as f:
            self.bad_ips = f.readlines()
        # strip() works differently on linux, don't change the below
        for x in range(len(self.bad_ips)):
            self.bad_ips[x] = self.bad_ips[x].strip()
        # self.bap_ips = [x.strip() for x in self.bad_ips] 
    
    def check_bad_ip(self, ipv4):
        check = False
        if ipv4.src in self.bad_ips:
            print(TAB_1 + "**WARNING: POTENTIALLY MALICIOUS SOURCE IP**")
            check = True
        if ipv4.target in self.bad_ips:
            print(TAB_1 + "**WARNING: POTENTIALLY MALICIOUS TARGET IP**")
            check = True
        
        return check
    
