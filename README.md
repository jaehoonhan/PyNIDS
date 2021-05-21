# PyNIDS

## Overview

- A python local area network intrusion detection program that captures network packets, dissembles them by bytes, and analyzes the packets to check for suspicious activity. 
- Packets can be monitored live via terminal prints, or viewed later on the pcap file that of the most recent run.
- Built from scratch, with no third-party security tools.

## Requirement
  - Python 3.x
  - Administrative priveleges on your machine
  - Linux Operating System

## Usage

```
git clone https://github.com/jaehoonhan/PySniff.git
cd PySniff
sudo python3 sniffer.py [INT]
^c    (Exit program)

Optional arguments:
 INT            Set a number of packets to sniff before exiting
                otherwise set to infinity.
               
```
pcap file will be overwritten at every scan. Make a duplicate if you wish to analyze multiple traffic histories.
- sample output:

![alt text](https://i.imgur.com/nDLnRNI.jpg)
- sample output with known malicious IP adddress in packet:

![alt text](https://i.imgur.com/bvuvW9w.jpg)
