# PySniff

## Overview

- A python packet sniffer that allows you to monitor local network traffic by capturing ethernet packets, dissembling them, and printing their info as they pass your computer.
- Built from scratch, with no third-party modules.

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
pcap file will be overwritten at every scan. Make a duplicate if you wish to analyze a scan in the future
