#!/usr/bin/python3
from scapy.all import *

print("SNIFFING PACKETS...")

def print_pkt(pkt):
        pkt.show()

pkt = sniff(filter='tcp and dst port 23',prn=print_pkt)

