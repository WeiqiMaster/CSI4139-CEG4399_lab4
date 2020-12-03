#!/usr/bin/python3
from scapy.all import *

def spoofing(pkt):
    a=IP()
    a.src = pkt[IP].dst
    a.dst = '192.168.175.155'

    b = ICMP()
    b.type = 0

    p = a/b
    send(p)
    pkt.show()
    p.show()

pkt = sniff(filter='icmp', prn=spoofing)
