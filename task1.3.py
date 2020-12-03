#!/usr/bin/python
from scapy.all import *

a=IP()
a.dst='8.8.8.8'
b=ICMP()
for x in range(20):
    a.ttl=x
    send(a/b)
    time.sleep(1)
