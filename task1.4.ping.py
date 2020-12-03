#!/usr/bin/python3
from scapy.all import *

a=IP()
a.dst = '1.2.3.4'
b=ICMP()
p=a/b
send(p)

