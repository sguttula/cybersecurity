#!/usr/bin/python3

from scapy.all import *

a = IP()
a.src = '8.8.8.8'	
a.dst = '10.0.2.7'		
b = ICMP()
p = a/b
send(p)