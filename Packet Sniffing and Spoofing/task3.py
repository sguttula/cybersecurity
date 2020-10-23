#!/usr/bin/python3

from scapy.all import *
a = IP()
a.dst = '172.217.4.132'
b = ICMP()
flag = True
ttl = 1
hops = []
while flag:
	a.ttl = ttl
	ans, unans = sr(a/b)
	if ans.res[0][1].type == 0:
		flag = False
	else:
		hops.append(ans.res[0][1].src)
		ttl+=1
i = 1
for hop in hops:
	print (i," " + hop)
	i+=1