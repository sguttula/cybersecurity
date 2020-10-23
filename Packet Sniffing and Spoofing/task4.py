#!/usr/bin/python3

from scapy.all import *

def spoof_pkt(pkt):
		if ICMP in pkt and pkt[ICMP].type == 8:
			print("ORIGINAL PACKET")
			print("Source IP: ", pkt[IP].src)
			print("Destination IP: ", pkt[IP].src)
			
			data = pkt[Raw].load

			ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
			icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
			
			newpkt = ip/icmp/data
			newpkt.show()
			
			print("SPOOFED PACKET")
			print("Source IP: ", newpkt[IP].src)
			print("Destination IP: ", newpkt[IP].dst)
			send(newpkt, verbose=0)
			
pkt = sniff(filter='icmp and src host 10.0.2.7',prn=spoof_pkt)