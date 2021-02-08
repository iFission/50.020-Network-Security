#!/usr/bin/python3
from scapy.all import *


def print_pkt(pkt):
    pkt.show()


pkt = sniff(filter='tcp port 23 and src host 10.0.2.1', prn=print_pkt)