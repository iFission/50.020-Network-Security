#!/usr/bin/python3
from scapy.all import *


def print_pkt(pkt):
    pkt.show()


pkt = sniff(filter='host 192.168.2', iface="ens38", prn=print_pkt)
