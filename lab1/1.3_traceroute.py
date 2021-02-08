from scapy.all import *
from time import sleep

for ttl in range(20):
    p = IP() / ICMP()
    p.dst = "31.13.68.35"

    p.ttl = ttl
    p.show()
    send(p)

    sleep(1)