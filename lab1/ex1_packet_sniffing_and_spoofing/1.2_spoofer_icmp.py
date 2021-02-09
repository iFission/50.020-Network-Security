from scapy.all import *

p = IP() / ICMP()
p.src = "10.0.2.11"
p.dst = "10.0.2.1"
p.show()

send(p)
