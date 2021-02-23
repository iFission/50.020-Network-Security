#!/usr/bin/python3
from scapy.all import *

Qdsec = DNSQR(qname='abcde.example.com')

dns = DNS(id=0xAAAA,
          qr=0,
          qdcount=1,
          ancount=0,
          nscount=0,
          arcount=0,
          qd=Qdsec)

ip = IP(dst='10.0.2.7', src='10.0.2.6')

udp = UDP(dport=53, sport=45000, chksum=0)

spoofed_packet = ip / udp / dns

spoofed_packet.show()
send(spoofed_packet)

with open('lab3/ip_req.bin', 'wb') as f:
    f.write(bytes(spoofed_packet))
