from scapy.all import *


def reply_with_spoofed_packet(packet_ethernet):
    if packet_ethernet["IP"]["ICMP"].type == ICMP(type="echo-request").type:
        print("found ICMP echo-request packet!")
        packet_ethernet["IP"].show()

        print()

        print("spoofing ICMP echo-reply packet")

        spoofed_packet = IP(dst=packet_ethernet["IP"].src,
                            src=packet_ethernet["IP"].dst) / ICMP(
                                type="echo-reply",
                                id=packet_ethernet["IP"]["ICMP"].id,
                                seq=packet_ethernet["IP"]["ICMP"].seq
                            ) / packet_ethernet["IP"]["ICMP"].load
        spoofed_packet.show()
        send(spoofed_packet)


pkt = sniff(filter='icmp', prn=reply_with_spoofed_packet)