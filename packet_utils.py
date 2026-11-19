"""Packet decoding helpers shared by the sniffer and offline analyzer."""
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP

COLUMNS = ["timestamp", "source", "destination", "protocol", "source_port", "destination_port", "length", "summary"]

def packet_to_row(pkt):
    try:
        source = destination = ""
        src_port = dst_port = None
        if IP in pkt:
            source, destination = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            source, destination = pkt[IPv6].src, pkt[IPv6].dst
        elif ARP in pkt:
            source, destination = pkt[ARP].psrc, pkt[ARP].pdst
        else:
            return None  # Not an IP or ARP packet
        if ARP in pkt:
            protocol = "ARP"
        elif TCP in pkt:
            protocol = "TCP"
            src_port, dst_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
        elif UDP in pkt:
            protocol = "UDP"
            src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
        elif ICMP in pkt or (IPv6 in pkt and int(pkt[IPv6].nh) == 58):
            protocol = "ICMP"
        else:
            protocol = "OTHER"
        if DNS in pkt and (TCP in pkt or UDP in pkt):
            protocol = "DNS"
        stamp = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        return (stamp, source, destination, protocol, src_port, dst_port, len(pkt), pkt.summary()[:240])
    except (ValueError, TypeError, AttributeError, OSError):
        return None
