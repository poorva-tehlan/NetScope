"""Best-effort hostname attribution from observed DNS A/AAAA answers and TLS ClientHello SNI.

No payload contents are persisted. Domain attribution is evidence-based, not an IP-owner guess.
"""
import ipaddress
import struct
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw


def clean_hostname(value):
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='ignore')
    return str(value or '').strip().rstrip('.').lower()[:253]


def service_from_host(host):
    host = clean_hostname(host)
    if not host:
        return 'Unknown'
    rules = [
        ('YouTube', ('youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com', 'youtube-nocookie.com', 'youtubei.googleapis.com')),
        ('Google', ('google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com')),
        ('Instagram', ('instagram.com', 'cdninstagram.com')),
        ('WhatsApp', ('whatsapp.com', 'whatsapp.net')),
        ('Facebook', ('facebook.com', 'fbcdn.net')),
        ('Netflix', ('netflix.com', 'nflxvideo.net', 'nflximg.net')),
        ('GitHub', ('github.com', 'githubusercontent.com')),
        ('Microsoft', ('microsoft.com', 'microsoftonline.com', 'windows.com')),
        ('Cloudflare', ('cloudflare.com',)),
    ]
    for name, suffixes in rules:
        if any(host == d or host.endswith('.' + d) for d in suffixes):
            return name
    return 'Other (' + host + ')'


def dns_answers(pkt):
    """Yield (address, domain) only for observed DNS responses, not speculative requests."""
    if DNS not in pkt or not pkt[DNS].qr:
        return
    dns = pkt[DNS]
    try:
        question_name = clean_hostname(dns.qd.qname) if dns.qdcount and dns.qd else ''
        rr = dns.an
        for _ in range(min(int(dns.ancount), 100)):
            if not isinstance(rr, DNSRR):
                break
            if int(rr.type) in (1, 28):
                try:
                    ip = str(ipaddress.ip_address(rr.rdata))
                except (ValueError, TypeError):
                    ip = None
                if ip:
                    yield ip, question_name or clean_hostname(rr.rrname)
            rr = rr.payload
    except (AttributeError, TypeError, ValueError):
        return


def tls_sni(pkt):
    """Extract an unfragmented TLS ClientHello SNI from TCP Raw data, if exposed.

    This intentionally does not attempt full TCP reassembly or encrypted QUIC parsing.
    """
    if TCP not in pkt or Raw not in pkt:
        return None
    data = bytes(pkt[Raw].load)
    if len(data) < 9 or data[0] != 22 or data[1] != 3:
        return None
    try:
        record_len = int.from_bytes(data[3:5], 'big')
        if len(data) < 5 + record_len or data[5] != 1:
            return None
        msg_len = int.from_bytes(data[6:9], 'big')
        if msg_len + 4 > record_len:
            return None
        body = data[9:9 + msg_len]
        pos = 2 + 32
        sid_len = body[pos]
        pos += 1 + sid_len
        cipher_len = int.from_bytes(body[pos:pos + 2], 'big')
        pos += 2 + cipher_len
        compression_len = body[pos]
        pos += 1 + compression_len
        ext_len = int.from_bytes(body[pos:pos + 2], 'big')
        pos += 2
        end = min(pos + ext_len, len(body))
        while pos + 4 <= end:
            etype = int.from_bytes(body[pos:pos + 2], 'big')
            elen = int.from_bytes(body[pos + 2:pos + 4], 'big')
            pos += 4
            if pos + elen > end:
                break
            if etype == 0 and elen >= 5:
                ext = body[pos:pos + elen]
                # server_name_list length, then name type (0), name length and bytes
                if ext[2] == 0:
                    n = int.from_bytes(ext[3:5], 'big')
                    return clean_hostname(ext[5:5 + n]) if n and 5 + n <= len(ext) else None
            pos += elen
    except (IndexError, ValueError, TypeError, struct.error):
        return None
    return None


class HostTracker:
    def __init__(self):
        self.addresses = {}
        self.flows = {}

    def observe(self, pkt):
        # DNS answers tell us which address a queried hostname resolved to.
        # A shared CDN address can correspond to several services; this is a best-effort mapping.
        for ip, host in dns_answers(pkt):
            self.addresses[ip] = host
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return '', 'Unknown', 'None'
        port_src = port_dst = 0
        if TCP in pkt:
            port_src, port_dst = int(pkt[TCP].sport), int(pkt[TCP].dport)
        elif UDP in pkt:
            port_src, port_dst = int(pkt[UDP].sport), int(pkt[UDP].dport)
        flow = (src, port_src, dst, port_dst)
        rev = (dst, port_dst, src, port_src)
        sni = tls_sni(pkt)
        if sni:
            self.flows[flow] = sni
            self.flows[rev] = sni
        host = self.flows.get(flow)
        evidence = 'TLS SNI' if host else 'DNS response' if (dst in self.addresses or src in self.addresses) else 'None'
        if not host:
            # For responses, source is the remote endpoint; otherwise destination.
            host = self.addresses.get(dst) or self.addresses.get(src, '')
        return host, service_from_host(host), evidence
