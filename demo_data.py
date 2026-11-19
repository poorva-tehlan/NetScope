"""Clearly labeled synthetic packets, for a dependable classroom demo."""
import random
from datetime import datetime, timedelta
import pandas as pd
from packet_utils import COLUMNS

def make_demo(count=850):
    rng = random.Random(2026)
    ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "1.1.1.1", "8.8.8.8", "93.184.215.14"]
    protocols = ["TCP", "UDP", "DNS", "ICMP", "ARP"]
    weights = [55, 20, 14, 8, 3]
    base = datetime.now().replace(microsecond=0) - timedelta(seconds=180)
    rows = []
    for i in range(count):
        protocol = rng.choices(protocols, weights=weights)[0]
        src, dst = rng.sample(ips, 2)
        if protocol == "ARP":
            src, dst = "192.168.1.10", "192.168.1.1"
        port_src = rng.randint(49152, 65535) if protocol in ("TCP", "UDP", "DNS") else None
        port_dst = (53 if protocol == "DNS" else rng.choice([80, 443, 8080]) if protocol == "TCP" else 123 if protocol == "UDP" else None)
        stamp = (base + timedelta(seconds=i * 180 / count)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        length = rng.randint(64, 1450)
        summary = f"SYNTHETIC {protocol} {src} -> {dst}"
        rows.append((stamp, src, dst, protocol, port_src, port_dst, length, summary))
    return pd.DataFrame(rows, columns=COLUMNS)
