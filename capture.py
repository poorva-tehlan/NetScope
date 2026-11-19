"""Capture packets into SQLite. Run separately from the Streamlit dashboard."""
import argparse
import sys
from scapy.all import sniff, get_if_list
from packet_utils import packet_to_row
from attribution import HostTracker
from storage import connect

INSERT = "INSERT INTO packets (timestamp, source, destination, protocol, source_port, destination_port, length, summary, hostname, service, evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?)"

def main():
    parser = argparse.ArgumentParser(description="NetScope live packet collector (only capture traffic you are authorized to inspect)")
    parser.add_argument("--list-interfaces", action="store_true", help="Show interface names")
    parser.add_argument("--iface", help="Network interface to capture, omitted = Scapy default")
    parser.add_argument("--limit", type=int, default=0, help="Stop after this many stored packets (0 = unlimited)")
    args = parser.parse_args()
    if args.list_interfaces:
        for item in get_if_list():
            print(item)
        return
    conn = connect()
    tracker = HostTracker()
    pending = []
    stored = 0
    def save():
        if pending:
            conn.executemany(INSERT, pending)
            conn.commit()
            pending.clear()
    def on_packet(pkt):
        nonlocal stored
        row = packet_to_row(pkt)
        if row is None:
            return
        host, service, evidence = tracker.observe(pkt)
        pending.append((*row, host, service, evidence))
        stored += 1
        if len(pending) >= 20:
            save()
        if stored % 100 == 0:
            print(f"Captured {stored} packets", flush=True)
    print("NetScope collector started. Press Ctrl+C to stop.", flush=True)
    print(f"Interface: {args.iface or 'Scapy default'}", flush=True)
    try:
        while args.limit == 0 or stored < args.limit:
            remaining = args.limit - stored if args.limit else 0
            sniff(iface=args.iface, prn=on_packet, store=False, timeout=1,
                  count=remaining if args.limit else 0)
            save()
    except KeyboardInterrupt:
        print("Stopped by user.", flush=True)
    except (OSError, RuntimeError, PermissionError) as error:
        print(f"Capture failed: {error}", file=sys.stderr)
        print("On Windows install Npcap, select an active interface, and try an Administrator terminal.", file=sys.stderr)
        sys.exit(1)
    finally:
        save()
        conn.close()
    print(f"Total saved: {stored}")

if __name__ == "__main__":
    main()
