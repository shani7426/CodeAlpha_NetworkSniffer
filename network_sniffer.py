"""
=============================================================
  CodeAlpha Internship — Task 1: Basic Network Sniffer
  Author  : [Your Name]
  Language: Python 3
  Library : scapy
=============================================================
  USAGE:
      sudo python3 network_sniffer.py                  # sniff all interfaces
      sudo python3 network_sniffer.py -i eth0          # specific interface
      sudo python3 network_sniffer.py -c 50            # capture 50 packets
      sudo python3 network_sniffer.py -f "tcp port 80" # BPF filter
      sudo python3 network_sniffer.py -o capture.pcap  # save to file
      sudo python3 network_sniffer.py --summary        # show stats summary

  INSTALL DEPENDENCIES:
      pip install scapy
      (Linux/Mac: run with sudo; Windows: run as Administrator)
=============================================================
"""

import argparse
import datetime
import sys
from collections import defaultdict

# ── Dependency check ──────────────────────────────────────
try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, DNS, ARP,
        Raw, wrpcap, Ether, conf
    )
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    print("[ERROR] scapy is not installed.")
    print("        Run:  pip install scapy")
    sys.exit(1)


# ── Colour helpers (ANSI) ─────────────────────────────────
class C:
    HEADER  = "\033[95m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


# ── Global statistics ─────────────────────────────────────
stats = defaultdict(int)
captured_packets = []

BANNER = f"""
{C.BOLD}{C.CYAN}
╔══════════════════════════════════════════════════════╗
║          CodeAlpha — Basic Network Sniffer           ║
║          Task 1  |  Cybersecurity Internship         ║
╚══════════════════════════════════════════════════════╝
{C.RESET}"""


# ── Packet analysis ───────────────────────────────────────
def get_protocol_name(packet) -> str:
    """Return a human-readable protocol label."""
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(HTTP):
        return "HTTP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IPv6):
        return "IPv6"
    if packet.haslayer(IP):
        return "IP"
    return "OTHER"


def get_color_for_protocol(proto: str) -> str:
    return {
        "HTTP" : C.GREEN,
        "DNS"  : C.CYAN,
        "TCP"  : C.BLUE,
        "UDP"  : C.YELLOW,
        "ICMP" : C.RED,
        "ARP"  : C.HEADER,
    }.get(proto, C.RESET)


def extract_payload(packet, max_bytes: int = 64) -> str:
    """Return a printable snippet of the raw payload."""
    if packet.haslayer(Raw):
        raw = bytes(packet[Raw].load)
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            text = repr(raw)
        text = "".join(c if c.isprintable() else "." for c in text)
        return text[:max_bytes] + ("…" if len(text) > max_bytes else "")
    return ""


def process_packet(packet):
    """Callback invoked for every captured packet."""
    stats["total"] += 1
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto = get_protocol_name(packet)
    color = get_color_for_protocol(proto)
    stats[proto] += 1

    # ── Layer 3 (IP / IPv6 / ARP) ────────────────────────
    src_ip = dst_ip = "N/A"
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ttl    = packet[IP].ttl
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        ttl    = packet[IPv6].hlim
    elif packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        ttl    = "-"
    else:
        ttl = "-"

    # ── Layer 4 (TCP / UDP) ───────────────────────────────
    src_port = dst_port = ""
    flags = ""
    if packet.haslayer(TCP):
        src_port = f":{packet[TCP].sport}"
        dst_port = f":{packet[TCP].dport}"
        flags    = f" [FLAGS={packet[TCP].flags}]"
    elif packet.haslayer(UDP):
        src_port = f":{packet[UDP].sport}"
        dst_port = f":{packet[UDP].dport}"

    # ── Payload ───────────────────────────────────────────
    payload_preview = extract_payload(packet)
    payload_str = f"\n    {C.RESET}Payload : {payload_preview}" if payload_preview else ""

    # ── DNS detail ────────────────────────────────────────
    dns_info = ""
    if packet.haslayer(DNS) and packet[DNS].qd:
        try:
            qname = packet[DNS].qd.qname.decode()
            dns_info = f"\n    {C.RESET}DNS Query: {qname}"
        except Exception:
            pass

    # ── HTTP detail ───────────────────────────────────────
    http_info = ""
    if packet.haslayer(HTTPRequest):
        try:
            method = packet[HTTPRequest].Method.decode()
            path   = packet[HTTPRequest].Path.decode()
            host   = packet[HTTPRequest].Host.decode() if packet[HTTPRequest].Host else ""
            http_info = f"\n    {C.RESET}HTTP  : {method} {host}{path}"
        except Exception:
            pass

    pkt_size = len(packet)
    stats["bytes"] += pkt_size

    print(
        f"{color}[{ts}] #{stats['total']:<5} {proto:<6}{C.RESET} "
        f"{src_ip}{src_port}  →  {dst_ip}{dst_port}"
        f"  TTL={ttl}  Size={pkt_size}B{flags}"
        f"{dns_info}{http_info}{payload_str}"
    )

    captured_packets.append(packet)


# ── Summary report ────────────────────────────────────────
def print_summary():
    print(f"\n{C.BOLD}{C.CYAN}{'='*56}")
    print("  CAPTURE SUMMARY")
    print(f"{'='*56}{C.RESET}")
    total = stats["total"] or 1  # avoid division by zero
    for key, val in sorted(stats.items()):
        if key in ("total", "bytes"):
            continue
        bar_len = int((val / total) * 30)
        bar = "█" * bar_len
        print(f"  {key:<8} {val:>5} packets  {bar}")
    print(f"\n  Total packets : {stats['total']}")
    print(f"  Total bytes   : {stats['bytes']:,} B  "
          f"({stats['bytes'] / 1024:.1f} KB)")
    print(f"{C.CYAN}{'='*56}{C.RESET}\n")


# ── CLI ────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="CodeAlpha — Basic Network Sniffer (Task 1)"
    )
    p.add_argument("-i", "--iface",   default=None,
                   help="Network interface to sniff (default: auto)")
    p.add_argument("-c", "--count",   type=int, default=0,
                   help="Number of packets to capture (0 = unlimited)")
    p.add_argument("-f", "--filter",  default=None,
                   help="BPF filter string, e.g. 'tcp port 80'")
    p.add_argument("-o", "--output",  default=None,
                   help="Save captured packets to a .pcap file")
    p.add_argument("--summary",       action="store_true",
                   help="Print statistics summary after capture")
    return p.parse_args()


def main():
    args = parse_args()
    print(BANNER)
    iface_label = args.iface or "auto"
    filter_label = args.filter or "none"
    count_label  = str(args.count) if args.count else "unlimited"

    print(f"  Interface : {C.YELLOW}{iface_label}{C.RESET}")
    print(f"  Filter    : {C.YELLOW}{filter_label}{C.RESET}")
    print(f"  Count     : {C.YELLOW}{count_label}{C.RESET}")
    if args.output:
        print(f"  Output    : {C.YELLOW}{args.output}{C.RESET}")
    print(f"\n  {C.GREEN}[*] Starting capture… press Ctrl+C to stop.{C.RESET}\n")
    print("-" * 56)

    try:
        sniff(
            iface=args.iface,
            prn=process_packet,
            count=args.count,
            filter=args.filter,
            store=False,       # memory-efficient; packets stored manually
        )
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Capture interrupted by user.{C.RESET}")
    except PermissionError:
        print(f"\n{C.RED}[ERROR] Permission denied — run with sudo / as Administrator.{C.RESET}")
        sys.exit(1)
    finally:
        if args.output and captured_packets:
            wrpcap(args.output, captured_packets)
            print(f"[+] Saved {len(captured_packets)} packets to '{args.output}'")
        if args.summary or True:   # always show summary
            print_summary()


if __name__ == "__main__":
    main()
