# Task 1 — Basic Network Sniffer
### CodeAlpha Cybersecurity Internship

---

## Overview

This tool captures and analyzes live network traffic using **Python + Scapy**.
It decodes packets at multiple OSI layers (Ethernet → IP → TCP/UDP → Application)
and displays source/destination IPs, ports, protocols, flags, TTL, payload
previews, DNS queries, and HTTP requests in real time.

---

## How It Works (Concepts)

| Layer | What We Capture |
|-------|----------------|
| Layer 2 — Data Link | MAC addresses, ARP |
| Layer 3 — Network | Source/Destination IP, TTL |
| Layer 4 — Transport | TCP/UDP ports, TCP flags |
| Layer 7 — Application | DNS queries, HTTP methods/paths |

**Packet flow:** NIC → Kernel → Scapy raw socket → `process_packet()` callback → console output

---

## Installation

```bash
# 1. Install Python 3.8+
# 2. Install scapy
pip install scapy

# On Linux/macOS you need root privileges to open raw sockets:
sudo python3 network_sniffer.py
```

---

## Usage Examples

```bash
# Capture all traffic (unlimited)
sudo python3 network_sniffer.py

# Capture on a specific interface
sudo python3 network_sniffer.py -i eth0

# Capture only 100 packets then stop
sudo python3 network_sniffer.py -c 100

# BPF filter — only HTTP traffic
sudo python3 network_sniffer.py -f "tcp port 80"

# BPF filter — only DNS
sudo python3 network_sniffer.py -f "udp port 53"

# Save capture to a .pcap file (open in Wireshark)
sudo python3 network_sniffer.py -o capture.pcap

# Combine options
sudo python3 network_sniffer.py -i wlan0 -c 200 -f "not arp" -o out.pcap
```

---

## Sample Output

```
[10:32:11.042] #1     TCP    192.168.1.5:54321  →  142.250.80.46:443  TTL=64  Size=60B [FLAGS=S]
[10:32:11.043] #2     DNS    192.168.1.5:52001  →  8.8.8.8:53         TTL=64  Size=74B
    DNS Query: www.google.com.
[10:32:11.045] #3     HTTP   192.168.1.5:48001  →  93.184.216.34:80   TTL=64  Size=420B
    HTTP  : GET example.com/index.html
```

---

## Protocol Color Coding

| Color  | Protocol |
|--------|---------|
| 🟢 Green  | HTTP |
| 🔵 Blue   | TCP  |
| 🟡 Yellow | UDP  |
| 🔴 Red    | ICMP |
| 🟣 Purple | ARP  |
| 🔵 Cyan   | DNS  |

---

## Key Functions

| Function | Purpose |
|----------|---------|
| `process_packet(packet)` | Main callback; decodes and prints each packet |
| `get_protocol_name(packet)` | Identifies the highest-level protocol |
| `extract_payload(packet)` | Returns printable payload preview |
| `print_summary()` | Displays per-protocol statistics at the end |

---

## Security & Ethical Use

> ⚠️ **Only sniff traffic on networks you own or have explicit permission to monitor.**
> Unauthorized packet capture is illegal in most jurisdictions.
> This tool is for educational purposes only.

---

## Requirements

- Python 3.8+
- scapy >= 2.5
- Root / Administrator privileges
