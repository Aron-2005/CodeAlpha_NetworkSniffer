# CodeAlpha_NetworkSniffer
#!/usr/bin/env python3
"""
network_sniffer.py (Windows-friendly)

- Lists interfaces (--list-ifaces)
- Captures live (--iface + --duration / --count)
- Reads from pcap (--pcap)
- If libpcap/Npcap is missing, prints clear installation instructions and exits.

Usage:
  python network_sniffer.py --list-ifaces
  python network_sniffer.py --iface "Wi-Fi" --duration 60
  python network_sniffer.py --pcap sample.pcap
"""
