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

import argparse
import csv
from datetime import datetime
from pathlib import Path

from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, Raw, ICMP, get_if_list, conf

OUTPUT_PCAP = "captured_packets.pcap"
OUTPUT_CSV = "packet_summary.csv"
DEFAULT_DURATION = 60


def summarize_packet(pkt):
    ts = datetime.fromtimestamp(pkt.time).isoformat(sep=" ", timespec="seconds")
    src = pkt[IP].src if IP in pkt else "-"
    dst = pkt[IP].dst if IP in pkt else "-"
    proto = "-"
    sport = ""
    dport = ""
    payload = ""

    if TCP in pkt:
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)[:120].hex()
    elif UDP in pkt:
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)[:120].hex()
    elif ICMP in pkt:
        proto = "ICMP"
    elif IP in pkt:
        proto = "IP"

    return {
        "timestamp": ts,
        "src": src,
        "dst": dst,
        "protocol": proto,
        "sport": sport,
        "dport": dport,
        "payload_hex": payload,
    }


def write_csv(rows, path=OUTPUT_CSV):
    headers = ["timestamp", "src", "dst", "protocol", "sport", "dport", "payload_hex"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def list_ifaces():
    ifs = get_if_list()
    print("Detected interfaces:")
    for i, iface in enumerate(ifs, 1):
        print(f"  {i}. {iface}")
    print(
        "\nTip: Run PowerShell or CMD as Administrator and ensure Npcap is installed (WinPcap-compatible mode)."
    )


def capture_from_pcap(pcap_path):
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    print(f"Reading packets from {pcap_path}")
    packets = rdpcap(str(pcap_path))
    return list(packets)


def try_live_sniff(iface=None, duration=None, count=None):
    """
    Attempt live sniff. If Scapy raises a RuntimeError because no libpcap provider is available,
    print clear instructions and exit.
    """
    sniff_kwargs = {}
    if count:
        sniff_kwargs["count"] = count
    else:
        sniff_kwargs["timeout"] = duration

    if iface:
        sniff_kwargs["iface"] = iface

    try:
        print(f"Starting live capture {('on ' + iface) if iface else ''} ...")
        packets = sniff(**sniff_kwargs)
        return list(packets)
    except RuntimeError as e:
        # Typically thrown when no libpcap provider (Npcap/WinPcap) is installed on Windows
        print("RuntimeError during sniff():", e)
        print("\n== Unable to perform Layer-2 capture on this system ==")
        print("Most likely cause: Npcap (WinPcap-compatible) is not installed or you are not running as Administrator.")
        print("Quick fixes:")
        print("  1) Install Npcap: https://nmap.org/npcap/  (choose 'Install Npcap in WinPcap API-compatible Mode')")
        print("  2) Reboot if the installer asked for it.")
        print("  3) Run this terminal as Administrator and try again.")
        print("\nAlternative: capture a pcap with Wireshark/tshark on the same machine or another machine and run:")
        print("  python network_sniffer.py --pcap <yourfile.pcap>")
        raise


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=DEFAULT_DURATION, help="capture duration in seconds (live)")
    ap.add_argument("--pcap", type=str, help="read from pcap file instead of live capture")
    ap.add_argument("--count", type=int, help="capture count instead of duration")
    ap.add_argument("--iface", type=str, help="network interface name to capture on (see --list-ifaces)")
    ap.add_argument("--list-ifaces", action="store_true", help="list available interfaces and exit")
    args = ap.parse_args()

    if args.list_ifaces:
        list_ifaces()
        return

    packets = []
    summaries = []

    try:
        if args.pcap:
            packets = capture_from_pcap(args.pcap)
        else:
            packets = try_live_sniff(iface=args.iface, duration=args.duration, count=args.count)
    except Exception as e:
        # try_live_sniff will already have printed instructions if it failed
        return

    # Summarize IP packets
    for pkt in packets:
        if IP in pkt:
            summaries.append(summarize_packet(pkt))

    # Save pcap
    try:
        if packets:
            print(f"Saving {len(packets)} packets to {OUTPUT_PCAP}")
            wrpcap(OUTPUT_PCAP, packets)
        else:
            print("No packets captured; skipping pcap write.")
    except Exception as e:
        print("Failed to write pcap:", e)

    # Save CSV summary
    if summaries:
        print(f"Writing summary for {len(summaries)} IP packets to {OUTPUT_CSV}")
        write_csv(summaries, OUTPUT_CSV)
        print("Done.")
    else:
        print("No IP packets to summarize; CSV not written.")


if __name__ == "__main__":
    main()
