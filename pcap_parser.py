"""
pcap_parser.py
Stage 1: Read a .pcap file using Scapy and extract raw connection text.

"""

from scapy.all import rdpcap, IP, IPv6, TCP, UDP
from collections import defaultdict


def parse_pcap(filepath):
    """
    Reads a .pcap file and returns a list of connection summaries as strings.
    Each summary describes one unique (src_ip, dst_ip, port, protocol) flow.

    Returns:
        connections (list of dict): Each dict has keys:
            src, dst, port, protocol, flags, packet_count, duration_seconds, raw_text
    """
    print(f"[Parser] Reading {filepath} ...")
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"[Parser] ERROR reading file: {e}")
        return []

    # Group packets by flow: (src_ip, dst_ip, dst_port, protocol)
    flows = defaultdict(lambda: {
        "packets": [],
        "flags": set(),
        "timestamps": []
    })

    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
        else:
            continue

        protocol = "OTHER"
        port = 0
        flag_str = ""

        if pkt.haslayer(TCP):
            protocol = "TCP"
            port = pkt[TCP].dport
            # Convert flags integer to readable string
            tcp_flags = pkt[TCP].flags
            flag_chars = []
            if tcp_flags & 0x02: flag_chars.append("SYN")
            if tcp_flags & 0x10: flag_chars.append("ACK")
            if tcp_flags & 0x01: flag_chars.append("FIN")
            if tcp_flags & 0x04: flag_chars.append("RST")
            if tcp_flags & 0x08: flag_chars.append("PSH")
            flag_str = " ".join(flag_chars) if flag_chars else "NONE"

        elif pkt.haslayer(UDP):
            protocol = "UDP"
            port = pkt[UDP].dport

        flow_key = (src, dst, port, protocol)
        flows[flow_key]["packets"].append(pkt)
        flows[flow_key]["timestamps"].append(float(pkt.time))
        if flag_str:
            flows[flow_key]["flags"].add(flag_str)

    # Build connection summaries
    connections = []
    for (src, dst, port, protocol), data in flows.items():
        timestamps = data["timestamps"]
        count = len(data["packets"])
        duration = round(max(timestamps) - min(timestamps), 2) if len(timestamps) > 1 else 0
        flags_display = " ".join(data["flags"]) if data["flags"] else "NONE"

        raw_text = (
            f"{src} → {dst}\n"
            f"port {port}, {protocol}\n"
            f"flags: {flags_display}\n"
            f"count: {count} packets / {duration}s"
        )

        connections.append({
            "src": src,
            "dst": dst,
            "port": port,
            "protocol": protocol,
            "flags": flags_display,
            "packet_count": count,
            "duration_seconds": duration,
            "raw_text": raw_text
        })

    print(f"[Parser] Extracted {len(connections)} unique flows.")
    return connections


def generate_demo_connections():
    """
    Returns a hardcoded list of fake connections for testing without a real PCAP file.
    This lets you demo the full pipeline immediately.
    """
    demo = [
        {"src": "203.0.113.5",   "dst": "192.168.1.105", "port": 22,  "protocol": "TCP", "flags": "SYN", "packet_count": 847, "duration_seconds": 12, "raw_text": "203.0.113.5 → 192.168.1.105\nport 22, TCP\nflags: SYN SYN SYN\ncount: 847 packets / 12s"},
        {"src": "192.168.1.105", "dst": "192.168.1.10",  "port": 445, "protocol": "TCP", "flags": "SYN ACK", "packet_count": 312, "duration_seconds": 3,  "raw_text": "192.168.1.105 → 192.168.1.10\nport 445, TCP\nflags: SYN ACK\ncount: 312 packets / 3s"},
        {"src": "192.168.1.10",  "dst": "192.168.1.20",  "port": 3389,"protocol": "TCP", "flags": "SYN", "packet_count": 500, "duration_seconds": 5,  "raw_text": "192.168.1.10 → 192.168.1.20\nport 3389, TCP\nflags: SYN\ncount: 500 packets / 5s"},
        {"src": "192.168.1.20",  "dst": "192.168.1.1",   "port": 80,  "protocol": "TCP", "flags": "PSH ACK", "packet_count": 200, "duration_seconds": 2,  "raw_text": "192.168.1.20 → 192.168.1.1\nport 80, TCP\nflags: PSH ACK\ncount: 200 packets / 2s"},
        {"src": "192.168.1.1",   "dst": "10.0.0.5",      "port": 443, "protocol": "TCP", "flags": "SYN ACK", "packet_count": 150, "duration_seconds": 1,  "raw_text": "192.168.1.1 → 10.0.0.5\nport 443, TCP\nflags: SYN ACK\ncount: 150 packets / 1s"},
        {"src": "192.168.1.105", "dst": "192.168.1.50",  "port": 53,  "protocol": "UDP", "flags": "NONE", "packet_count": 20,  "duration_seconds": 0.5,"raw_text": "192.168.1.105 → 192.168.1.50\nport 53, UDP\nflags: NONE\ncount: 20 packets / 0.5s"},
        {"src": "192.168.1.50",  "dst": "192.168.1.10",  "port": 8080,"protocol": "TCP", "flags": "SYN", "packet_count": 10,  "duration_seconds": 0.2,"raw_text": "192.168.1.50 → 192.168.1.10\nport 8080, TCP\nflags: SYN\ncount: 10 packets / 0.2s"},
    ]
    print(f"[Parser] Using demo mode — {len(demo)} fake connections loaded.")
    return demo