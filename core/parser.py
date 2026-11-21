"""
PCAP ANALYZER - Network Packet Parsing Engine
VCAS.PRIVATE × QNTSOFTWARE

Dual-engine packet extraction: tshark primary with Scapy fallback.
Comprehensive 0-65,535 port identification and protocol hierarchy dissection.
"""

import subprocess
import json
import sys
from dataclasses import dataclass, field
from typing import Optional
from .ports import lookup_port, get_top_protocol, is_risky_port, get_category, ICMP_TYPES


@dataclass
class Packet:
    index:      int
    timestamp:  str
    src:        str
    dst:        str
    src_port:   int   = 0
    dst_port:   int   = 0
    protocol:   str   = "UNKNOWN"
    service:    str   = ""          # e.g. "HTTPS", "REDIS"
    category:   str   = "STANDARD" # SECURE/RISKY/MALWARE/etc.
    length:     int   = 0
    ttl:        int   = 0
    flags:      str   = ""          # TCP flags
    info:       str   = ""
    layers:     dict  = field(default_factory=dict)
    raw_summary: str  = ""
    is_key_packet:   bool  = False
    importance_score: float = 0.0
    highlighted_fields: list = field(default_factory=list)
    is_risky:   bool  = False
    icmp_type:  str   = ""


def parse_pcap(pcap_path: str, wireshark_filter: str = "") -> list[Packet]:
    """Parse a PCAP file — tshark primary, scapy fallback."""
    cmd = [
        "tshark", "-r", pcap_path,
        "-T", "json",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "frame.len",
        "-e", "frame.protocols",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.ttl",
        "-e", "ip.proto",
        "-e", "ipv6.src",
        "-e", "ipv6.dst",
        "-e", "ipv6.hlim",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.flags.str",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "icmp.type",
        "-e", "icmp.code",
        "-e", "icmpv6.type",
        "-e", "_ws.col.Info",
    ]
    if wireshark_filter:
        cmd += ["-Y", wireshark_filter]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        raw_packets = json.loads(result.stdout) if result.stdout.strip() else []
    except subprocess.CalledProcessError as e:
        print(f"\033[91m[ERROR] tshark: {e.stderr[:200]}\033[0m", file=sys.stderr)
        return _parse_with_scapy(pcap_path, wireshark_filter)
    except FileNotFoundError:
        print("\033[93m[WARN] tshark not found → scapy fallback\033[0m", file=sys.stderr)
        return _parse_with_scapy(pcap_path, wireshark_filter)
    except json.JSONDecodeError:
        return _parse_with_scapy(pcap_path, wireshark_filter)

    packets = []
    for pkt in raw_packets:
        layers = pkt.get("_source", {}).get("layers", {})

        def g(key, default=""):
            val = layers.get(key, [default])
            if isinstance(val, list):
                return val[0] if val else default
            return val

        def gi(key, default=0):
            try:
                return int(g(key, default))
            except (ValueError, TypeError):
                return default

        # Addresses
        src = g("ip.src") or g("ipv6.src") or g("eth.src")
        dst = g("ip.dst") or g("ipv6.dst") or g("eth.dst")

        # Ports
        src_port = gi("tcp.srcport") or gi("udp.srcport")
        dst_port = gi("tcp.dstport") or gi("udp.dstport")

        # Service lookup (full 65535 port DB)
        svc_name, svc_tag, svc_desc, category = lookup_port(dst_port) if dst_port else ("", "", "", "STANDARD")
        if not svc_name and src_port:
            svc_name, svc_tag, svc_desc, category = lookup_port(src_port)

        # Protocol chain
        proto_chain = g("frame.protocols", "")
        protocol    = _top_protocol(proto_chain, src_port, dst_port)

        # ICMP
        icmp_type_raw = gi("icmp.type", -1)
        icmpv6_type   = gi("icmpv6.type", -1)
        icmp_desc = ""
        if icmp_type_raw >= 0:
            icmp_desc = ICMP_TYPES.get(icmp_type_raw, f"ICMP Type {icmp_type_raw}")
        elif icmpv6_type >= 0:
            icmp_desc = f"ICMPv6 Type {icmpv6_type}"

        try:
            idx = int(g("frame.number"))
        except (ValueError, TypeError):
            idx = len(packets) + 1

        length = gi("frame.len")
        ttl    = gi("ip.ttl") or gi("ipv6.hlim")
        flags  = g("tcp.flags.str")
        info   = g("_ws.col.Info")

        risky = is_risky_port(src_port) or is_risky_port(dst_port)

        # Build summary line
        port_str = f":{dst_port}" if dst_port else ""
        summary  = info or f"{src} → {dst}{port_str} [{protocol}]"

        p = Packet(
            index=idx,
            timestamp=g("frame.time_relative"),
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            service=svc_name or protocol,
            category=category,
            length=length,
            ttl=ttl,
            flags=flags,
            info=info,
            layers=layers,
            raw_summary=summary,
            is_risky=risky,
            icmp_type=icmp_desc,
        )
        packets.append(p)

    return packets


def _top_protocol(protocols_raw: str, src_port: int = 0, dst_port: int = 0) -> str:
    """Extract topmost meaningful protocol. Port-aware for full coverage."""
    if not protocols_raw:
        if dst_port or src_port:
            return get_top_protocol(src_port, dst_port)
        return "UNKNOWN"

    priority = [
        "http2", "quic", "http", "tls", "ssl", "dns", "dhcp", "dhcpv6",
        "ftp", "smtp", "pop", "imap", "ssh", "rdp", "smb2", "smb",
        "ntp", "snmp", "ldap", "kerberos", "radius", "sip", "rtsp",
        "mqtt", "coap", "modbus", "dnp3", "s7comm",
        "icmpv6", "icmp", "arp", "ospf", "bgp", "rip", "eigrp",
        "tcp", "udp", "ipv6", "ip", "eth"
    ]
    protos = [p.lower() for p in protocols_raw.split(":")]
    for p in priority:
        if p in protos:
            return p.upper()

    # Port-based fallback for unrecognised protocol chains
    if dst_port or src_port:
        svc = get_top_protocol(src_port, dst_port)
        if svc and not svc.startswith("PORT-") and not svc.startswith("EPHEMERAL"):
            return svc

    return protos[-1].upper() if protos else "UNKNOWN"


def _parse_with_scapy(pcap_path: str, wireshark_filter: str = "") -> list[Packet]:
    """Full scapy fallback with complete port DB."""
    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Ether, ICMP, ICMPv6EchoRequest, DNS, Raw, ARP
    except ImportError:
        print("\033[91m[ERROR] Neither tshark nor scapy available.\033[0m")
        sys.exit(1)

    try:
        raw = rdpcap(pcap_path)
    except Exception as e:
        print(f"\033[91m[ERROR] Cannot read PCAP: {e}\033[0m")
        sys.exit(1)

    packets = []
    for idx, pkt in enumerate(raw, 1):
        src = dst = ""
        src_port = dst_port = 0
        protocol = "UNKNOWN"
        info     = ""
        ttl      = 0
        flags    = ""
        icmp_desc = ""
        length   = len(pkt)

        if ARP in pkt:
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst
            protocol = "ARP"
            info = f"ARP {'Request' if pkt[ARP].op == 1 else 'Reply'}: {src} → {dst}"
        elif IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            ttl = pkt[IP].ttl
            protocol = "IP"
        elif IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            ttl = pkt[IPv6].hlim
            protocol = "IPv6"
        elif Ether in pkt:
            src = pkt[Ether].src
            dst = pkt[Ether].dst
            protocol = "ETH"

        if ICMP in pkt:
            t = pkt[ICMP].type
            icmp_desc = ICMP_TYPES.get(t, f"ICMP Type {t}")
            protocol = "ICMP"
            info = icmp_desc

        elif TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
            # Full port lookup
            svc_name, svc_tag, _, category = lookup_port(dst_port)
            if not svc_name:
                svc_name, svc_tag, _, category = lookup_port(src_port)
            protocol = svc_name or "TCP"
            info = f"{src}:{src_port} → {dst}:{dst_port} [{flags}]"

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            svc_name, _, _, _ = lookup_port(dst_port)
            if not svc_name:
                svc_name, _, _, _ = lookup_port(src_port)
            protocol = svc_name or "UDP"
            info = f"{src}:{src_port} → {dst}:{dst_port}"

        if DNS in pkt and not info:
            try:
                qname = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else ""
                info = f"DNS: {qname}"
                protocol = "DNS"
            except Exception:
                info = "DNS"

        if Raw in pkt and not info:
            snippet = pkt[Raw].load[:50]
            info = f"Data: {snippet}"

        svc_name, _, _, category = lookup_port(dst_port) if dst_port else ("", "", "", "STANDARD")
        risky = is_risky_port(src_port) or is_risky_port(dst_port)
        summary = info or f"#{idx} {src} → {dst} [{protocol}]"

        p = Packet(
            index=idx,
            timestamp=f"{float(pkt.time):.6f}",
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            service=svc_name or protocol,
            category=category,
            length=length,
            ttl=ttl,
            flags=flags,
            info=info,
            raw_summary=summary,
            is_risky=risky,
            icmp_type=icmp_desc,
        )
        packets.append(p)

    return packets
