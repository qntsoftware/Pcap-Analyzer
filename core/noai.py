"""
PCAP ANALYZER - No-AI Analysis Engine
VCAS.PRIVATE & QNTSOFTWARE

100+ profesyonel analiz parametresi — AI olmadan tam analiz.
Tamamen local, internet gerektirmez.
"""

from __future__ import annotations
import re
import math
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional
from .parser import Packet
from .ports  import lookup_port, is_risky_port, get_category, ICMP_TYPES


# ─── Sonuç Veri Yapıları ────────────────────────────────────────────────────

@dataclass
class Finding:
    severity:    str    # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category:    str    # SECURITY / ANOMALY / PERFORMANCE / RECON / etc.
    title:       str
    description: str
    packets:     list   = field(default_factory=list)  # ilgili paket indeksleri
    evidence:    str    = ""


@dataclass
class NoAIReport:
    # Temel İstatistikler
    total_packets:         int   = 0
    total_bytes:           int   = 0
    duration_sec:          float = 0.0
    avg_packet_size:       float = 0.0
    packets_per_second:    float = 0.0
    bytes_per_second:      float = 0.0
    capture_start:         str   = ""
    capture_end:           str   = ""

    # Protokol Dağılımı
    protocol_counts:       dict  = field(default_factory=dict)
    protocol_bytes:        dict  = field(default_factory=dict)
    service_counts:        dict  = field(default_factory=dict)

    # Host Analizi
    unique_src_ips:        list  = field(default_factory=list)
    unique_dst_ips:        list  = field(default_factory=list)
    top_talkers:           list  = field(default_factory=list)   # (ip, pkt_count)
    top_destinations:      list  = field(default_factory=list)
    internal_hosts:        list  = field(default_factory=list)
    external_hosts:        list  = field(default_factory=list)
    multicast_traffic:     list  = field(default_factory=list)
    broadcast_traffic:     list  = field(default_factory=list)

    # Port Analizi
    open_ports_dst:        list  = field(default_factory=list)
    top_dst_ports:         list  = field(default_factory=list)   # (port, count, service)
    risky_ports_seen:      list  = field(default_factory=list)
    malware_ports_seen:    list  = field(default_factory=list)
    ephemeral_port_count:  int   = 0

    # TCP Analizi
    tcp_flags_dist:        dict  = field(default_factory=dict)
    tcp_syn_count:         int   = 0
    tcp_rst_count:         int   = 0
    tcp_fin_count:         int   = 0
    tcp_syn_ack_count:     int   = 0
    half_open_conns:       int   = 0
    retransmit_estimate:   int   = 0
    tcp_conversations:     list  = field(default_factory=list)

    # UDP Analizi
    udp_flood_suspects:    list  = field(default_factory=list)
    dns_queries:           list  = field(default_factory=list)
    dns_unique_domains:    list  = field(default_factory=list)
    ntp_amplify_suspect:   bool  = False

    # ICMP Analizi
    icmp_types_seen:       dict  = field(default_factory=dict)
    icmp_flood_suspect:    bool  = False
    ping_sweep_suspect:    bool  = False

    # Güvenlik Bulguları
    findings:              list[Finding] = field(default_factory=list)
    threat_level:          str   = "LOW"
    security_score:        int   = 100   # 100 = clean, 0 = critical

    # Ağ Topolojisi
    gateway_candidates:    list  = field(default_factory=list)
    dns_servers_seen:      list  = field(default_factory=list)
    dhcp_servers_seen:     list  = field(default_factory=list)
    ntp_servers_seen:      list  = field(default_factory=list)

    # Anomaliler
    large_packets:         list  = field(default_factory=list)
    tiny_packets:          list  = field(default_factory=list)
    ttl_anomalies:         list  = field(default_factory=list)
    duplicate_ips:         list  = field(default_factory=list)   # IP spoofing hint
    asymmetric_traffic:    list  = field(default_factory=list)

    # Recon / Scan
    port_scan_suspects:    list  = field(default_factory=list)
    host_scan_suspects:    list  = field(default_factory=list)
    service_enum_suspects: list  = field(default_factory=list)
    banner_grab_suspects:  list  = field(default_factory=list)

    # VPN / Tunnel
    vpn_traffic:           list  = field(default_factory=list)
    tunnel_suspects:       list  = field(default_factory=list)
    dns_tunnel_suspect:    bool  = False

    # Credentials / Cleartext
    cleartext_protocols:   list  = field(default_factory=list)
    credential_suspects:   list  = field(default_factory=list)

    # Exfiltration
    large_upload_suspects: list  = field(default_factory=list)
    beacon_suspects:       list  = field(default_factory=list)   # C2 beaconing
    high_entropy_suspects: list  = field(default_factory=list)

    # IoT / ICS
    ics_protocols_seen:    list  = field(default_factory=list)
    iot_protocols_seen:    list  = field(default_factory=list)

    # Crypto / Blockchain
    crypto_traffic:        list  = field(default_factory=list)

    # Timing Analizi
    inter_arrival_min:     float = 0.0
    inter_arrival_max:     float = 0.0
    inter_arrival_avg:     float = 0.0
    inter_arrival_std:     float = 0.0
    burst_periods:         list  = field(default_factory=list)
    idle_periods:          list  = field(default_factory=list)

    # Coğrafi / ASN (offline heuristic)
    private_to_public:     list  = field(default_factory=list)
    public_to_private:     list  = field(default_factory=list)

    # Özet
    executive_summary:     str   = ""
    key_packet_indices:    list  = field(default_factory=list)
    recommendations:       list  = field(default_factory=list)
    ctf_hints:             list  = field(default_factory=list)


# ─── Yardımcı Fonksiyonlar ──────────────────────────────────────────────────

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]

def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_NETS)
    except ValueError:
        return False

def _is_multicast(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False

def _is_broadcast(ip: str) -> bool:
    return ip in ("255.255.255.255", "ff:ff:ff:ff:ff:ff") or ip.endswith(".255")

def _entropy(data: str) -> float:
    """Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())

def _stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))

def _ts(p: Packet) -> float:
    try:
        return float(p.timestamp)
    except (ValueError, TypeError):
        return 0.0


# ─── Ana Analiz Motoru ──────────────────────────────────────────────────────

def analyze_noai(packets: list[Packet], description: str = "") -> NoAIReport:
    """
    100+ parametreli tam analiz — AI gerektirmez.
    """
    r = NoAIReport()
    if not packets:
        r.executive_summary = "Hiç paket bulunamadı."
        return r

    r.total_packets = len(packets)

    # ── 1. TEMEL İSTATİSTİKLER ──────────────────────────────────────────────
    r.total_bytes    = sum(p.length for p in packets)
    r.avg_packet_size = r.total_bytes / r.total_packets

    timestamps = [_ts(p) for p in packets if _ts(p) > 0]
    if timestamps:
        r.capture_start  = f"{min(timestamps):.6f}s"
        r.capture_end    = f"{max(timestamps):.6f}s"
        r.duration_sec   = max(timestamps) - min(timestamps)
        if r.duration_sec > 0:
            r.packets_per_second = r.total_packets / r.duration_sec
            r.bytes_per_second   = r.total_bytes   / r.duration_sec

    # ── 2. INTER-ARRIVAL TIMES ───────────────────────────────────────────────
    if len(timestamps) >= 2:
        sorted_ts  = sorted(timestamps)
        iats       = [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts)-1)]
        r.inter_arrival_min = min(iats)
        r.inter_arrival_max = max(iats)
        r.inter_arrival_avg = sum(iats) / len(iats)
        r.inter_arrival_std = _stddev(iats)

        # Burst: IAT < avg/5
        burst_thresh = r.inter_arrival_avg / 5
        for i, iat in enumerate(iats):
            if iat < burst_thresh:
                r.burst_periods.append(i + 1)

        # Idle: IAT > avg*10
        idle_thresh = r.inter_arrival_avg * 10
        for i, iat in enumerate(iats):
            if iat > idle_thresh:
                r.idle_periods.append(i + 1)

    # ── 3. PROTOKOL DAĞILIMI ────────────────────────────────────────────────
    proto_cnt  = Counter(p.protocol for p in packets)
    proto_byt  = defaultdict(int)
    svc_cnt    = Counter(p.service  for p in packets if p.service)
    for p in packets:
        proto_byt[p.protocol] += p.length

    r.protocol_counts = dict(proto_cnt.most_common(30))
    r.protocol_bytes  = dict(sorted(proto_byt.items(), key=lambda x: x[1], reverse=True)[:30])
    r.service_counts  = dict(svc_cnt.most_common(30))

    # ── 4. HOST ANALİZİ ─────────────────────────────────────────────────────
    src_ips = [p.src for p in packets if p.src]
    dst_ips = [p.dst for p in packets if p.dst]

    src_cnt = Counter(src_ips)
    dst_cnt = Counter(dst_ips)

    r.unique_src_ips    = list(set(src_ips))
    r.unique_dst_ips    = list(set(dst_ips))
    r.top_talkers       = src_cnt.most_common(20)
    r.top_destinations  = dst_cnt.most_common(20)

    all_ips = set(src_ips + dst_ips)
    r.internal_hosts  = [ip for ip in all_ips if _is_private(ip)]
    r.external_hosts  = [ip for ip in all_ips if not _is_private(ip) and not _is_multicast(ip) and not _is_broadcast(ip)]
    r.multicast_traffic = [ip for ip in all_ips if _is_multicast(ip)]
    r.broadcast_traffic = [ip for ip in all_ips if _is_broadcast(ip)]

    # Private → Public (exfil hint)
    for p in packets:
        if p.src and p.dst and _is_private(p.src) and not _is_private(p.dst) and not _is_multicast(p.dst):
            key = f"{p.src} → {p.dst}"
            if key not in r.private_to_public:
                r.private_to_public.append(key)
        elif p.src and p.dst and not _is_private(p.src) and _is_private(p.dst):
            key = f"{p.src} → {p.dst}"
            if key not in r.public_to_private:
                r.public_to_private.append(key)

    # ── 5. PORT ANALİZİ ─────────────────────────────────────────────────────
    dst_port_cnt = Counter(p.dst_port for p in packets if p.dst_port)
    src_port_cnt = Counter(p.src_port for p in packets if p.src_port)

    all_ports_seen = set(p.dst_port for p in packets if p.dst_port) | \
                     set(p.src_port for p in packets if p.src_port)
    r.open_ports_dst = sorted(set(p.dst_port for p in packets if p.dst_port))

    r.top_dst_ports = [
        (port, count, lookup_port(port)[0])
        for port, count in dst_port_cnt.most_common(25)
        if port > 0
    ]

    r.risky_ports_seen   = [(p, lookup_port(p)[0]) for p in all_ports_seen if get_category(p) == "RISKY"]
    r.malware_ports_seen = [(p, lookup_port(p)[0]) for p in all_ports_seen if get_category(p) in ("MALWARE", "C2")]

    r.ephemeral_port_count = sum(1 for p in all_ports_seen if p > 49151)

    # ── 6. TCP ANALİZİ ──────────────────────────────────────────────────────
    tcp_pkts = [p for p in packets if "TCP" in p.protocol or p.src_port in (80,443) or p.dst_port in (80,443)]
    flag_cnt = Counter()
    for p in tcp_pkts:
        if p.flags:
            flag_cnt[p.flags] += 1
        # Heuristic: flag string contains letters
        info_low = (p.info or "").lower()
        if "syn" in info_low and "ack" not in info_low:
            r.tcp_syn_count += 1
        if "rst" in info_low:
            r.tcp_rst_count += 1
        if "fin" in info_low:
            r.tcp_fin_count += 1
        if "syn" in info_low and "ack" in info_low:
            r.tcp_syn_ack_count += 1

    r.tcp_flags_dist = dict(flag_cnt.most_common(15))

    # Half-open: SYN >> SYN-ACK
    if r.tcp_syn_count > 10 and r.tcp_syn_ack_count < r.tcp_syn_count * 0.5:
        r.half_open_conns = r.tcp_syn_count - r.tcp_syn_ack_count

    # Retransmit estimate (duplicate small packets with same size)
    size_ts_pairs = [(p.length, _ts(p)) for p in packets]
    seen_sizes    = Counter(p.length for p in packets)
    r.retransmit_estimate = sum(c - 1 for c in seen_sizes.values() if c > 1 and 40 < c < 1500)

    # TCP conversations (src:port ↔ dst:port pairs)
    conv_set = set()
    for p in packets:
        if p.src_port and p.dst_port:
            key = tuple(sorted([(p.src, p.src_port), (p.dst, p.dst_port)]))
            conv_set.add(key)
    r.tcp_conversations = [f"{a[0]}:{a[1]} ↔ {b[0]}:{b[1]}" for a, b in list(conv_set)[:30]]

    # ── 7. UDP ANALİZİ ──────────────────────────────────────────────────────
    udp_pkts = [p for p in packets if p.protocol in ("UDP", "DNS", "NTP", "DHCP", "SNMP")]

    # DNS
    for p in packets:
        info = (p.info or "").lower()
        if p.dst_port == 53 or p.src_port == 53 or "dns" in p.protocol.lower():
            # Extract domain heuristic
            match = re.search(r'[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}', p.info or "")
            if match:
                domain = match.group()
                r.dns_queries.append((p.index, domain))
    r.dns_unique_domains = list(set(d for _, d in r.dns_queries))

    # DNS tunnel: very long subdomains or high-entropy domain names
    for _, domain in r.dns_queries:
        parts = domain.split(".")
        for part in parts:
            if len(part) > 30 or _entropy(part) > 3.8:
                r.dns_tunnel_suspect = True
                break

    # NTP amplification: large NTP responses
    ntp_resp = [p for p in packets if (p.dst_port == 123 or p.src_port == 123) and p.length > 300]
    r.ntp_amplify_suspect = len(ntp_resp) > 5

    # UDP flood: same dst_port > 1000 packets/unique_src
    udp_dst_cnt = Counter((p.dst, p.dst_port) for p in udp_pkts if p.dst_port)
    for (dst, port), cnt in udp_dst_cnt.items():
        if cnt > 500:
            r.udp_flood_suspects.append(f"{dst}:{port} ({cnt} pkts)")

    # ── 8. ICMP ANALİZİ ─────────────────────────────────────────────────────
    icmp_pkts = [p for p in packets if "ICMP" in p.protocol or p.icmp_type]
    icmp_type_cnt = Counter(p.icmp_type for p in icmp_pkts if p.icmp_type)
    r.icmp_types_seen = dict(icmp_type_cnt.most_common(10))

    if len(icmp_pkts) > 200:
        r.icmp_flood_suspect = True

    # Ping sweep: single src pinging many unique dsts
    ping_src_dst = defaultdict(set)
    for p in icmp_pkts:
        if "Echo Request" in (p.icmp_type or "") or "ping" in (p.info or "").lower():
            ping_src_dst[p.src].add(p.dst)
    for src, dsts in ping_src_dst.items():
        if len(dsts) > 10:
            r.ping_sweep_suspect = True
            r.host_scan_suspects.append(f"{src} → {len(dsts)} hosts")

    # ── 9. PORT TARAMA TESPİTİ ──────────────────────────────────────────────
    # SYN scan: single src to many unique dst ports
    syn_src_ports = defaultdict(set)
    for p in packets:
        info_low = (p.info or p.raw_summary or "").lower()
        if "syn" in info_low and "ack" not in info_low and p.dst_port:
            syn_src_ports[p.src].add(p.dst_port)
    for src, ports in syn_src_ports.items():
        if len(ports) > 20:
            r.port_scan_suspects.append(
                f"{src} → {len(ports)} port tarandı (SYN scan)"
            )
            _add_finding(r, "HIGH", "RECON",
                "Port Tarama Tespiti",
                f"{src} → {len(ports)} farklı porta SYN paketi gönderdi.",
                evidence=str(sorted(ports)[:20])
            )

    # RST-based scan hint
    rst_dsts = Counter(p.dst for p in packets if r.tcp_rst_count > 50)
    for dst, cnt in rst_dsts.most_common(5):
        if cnt > 50:
            r.service_enum_suspects.append(f"{dst} ({cnt} RST)")

    # ── 10. AĞ TİYOLOJİSİ ───────────────────────────────────────────────────
    # Gateway: src that appears frequently in both directions + forwards packets
    for ip, cnt in src_cnt.most_common(5):
        if ip in dst_cnt and cnt > 10:
            r.gateway_candidates.append(ip)

    # DNS servers
    for p in packets:
        if p.src_port == 53 and p.src and p.src not in r.dns_servers_seen:
            r.dns_servers_seen.append(p.src)
        if p.dst_port == 67 or p.src_port == 68:
            if p.src and p.src not in r.dhcp_servers_seen:
                r.dhcp_servers_seen.append(p.src)
        if p.dst_port == 123 or p.src_port == 123:
            if p.src and p.src not in r.ntp_servers_seen:
                r.ntp_servers_seen.append(p.src)

    # ── 11. ANOMALİ TESPİTİ ─────────────────────────────────────────────────
    avg_len = r.avg_packet_size
    for p in packets:
        if p.length > 1400:
            r.large_packets.append((p.index, p.length))
        if 0 < p.length < 20:
            r.tiny_packets.append((p.index, p.length))
        # TTL anomaly: unusual TTL values (not 64, 128, 255)
        if p.ttl and p.ttl not in (0, 64, 128, 255, 32, 60):
            r.ttl_anomalies.append((p.index, p.ttl))

    # ── 12. VPN / TÜNEL ─────────────────────────────────────────────────────
    vpn_ports = {500, 4500, 1194, 1723, 1701, 51820}
    for p in packets:
        if p.dst_port in vpn_ports or p.src_port in vpn_ports:
            svc = lookup_port(p.dst_port or p.src_port)[0]
            if svc not in r.vpn_traffic:
                r.vpn_traffic.append(svc)
        # GRE / ESP payloads (protocol-based)
        if p.protocol in ("GRE", "ESP", "AH", "L2TP"):
            if p.protocol not in r.tunnel_suspects:
                r.tunnel_suspects.append(p.protocol)

    # ── 13. CLEARTEXT PROTOKOLLER ────────────────────────────────────────────
    cleartext = {21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP",
                 110: "POP3", 143: "IMAP", 161: "SNMP", 69: "TFTP",
                 514: "Syslog", 389: "LDAP"}
    for port, name in cleartext.items():
        if port in all_ports_seen:
            if name not in r.cleartext_protocols:
                r.cleartext_protocols.append(name)
                _add_finding(r, "MEDIUM", "SECURITY",
                    f"Şifrelenmemiş Protokol: {name}",
                    f"{name} (port {port}) trafiği açık metin içerebilir."
                )

    # Credential heuristics — basic
    for p in packets:
        info = (p.info or "").lower()
        summary = (p.raw_summary or "").lower()
        combined = info + " " + summary
        for kw in ("login", "password", "pass=", "user=", "authorization", "credential",
                   "authenticate", "basic ", "passwd", "secret", "token"):
            if kw in combined:
                r.credential_suspects.append((p.index, kw, p.info[:80] if p.info else ""))
                _add_finding(r, "HIGH", "CREDENTIALS",
                    "Potansiyel Kimlik Bilgisi",
                    f"Paket #{p.index} içinde '{kw}' tespit edildi.",
                    packets=[p.index]
                )
                break

    # ── 14. EKSFİLTRASYON İPUCU ─────────────────────────────────────────────
    # Large outbound packets to external IPs
    for p in packets:
        if p.length > 8000 and p.src and p.dst:
            if _is_private(p.src) and not _is_private(p.dst):
                r.large_upload_suspects.append((p.index, p.length, p.dst))

    # C2 Beaconing: same src→dst pair with very regular intervals
    pair_times: dict[str, list[float]] = defaultdict(list)
    for p in packets:
        if p.src and p.dst:
            pair_times[f"{p.src}→{p.dst}"].append(_ts(p))

    for pair, times in pair_times.items():
        if len(times) >= 10:
            times_s = sorted(times)
            iats = [times_s[i+1] - times_s[i] for i in range(len(times_s)-1)]
            if iats:
                std = _stddev(iats)
                avg = sum(iats) / len(iats)
                # Very regular intervals = potential beacon
                if avg > 0 and std / avg < 0.1 and avg > 1.0:
                    r.beacon_suspects.append(
                        f"{pair} — {len(times)} paket, {avg:.1f}s aralık (std={std:.2f})"
                    )
                    _add_finding(r, "HIGH", "C2",
                        "C2 Beaconing Şüphesi",
                        f"{pair} çifti {avg:.1f}s düzenli aralıklarla iletişim kuruyor.",
                        evidence=f"std/avg = {std/avg:.3f}"
                    )

    # High entropy payload hint (from info field)
    for p in packets:
        combined = (p.info or "") + (p.raw_summary or "")
        if _entropy(combined) > 4.5 and p.length > 200:
            r.high_entropy_suspects.append((p.index, round(_entropy(combined), 2)))

    # ── 15. ICS / IOT ───────────────────────────────────────────────────────
    ics_ports  = {502, 2404, 44818, 47808, 20000, 4840, 102}
    iot_ports  = {1883, 5683, 8883, 8080}
    for p in packets:
        for port in (p.src_port, p.dst_port):
            if port in ics_ports:
                svc = lookup_port(port)[0]
                if svc not in r.ics_protocols_seen:
                    r.ics_protocols_seen.append(svc)
                    _add_finding(r, "HIGH", "ICS",
                        f"ICS/SCADA Protokolü: {svc}",
                        f"Endüstriyel kontrol protokolü port {port}'ta görüldü.",
                        packets=[p.index]
                    )
            if port in iot_ports:
                svc = lookup_port(port)[0]
                if svc not in r.iot_protocols_seen:
                    r.iot_protocols_seen.append(svc)

    # ── 16. MALWARE PORT UYARISI ─────────────────────────────────────────────
    for port, svc_name in r.malware_ports_seen:
        pkt_indices = [p.index for p in packets if p.dst_port == port or p.src_port == port]
        _add_finding(r, "CRITICAL", "MALWARE",
            f"Bilinen Zararlı Port: {port} ({svc_name})",
            f"Port {port} zararlı yazılım / C2 ile ilişkilendirilmiş.",
            packets=pkt_indices
        )

    for port, svc_name in r.risky_ports_seen:
        if port not in {p[0] for p in r.malware_ports_seen}:
            _add_finding(r, "MEDIUM", "SECURITY",
                f"Riskli Port: {port} ({svc_name})",
                f"Port {port} güvenlik riski taşıyan bir servisi işaret ediyor."
            )

    # ── 17. CRYPTO / BLOCKCHAIN ──────────────────────────────────────────────
    crypto_ports = {8333, 8332, 8545, 8546, 30303, 18080, 9333}
    for p in packets:
        for port in (p.src_port, p.dst_port):
            if port in crypto_ports:
                svc = lookup_port(port)[0]
                if svc not in r.crypto_traffic:
                    r.crypto_traffic.append(svc)

    # ── 18. KEY PACKETS (en önemli paketler) ─────────────────────────────────
    score: dict[int, int] = defaultdict(int)
    for p in packets:
        if p.is_risky:
            score[p.index] += 10
        if p.length > 1200:
            score[p.index] += 3
        if p.dst_port in {80, 443, 8080, 8443}:
            score[p.index] += 2
        for kw in ("login", "password", "flag", "secret", "key", "token", "auth"):
            if kw in (p.info or "").lower():
                score[p.index] += 20
                p.is_key_packet = True
        if p.dst_port in {p[0] for p in r.malware_ports_seen}:
            score[p.index] += 30
            p.is_key_packet = True
        for f in r.findings:
            if p.index in f.packets:
                score[p.index] += 15
                p.is_key_packet = True

    # Top 10 most significant
    top_scored = sorted(score.items(), key=lambda x: x[1], reverse=True)[:10]
    r.key_packet_indices = [idx for idx, _ in top_scored if score[idx] > 5]
    for p in packets:
        if p.index in r.key_packet_indices:
            p.is_key_packet = True

    # ── 19. THREAT LEVEL ─────────────────────────────────────────────────────
    critical_cnt = sum(1 for f in r.findings if f.severity == "CRITICAL")
    high_cnt     = sum(1 for f in r.findings if f.severity == "HIGH")
    med_cnt      = sum(1 for f in r.findings if f.severity == "MEDIUM")

    deduct = critical_cnt * 25 + high_cnt * 10 + med_cnt * 3
    r.security_score = max(0, 100 - deduct)

    if critical_cnt >= 1 or r.security_score < 30:
        r.threat_level = "CRITICAL"
    elif high_cnt >= 3 or r.security_score < 60:
        r.threat_level = "HIGH"
    elif med_cnt >= 3 or r.security_score < 80:
        r.threat_level = "MEDIUM"
    else:
        r.threat_level = "LOW"

    # ── 20. CTF İPUÇLARI ─────────────────────────────────────────────────────
    if description:
        desc_low = description.lower()
        if any(kw in desc_low for kw in ("ctf", "flag", "challenge", "solve")):
            r.ctf_hints.extend([
                "HTTP GET/POST yanıtlarında flag formatı arayın (FLAG{...}, CTF{...})",
                "TLS/SSL el sıkışmasında sertifika alanlarına bakın",
                "DNS sorgularında gömülü veri olabilir (DNS tüneli)",
                "ICMP payload'larını inceleyin — veri gizlenmiş olabilir",
                "Büyük paketlerdeki ham veriyi base64/hex decode edin",
                "Kimlik bilgilerini içeren HTTP Basic Auth başlıklarına bakın",
                "FTP/SMTP cleartext oturumlarında credential arayın",
            ])

    # ── 21. TAVSİYELER ───────────────────────────────────────────────────────
    if r.cleartext_protocols:
        r.recommendations.append(
            f"Şifrelenmemiş protokoller ({', '.join(r.cleartext_protocols)}) yerine "
            "şifreli alternatifleri kullanın (SSH, HTTPS, LDAPS, SMTPS)."
        )
    if r.malware_ports_seen:
        r.recommendations.append(
            f"Zararlı portlar tespit edildi ({[p for p,_ in r.malware_ports_seen]}). "
            "Bu portları güvenlik duvarında derhal engelleyin."
        )
    if r.port_scan_suspects:
        r.recommendations.append(
            "Port taraması tespit edildi. IPS/IDS kurallarını gözden geçirin ve "
            "tarama yapan IP'leri engelleyin."
        )
    if r.dns_tunnel_suspect:
        r.recommendations.append(
            "DNS tünel şüphesi var. DNS trafiğini RPZ veya DNS güvenlik duvarı ile filtreleyin."
        )
    if r.beacon_suspects:
        r.recommendations.append(
            "C2 beaconing şüphesi. Şüpheli host'ları izole edin ve EDR ile tarayın."
        )
    if r.half_open_conns > 50:
        r.recommendations.append(
            f"{r.half_open_conns} yarı açık TCP bağlantısı tespit edildi. "
            "SYN cookie veya rate-limiting uygulayın."
        )
    if r.ics_protocols_seen:
        r.recommendations.append(
            "ICS/SCADA protokolleri tespit edildi. Bu ağı IT ağından segmentlere ayırın."
        )
    if not r.vpn_traffic and r.external_hosts:
        r.recommendations.append(
            "Dış ağ trafiği VPN koruması olmadan gözüküyor. VPN kullanımını zorunlu kılın."
        )
    if r.large_upload_suspects:
        r.recommendations.append(
            f"{len(r.large_upload_suspects)} büyük dış yükleme paketi tespit edildi. "
            "DLP (Data Loss Prevention) politikalarını gözden geçirin."
        )
    r.recommendations.append("Düzenli PCAP analizi ile ağ baseline'ı oluşturun ve anomalileri izleyin.")

    # ── 22. EXECUTİVE SUMMARY ────────────────────────────────────────────────
    r.executive_summary = _build_summary(r)

    return r


def _add_finding(r: NoAIReport, severity: str, category: str,
                 title: str, description: str,
                 packets: list = None, evidence: str = ""):
    # Duplicate prevention
    for f in r.findings:
        if f.title == title:
            return
    r.findings.append(Finding(
        severity=severity, category=category,
        title=title, description=description,
        packets=packets or [], evidence=evidence
    ))


def _build_summary(r: NoAIReport) -> str:
    lines = [
        f"Toplam {r.total_packets} paket ({r.total_bytes:,} byte) analiz edildi.",
        f"Yakalama süresi: {r.duration_sec:.2f}s | Ortalama hız: {r.packets_per_second:.1f} pkt/s.",
        f"Tespit edilen protokoller: {', '.join(list(r.protocol_counts.keys())[:8])}.",
        f"Benzersiz kaynak IP: {len(r.unique_src_ips)} | Hedef IP: {len(r.unique_dst_ips)}.",
    ]
    if r.findings:
        crit = sum(1 for f in r.findings if f.severity == "CRITICAL")
        high = sum(1 for f in r.findings if f.severity == "HIGH")
        lines.append(
            f"Toplam {len(r.findings)} güvenlik bulgusu ({crit} KRİTİK, {high} YÜKSEK). "
            f"Güvenlik skoru: {r.security_score}/100."
        )
    if r.port_scan_suspects:
        lines.append(f"PORT TARAMASI TESPİT EDİLDİ: {'; '.join(r.port_scan_suspects[:3])}")
    if r.beacon_suspects:
        lines.append(f"C2 BEACONING ŞÜPHESİ: {r.beacon_suspects[0]}")
    if r.dns_tunnel_suspect:
        lines.append("DNS TÜNELİ ŞÜPHESİ tespit edildi.")
    return " ".join(lines)
