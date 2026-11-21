"""
PCAP ANALYZER - Smart Prompt Engine
VCAS.PRIVATE × QNTSOFTWARE

Parses user task descriptions to:
  1. Detect intended protocols and forensic domain
  2. Focus AI reasoning on targeted packets
  3. Inject expert analyst persona profiles
  4. Generate optimized Wireshark display filter hints
"""

import os
import re
from pathlib import Path
from .parser import Packet
from .lang import get_ai_language_instruction, get_lang


PERSONA_DIR = Path(__file__).parent / "persona"


def _load_persona() -> str:
    """Read all persona/character files."""
    texts = []
    if PERSONA_DIR.exists():
        for f in sorted(PERSONA_DIR.glob("*.md")):
            texts.append(f.read_text(encoding="utf-8"))
    return "\n\n".join(texts)


# --- Protocol Keyword & Filter Mappings ---
PROTO_KEYWORDS: list[tuple[str, list[str], str]] = [
    # (label, keywords, auto_tshark_filter)
    ("FTP",        ["ftp","file transfer","dosya transfer","ftp auth","ftp login","anonymous ftp"],
                   "ftp or ftp-data"),
    ("HTTP",       ["http","web","get request","post request","web traffic","html","http auth","basic auth","authorization"],
                   "http"),
    ("HTTPS",      ["https","ssl","tls","certificate","sertifika","handshake","cipher","https traffic"],
                   "ssl or tls"),
    ("DNS",        ["dns","domain","name resolution","dns query","dns tünel","dns tunnel","subdomain"],
                   "dns"),
    ("SMB",        ["smb","samba","windows share","file share","ntlm","eternalblue","ms17-010"],
                   "smb or smb2"),
    ("SSH",        ["ssh","secure shell","ssh tunnel","ssh brute"],
                   "ssh"),
    ("TELNET",     ["telnet","cleartext shell","unencrypted shell"],
                   "telnet"),
    ("SIP",        ["sip","voip","voice","ses","çağrı","call","register","invite","bye","rtp","asterisk"],
                   "sip or rtp"),
    ("ICMP",       ["icmp","ping","echo","traceroute","ping sweep","icmp tunnel","ping flood"],
                   "icmp or icmpv6"),
    ("ARP",        ["arp","mac address","gratuitous arp","arp poison","arp spoof","mitm"],
                   "arp"),
    ("DHCP",       ["dhcp","ip lease","ip address assign","rogue dhcp","dhcp starvation"],
                   "dhcp or dhcpv6 or bootp"),
    ("SNMP",       ["snmp","management","community string","snmpwalk","mibs"],
                   "snmp"),
    ("SMTP",       ["smtp","email","e-posta","mail","ehlo","helo","rcpt","from:"],
                   "smtp"),
    ("IMAP",       ["imap","mail fetch","inbox"],
                   "imap"),
    ("POP3",       ["pop3","pop","mail download"],
                   "pop"),
    ("LDAP",       ["ldap","active directory","ad","directory service","ldap bind"],
                   "ldap"),
    ("MYSQL",      ["mysql","sql","database","mariadb","port 3306"],
                   "mysql"),
    ("RDP",        ["rdp","remote desktop","ms-rdp","xrdp"],
                   "rdp"),
    ("KERBEROS",   ["kerberos","ticket","krb","kdc","as-req","tgs"],
                   "kerberos"),
    ("BGP",        ["bgp","border gateway","routing","autonomous system","as path"],
                   "bgp"),
    ("OSPF",       ["ospf","link state","routing protocol","lsa"],
                   "ospf"),
    ("MODBUS",     ["modbus","scada","plc","industrial","ics","ot network"],
                   "modbus"),
    ("MQTT",       ["mqtt","iot","broker","publish","subscribe","sensor"],
                   "mqtt"),
    ("HTTP2",      ["http/2","http2","h2","grpc","multiplexing"],
                   "http2"),
    ("QUIC",       ["quic","http/3","http3","udp 443"],
                   "quic"),
    ("NETBIOS",    ["netbios","nbns","broadcast name"],
                   "nbns or nbdgm or nbss"),
    ("NTP",        ["ntp","time server","ntp amplif","clock sync"],
                   "ntp"),
    ("ISAKMP",     ["ipsec","isakmp","ikev2","vpn tunnel","esp"],
                   "isakmp or esp"),
    ("OPENVPN",    ["openvpn","port 1194","vpn traffic"],
                   "openvpn"),
    ("BITTORRENT", ["bittorrent","p2p","torrent","dht","peer"],
                   "bittorrent"),
    ("COAP",       ["coap","constrained","iot protocol","port 5683"],
                   "coap"),
]


def detect_protocol_from_description(description: str) -> tuple[str, str]:
    """
    Kullanıcının -des açıklamasından protokolü tespit eder.
    Returns: (protocol_label, suggested_tshark_filter)
    """
    desc_lower = description.lower()
    matches = []
    for label, keywords, filt in PROTO_KEYWORDS:
        score = sum(1 for kw in keywords if kw in desc_lower)
        if score > 0:
            matches.append((score, label, filt))

    if matches:
        matches.sort(reverse=True)
        best_score, best_label, best_filter = matches[0]
        return best_label, best_filter

    return "GENERAL", ""


def detect_task_type(description: str) -> str:
    """
    Görev tipini tespit et: CTF | FORENSIC | AUDIT | RECON | MALWARE | GENERAL
    """
    desc_lower = description.lower()
    if any(kw in desc_lower for kw in ["ctf", "flag", "challenge", "solve", "flag{", "çöz", "bul"]):
        return "CTF"
    if any(kw in desc_lower for kw in ["forensic", "incident", "breach", "saldırı", "attack", "malware", "ransomware"]):
        return "FORENSIC"
    if any(kw in desc_lower for kw in ["audit", "denetim", "penetration", "pentest", "vulnerability", "güvenlik açığı"]):
        return "AUDIT"
    if any(kw in desc_lower for kw in ["scan", "recon", "enumerat", "discover", "tarama", "keşif"]):
        return "RECON"
    if any(kw in desc_lower for kw in ["monitor", "baseline", "normal traffic", "analiz", "statistics"]):
        return "MONITORING"
    return "GENERAL"


def build_smart_prompt(
    packets: list[Packet],
    description: str,
    auto_filter: bool = True,
) -> str:
    """
    Akıllı, odaklanmış AI prompt'u oluşturur.
    - Persona karakter dosyasını okur
    - Protokolü ve görev tipini tespit eder
    - Sadece ilgili paketlere odaklanır
    - Wireshark uzmanı seviyesinde talimatlar verir
    """
    # 1. Load analyst persona
    persona = _load_persona()

    # 2. Protocol & task classification
    detected_proto, suggested_filter = detect_protocol_from_description(description)
    task_type = detect_task_type(description)

    # 3. Protocol-focused packet filtering
    if auto_filter and detected_proto != "GENERAL":
        focused_packets = _focus_packets(packets, detected_proto)
        if not focused_packets:
            focused_packets = packets
    else:
        focused_packets = packets

    # 4. Generate packet summaries
    packet_lines = []
    for p in focused_packets[:500]:
        port_info = f":{p.dst_port}" if p.dst_port else ""
        svc_info  = f" [{p.service}]" if p.service and p.service != p.protocol else ""
        ttl_info  = f" TTL={p.ttl}" if p.ttl else ""
        flag_info = f" FLAGS={p.flags}" if p.flags else ""
        risk_info = " ⚠RISKY" if p.is_risky else ""
        line = (
            f"#{p.index} t={p.timestamp}s | "
            f"{p.src} → {p.dst}{port_info} | "
            f"proto={p.protocol}{svc_info} | "
            f"len={p.length}B{ttl_info}{flag_info}{risk_info} | "
            f"{p.info or ''}"
        )
        packet_lines.append(line)

    pkt_text = "\n".join(packet_lines)
    total    = len(packets)
    focused  = len(focused_packets)

    # 5. Specialized task instructions
    task_instructions = _get_task_instructions(task_type, detected_proto, description)

    # 6. Protocol deep-dive instructions
    proto_instructions = _get_proto_instructions(detected_proto)

    # 7. Language enforcement instruction
    lang_instruction = get_ai_language_instruction()

    prompt = f"""
{persona}

═══════════════════════════════════════════════════════════════════
LANGUAGE INSTRUCTION
═══════════════════════════════════════════════════════════════════
{lang_instruction}

═══════════════════════════════════════════════════════════════════
TASK CONTEXT
═══════════════════════════════════════════════════════════════════

**USER DESCRIPTION:** {description}

**DETECTED PROTOCOL:** {detected_proto}
**TASK TYPE:** {task_type}
**RECOMMENDED FILTER:** {suggested_filter or "None"}
**TOTAL PACKETS:** {total} (focused: {focused})

═══════════════════════════════════════════════════════════════════
FOCUS INSTRUCTIONS
═══════════════════════════════════════════════════════════════════

{task_instructions}

{proto_instructions}

═══════════════════════════════════════════════════════════════════
PACKETS ({focused} packets in scope)
═══════════════════════════════════════════════════════════════════

{pkt_text}

═══════════════════════════════════════════════════════════════════
ANALYSIS OBJECTIVES
═══════════════════════════════════════════════════════════════════

1. Explain every packet concisely on a single line (format: #N: explanation)
2. Focus deeply on {detected_proto} protocol events
3. Isolate KEY PACKETS that directly answer or solve the objective
4. Extract credentials, hashes, flags, certificates, and anomalies
5. Provide actionable findings matching the {task_type} objective

RESPONSE FORMAT (JSON only):
{{
  "packet_summaries": [
    {{"index": 1, "summary": "single line explanation", "is_key": false, "highlights": []}}
  ],
  "key_packet_indices": [42],
  "highlights": [
    {{"packet_index": 42, "field": "value or field name", "reason": "significance"}}
  ],
  "detected_protocol": "{detected_proto}",
  "task_type": "{task_type}",
  "executive_summary": "...",
  "detailed_analysis": "...",
  "ctf_answer": "FLAG{{...}} or N/A",
  "decoded_values": [
    {{"type": "base64/hex/cipher", "original": "...", "decoded": "..."}}
  ],
  "protocol_findings": {{
    "credentials": [],
    "hashes": [],
    "certificates": [],
    "files_transferred": [],
    "commands": []
  }},
  "security_recommendations": ["..."],
  "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "attack_vectors": [],
  "ioc_list": []
}}
"""
    return prompt


def _focus_packets(packets: list[Packet], protocol: str) -> list[Packet]:
    """Filter and prioritize packets matching the requested protocol or port."""
    proto_lower = protocol.lower()

    exact = [p for p in packets if proto_lower in p.protocol.lower() or proto_lower in p.service.lower()]
    if exact:
        return exact

    port_map = {
        "FTP":      {20, 21},
        "HTTP":     {80, 8080, 8000, 8008, 8888},
        "HTTPS":    {443, 8443, 4443},
        "DNS":      {53},
        "SMB":      {445, 139, 137, 138},
        "SSH":      {22},
        "TELNET":   {23},
        "SIP":      {5060, 5061},
        "ICMP":     set(),
        "ARP":      set(),
        "DHCP":     {67, 68},
        "SNMP":     {161, 162},
        "SMTP":     {25, 587, 465},
        "IMAP":     {143, 993},
        "POP3":     {110, 995},
        "LDAP":     {389, 636},
        "MYSQL":    {3306, 3307},
        "RDP":      {3389},
        "KERBEROS": {88},
        "BGP":      {179},
        "MODBUS":   {502},
        "MQTT":     {1883, 8883},
        "NTP":      {123},
    }
    ports = port_map.get(protocol.upper(), set())
    if ports:
        port_matched = [p for p in packets if p.dst_port in ports or p.src_port in ports]
        if port_matched:
            return port_matched

    info_matched = [p for p in packets
                    if proto_lower in (p.info or "").lower()
                    or proto_lower in (p.raw_summary or "").lower()]
    if info_matched:
        return info_matched

    return packets


def _get_task_instructions(task_type: str, protocol: str, description: str) -> str:
    if task_type == "CTF":
        return f"""
TARGET OBJECTIVE: CTF (Capture The Flag) Challenge
1. Prioritize {protocol} traffic before inspecting other protocols.
2. Search for flag signatures: FLAG{{...}}, CTF{{...}}, picoCTF{{...}}, ASIS{{...}}, HTB{{...}}, Root-Me{{...}}
3. Check authentication headers, cleartext credentials, transferred file streams.
4. Detect Base64, hex, XOR, ROT13 encoding and decode hidden payload text.
5. Inspect SSL/TLS certificates (Subject Alternative Names, Common Names) for embedded flags.
USER REQUEST: "{description}"
"""
    elif task_type == "FORENSIC":
        return f"""
TARGET OBJECTIVE: Digital Forensics & Incident Response (DFIR)
1. Reconstruct incident chronological timeline.
2. Focus on {protocol} anomalies, unauthorized access, and lateral movement.
3. Extract Indicators of Compromise (IOCs): suspicious IPs, ports, malicious domains, C2 channels.
USER REQUEST: "{description}"
"""
    elif task_type == "AUDIT":
        return f"""
TARGET OBJECTIVE: Security Audit & Penetration Testing
1. Identify protocol misconfigurations, weak ciphers, and unencrypted credentials on {protocol}.
2. Benchmark against network hardening best practices.
USER REQUEST: "{description}"
"""
    else:
        return f"""
TARGET OBJECTIVE: Network Traffic Intelligence & Protocol Audit
Focused protocol: {protocol}
User request: "{description}"
"""


def _get_proto_instructions(protocol: str) -> str:
    instructions = {
        "FTP": """
FTP ANALYSIS DIRECTIVES:
- Separate Port 21 (control) and Port 20 (data transfer).
- Isolate USER and PASS commands (cleartext authentication credentials).
- Trace RETR (file download) and STOR (file upload) commands.
- Correlate PASV responses to data connection ephemeral ports.
- Identify anonymous FTP logins and server response codes (230, 331, 530).
""",
        "HTTP": """
HTTP ANALYSIS DIRECTIVES:
- Enumerate GET, POST, PUT requests (URIs, query parameters, endpoints).
- Parse Authorization: Basic headers, Base64 decode to username:password.
- Analyze Cookie and Set-Cookie session identifiers.
- Inspect POST payloads for form data, JSON structures, or exfiltration.
- Highlight HTTP response status codes (200, 301, 302, 401, 403, 500).
- Check X-Custom headers and response bodies for flags or leaked keys.
""",
        "HTTPS": """
TLS/SSL ANALYSIS DIRECTIVES:
- Dissect ClientHello: TLS record version, cipher suite offerings, SNI domain.
- Dissect ServerHello: Negotiated cipher suite and protocol version.
- Extract X.509 Certificate CN, SAN, and Issuer fields.
- Flag weak or legacy cipher suites (RC4, 3DES, EXPORT, NULL).
""",
        "DNS": """
DNS ANALYSIS DIRECTIVES:
- Audit query types: A, AAAA, MX, TXT, NS, SOA, PTR, SRV.
- Deep-dive into TXT records for verification tokens or steganographic data.
- Analyze subdomain entropy to uncover DNS tunneling and data exfiltration.
- Detect fast-flux domains (ultra-low TTL) and NXDOMAIN brute-forcing.
""",
        "SIP": """
SIP/VOIP ANALYSIS DIRECTIVES:
- Audit REGISTER and INVITE transactions.
- Extract Authorization headers (realm, nonce, uri, algorithm, response hash).
- Harvest MD5 response hashes for offline Hashcat recovery (mode 11400).
- Map associated RTP media audio streams.
""",
        "ICMP": """
ICMP ANALYSIS DIRECTIVES:
- Inspect Type 8/0 Echo Request/Reply payloads as ASCII text.
- Detect ICMP covert channels and tunneling.
- Flag ping sweeps and ICMP flood denial of service attempts.
""",
        "SMB": """
SMB/SAMBA ANALYSIS DIRECTIVES:
- Detect legacy SMBv1 negotiation (EternalBlue MS17-010 risk).
- Trace NTLM challenge-response authentication exchanges.
- Enumerate accessed administrative share names (C$, ADMIN$, IPC$).
""",
    }
    return instructions.get(protocol, f"# Focus on {protocol} protocol events\n")


def suggest_filter_from_description(description: str) -> str:
    """Recommend Wireshark display filter inferred from task description."""
    _, filt = detect_protocol_from_description(description)
    return filt
