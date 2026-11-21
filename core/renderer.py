"""
PCAP ANALYZER - Terminal Renderer
VCAS.PRIVATE & QNTSOFTWARE

Color codes:
  - Normal packets  → white/default
  - KEY packets     → bright red background + bold
  - Important words → bright yellow
  - Protocol badges → cyan
  - Metadata        → dim grey
"""

import sys
import re
import shutil
from .lang import L, get_lang

# ANSI codes
RESET     = "\033[0m"
BOLD      = "\033[1m"
DIM       = "\033[2m"
RED_BG    = "\033[41m"
RED       = "\033[91m"
YELLOW    = "\033[93m"
CYAN      = "\033[96m"
GREEN     = "\033[92m"
MAGENTA   = "\033[95m"
BLUE      = "\033[94m"
WHITE     = "\033[97m"
GREY      = "\033[90m"

TERM_WIDTH = shutil.get_terminal_size((120, 40)).columns


def _divider(char="─", color=GREY):
    print(f"{color}{char * TERM_WIDTH}{RESET}")


def _banner():
    banner = r"""
██████╗  ██████╗ █████╗ ██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
██╔══██╗██╔════╝██╔══██╗██╔══██╗    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
██████╔╝██║     ███████║██████╔╝    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
██╔═══╝ ██║     ██╔══██║██╔═══╝     ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
██║     ╚██████╗██║  ██║██║         ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝         ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
"""
    print(f"{CYAN}{BOLD}{banner}{RESET}")
    print(f"{GREY}{'─'*TERM_WIDTH}{RESET}")
    print(f"{WHITE}{BOLD}  VCAS.PRIVATE  ×  QNTSOFTWARE  —  Network Intelligence Platform{RESET}")
    print(f"{GREY}{'─'*TERM_WIDTH}{RESET}\n")


def _proto_badge(proto: str) -> str:
    colors = {
        "HTTP": f"{GREEN}",
        "HTTPS": f"{GREEN}",
        "TLS": f"{GREEN}",
        "SSL": f"{GREEN}",
        "DNS": f"{BLUE}",
        "TCP": f"{CYAN}",
        "UDP": f"{CYAN}",
        "ICMP": f"{MAGENTA}",
        "ARP": f"{MAGENTA}",
        "FTP": f"{YELLOW}",
        "SSH": f"{YELLOW}",
        "SMTP": f"{YELLOW}",
        "SMB": f"{RED}",
        "SMB2": f"{RED}",
    }
    color = colors.get(proto, WHITE)
    return f"{color}[{proto}]{RESET}"


def _highlight_text(text: str, fields: list) -> str:
    """Apply yellow highlighting to important field values in text."""
    for field in fields:
        if field and field in text:
            text = text.replace(field, f"{YELLOW}{BOLD}{field}{RESET}")
    return text


def render_banner():
    _banner()


def render_packet_list(packets, analysis: dict):
    """Render all packets with color coding."""
    total = len(packets)
    key_count = sum(1 for p in packets if p.is_key_packet)

    hdr = L("section_packet_list")
    print(f"\n{BOLD}{WHITE}  ┌─ {hdr} ───────────────────────────────────────{RESET}")
    print(f"{BOLD}{WHITE}  │  Total: {CYAN}{total}{RESET}{BOLD}{WHITE}   {L('key_packet')}s: {RED}{key_count}{RESET}\n")

    for p in packets:
        summary = p.raw_summary or f"Packet #{p.index}"
        summary = _highlight_text(summary, p.highlighted_fields)

        # Format the base line
        meta = f"{DIM}{GREY}  {p.timestamp:>10}s  {RESET}"
        badge = _proto_badge(p.protocol)
        length_str = f"{GREY}{p.length:>5}B{RESET}"
        idx_str = f"{GREY}#{p.index:<5}{RESET}"

        if p.is_key_packet:
            # RED background highlight for key packet
            kp = L("key_packet")
            line = (
                f"\n{RED_BG}{BOLD}  ★ {kp}  "
                f"#{p.index} │ {p.src} → {p.dst} │ {p.protocol} │ {p.length}B  {RESET}\n"
                f"{RED}{BOLD}    └─ {summary}{RESET}\n"
            )
            print(line)
        else:
            line = f"  {idx_str} {meta} {badge} {length_str}  {summary}"
            print(line)

    _divider()


def render_analysis(analysis: dict):
    """Render AI analysis sections."""
    threat_colors = {
        "LOW": GREEN,
        "MEDIUM": YELLOW,
        "HIGH": f"{BOLD}{RED}",
        "CRITICAL": f"{BOLD}{RED_BG}",
        "UNKNOWN": GREY
    }
    threat = analysis.get("threat_level", "UNKNOWN")
    t_color = threat_colors.get(threat, GREY)

    title = L("ai_report_title")
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║{title:^62}║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════╝{RESET}\n")

    # Threat Level
    print(f"  {BOLD}{L('section_threat_level')}:{RESET}  {t_color}{BOLD}{threat}{RESET}\n")
    _divider("─")

    # Executive Summary
    print(f"\n  {BOLD}{WHITE}▶ {L('section_executive_summary')}{RESET}")
    summary_text = analysis.get("executive_summary", "No summary available.")
    for line in _wrap(summary_text, TERM_WIDTH - 6):
        print(f"    {WHITE}{line}{RESET}")

    _divider("·")

    # Detailed Analysis
    print(f"\n  {BOLD}{WHITE}▶ {L('section_detailed_analysis')}{RESET}")
    detail = analysis.get("detailed_analysis", "")
    for line in _wrap(detail, TERM_WIDTH - 6):
        print(f"    {line}")

    _divider("·")

    # CTF Answer
    ctf = analysis.get("ctf_answer", "N/A")
    if ctf and ctf != "N/A":
        print(f"\n  {BOLD}{YELLOW}★ {L('section_ctf_answer')}:{RESET}")
        print(f"    {BOLD}{GREEN}{ctf}{RESET}\n")
        _divider("·")

    # Highlights
    highlights = analysis.get("highlights", [])
    if highlights:
        print(f"\n  {BOLD}{WHITE}▶ {L('section_key_findings')}{RESET}")
        for h in highlights:
            pkt = h.get("packet_index", "?")
            field = h.get("field", "")
            reason = h.get("reason", "")
            print(f"    {YELLOW}●{RESET} Pkt #{pkt}: {YELLOW}{BOLD}{field}{RESET}  {GREY}← {reason}{RESET}")
        _divider("·")

    # Security Recommendations
    recs = analysis.get("security_recommendations", [])
    if recs:
        print(f"\n  {BOLD}{WHITE}▶ {L('section_recommendations')}{RESET}")
        for i, rec in enumerate(recs, 1):
            print(f"    {CYAN}{i}.{RESET} {rec}")

    print(f"\n{GREY}{'═'*TERM_WIDTH}{RESET}\n")


def render_config_saved(key_hint: str):
    print(f"\n  {GREEN}✔ API key saved successfully!{RESET}")
    print(f"  {GREY}Key: {key_hint[:8]}{'*'*12}{RESET}\n")


def render_error(msg: str):
    print(f"\n  {RED}{BOLD}[ERROR]{RESET} {msg}\n")


def render_info(msg: str):
    print(f"  {CYAN}[*]{RESET} {msg}")


def render_pdf_saved(path: str):
    print(f"\n  {GREEN}{BOLD}✔ PDF Report saved:{RESET} {path}\n")


def _wrap(text: str, width: int) -> list[str]:
    """Simple word-wrap."""
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 <= width:
            current = (current + " " + word).lstrip()
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


# ═══════════════════════════════════════════════════════════════
#  NO-AI REPORT RENDERER
# ═══════════════════════════════════════════════════════════════

SEV_COLOR = {
    "CRITICAL": f"{RED_BG}{BOLD}",
    "HIGH":     f"{RED}{BOLD}",
    "MEDIUM":   f"{YELLOW}",
    "LOW":      f"{CYAN}",
    "INFO":     f"{GREY}",
}

CAT_ICON = {
    "SECURITY":     "🔐",
    "MALWARE":      "☠",
    "C2":           "👾",
    "RECON":        "🔍",
    "ANOMALY":      "⚠",
    "CREDENTIALS":  "🔑",
    "ICS":          "⚙",
    "PERFORMANCE":  "📊",
}


def render_noai_report(
    packets,
    report,
    show_conversations: bool = False,
    show_dns: bool = False,
    show_ports: bool = False,
    show_hosts: bool = False,
    show_timing: bool = False,
    show_ics: bool = False,
    show_crypto: bool = False,
    show_vpn: bool = False,
    compact: bool = False,
):
    """Full No-AI terminal report renderer."""
    from .noai import NoAIReport, Finding

    # --- Packet List ---
    _divider()
    print(f"\n{BOLD}{WHITE}  {L('section_packet_list')}  ({len(packets)}){RESET}\n")
    for p in packets:
        summary   = _highlight_text(p.raw_summary or p.info or f"Packet #{p.index}", p.highlighted_fields)
        badge     = _proto_badge(p.protocol)
        risk_flag = f" {RED}{BOLD}[{L('risky_label')}]{RESET}" if p.is_risky else ""
        len_str   = f"{GREY}{p.length:>5}B{RESET}"
        ttl_str   = f"{GREY} TTL={p.ttl}{RESET}" if p.ttl else ""
        port_str  = f"{GREY} :{p.dst_port}{RESET}" if p.dst_port else ""
        svc_str   = f" {CYAN}{p.service}{RESET}" if p.service and p.service != p.protocol else ""

        if p.is_key_packet:
            print(f"\n{RED_BG}{BOLD}  ★ KEY  #{p.index} │ {p.src} → {p.dst} │ {p.protocol}{p.service and ' '+p.service or ''} │ {p.length}B  {RESET}")
            print(f"{RED}{BOLD}    └─ {summary}{RESET}\n")
        elif compact:
            print(f"  {GREY}#{p.index:<5}{RESET} {badge}{svc_str}{port_str} {len_str}{risk_flag}  {summary[:90]}")
        else:
            print(f"  {GREY}#{p.index:<5}{RESET} {GREY}{str(p.timestamp)[:10]:>12}s{RESET} "
                  f"{badge}{svc_str}{port_str}{ttl_str} {len_str}{risk_flag}  {summary}")

    _divider()

    # --- Statistical Summary ---
    noai_title = L("noai_report_title")
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║{noai_title:^58}║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════╝{RESET}\n")

    threat_colors = {
        "LOW": GREEN, "MEDIUM": YELLOW,
        "HIGH": f"{BOLD}{RED}", "CRITICAL": f"{BOLD}{RED_BG}", "UNKNOWN": GREY
    }
    tc = threat_colors.get(report.threat_level, GREY)
    print(f"  {BOLD}{L('section_threat_level')}:{RESET}  {tc}{BOLD}{report.threat_level}{RESET}   "
          f"{BOLD}{L('security_score')}:{RESET}  {_score_color(report.security_score)}{report.security_score}/100{RESET}\n")
    _divider("─")

    # --- Basic Statistics ---
    print(f"\n  {BOLD}{WHITE}▶ {L('section_executive_summary')}{RESET}")
    stats = [
        (L("total_packets"),  f"{report.total_packets:,}"),
        ("Bytes",             f"{report.total_bytes:,} byte  ({report.total_bytes/1024:.1f} KB)"),
        (L("duration"),       f"{report.duration_sec:.3f} s"),
        ("Avg Packet Size",   f"{report.avg_packet_size:.1f} byte"),
        ("Pkt/s",             f"{report.packets_per_second:.1f}"),
        ("Byte/s",            f"{report.bytes_per_second:.0f}"),
        ("Start",             report.capture_start),
        ("End",               report.capture_end),
        ("Unique Src IP",     str(len(report.unique_src_ips))),
        ("Unique Dst IP",     str(len(report.unique_dst_ips))),
        ("Internal Hosts",    str(len(report.internal_hosts))),
        ("External Hosts",    str(len(report.external_hosts))),
        ("Findings",          str(len(report.findings))),
    ]
    for k, v in stats:
        print(f"    {CYAN}{k:<22}{RESET} {WHITE}{v}{RESET}")

    _divider("·")

    # --- Protocol Distribution ---
    print(f"\n  {BOLD}{WHITE}▶ {L('protocol_distribution')}{RESET}")
    for proto, cnt in list(report.protocol_counts.items())[:15]:
        bar_len = min(40, int(cnt / max(report.total_packets, 1) * 40))
        bar = f"{CYAN}{'█' * bar_len}{GREY}{'░' * (40 - bar_len)}{RESET}"
        byt = report.protocol_bytes.get(proto, 0)
        print(f"    {WHITE}{proto:<12}{RESET} {bar}  {cnt:>6} pkt  {byt/1024:>8.1f} KB")

    _divider("·")

    # --- Security Findings ---
    if report.findings:
        print(f"\n  {BOLD}{WHITE}▶ {L('security_findings')} ({len(report.findings)}){RESET}")
        for f in sorted(report.findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity)):
            sc  = SEV_COLOR.get(f.severity, "")
            ico = CAT_ICON.get(f.category, "●")
            print(f"\n    {sc}[{f.severity}]{RESET} {ico}  {BOLD}{f.title}{RESET}")
            for line in _wrap(f.description, TERM_WIDTH - 10):
                print(f"           {GREY}{line}{RESET}")
            if f.evidence:
                print(f"           {DIM}Evidence: {f.evidence[:80]}{RESET}")
            if f.packets:
                print(f"           {DIM}Packets: {f.packets[:8]}{RESET}")

    _divider("·")

    # --- Executive Summary ---
    print(f"\n  {BOLD}{WHITE}▶ {L('summary_label')}{RESET}")
    for line in _wrap(report.executive_summary, TERM_WIDTH - 6):
        print(f"    {WHITE}{line}{RESET}")

    # --- Optional Diagnostic Sections ---

    if show_hosts or not compact:
        _divider("·")
        print(f"\n  {BOLD}{WHITE}▶ {L('top_talkers')} (Top 10){RESET}")
        for ip, cnt in report.top_talkers[:10]:
            print(f"    {CYAN}{ip:<20}{RESET}  {cnt:>6} pkt")
        print(f"\n  {BOLD}{WHITE}▶ TOP DESTINATIONS (Top 10){RESET}")
        for ip, cnt in report.top_destinations[:10]:
            print(f"    {CYAN}{ip:<20}{RESET}  {cnt:>6} pkt")

    if show_ports:
        _divider("·")
        print(f"\n  {BOLD}{WHITE}▶ TOP DESTINATION PORTS{RESET}")
        for port, cnt, svc in report.top_dst_ports[:20]:
            cat    = __import__('core.ports', fromlist=['get_category']).get_category(port) if False else ""
            risky  = f" {RED}[{L('risky_label')}]{RESET}" if is_risky_port(port) else ""
            svc_info = f"{CYAN}{svc:<18}{RESET}" if svc else f"{GREY}PORT-{port:<14}{RESET}"
            print(f"    {WHITE}{port:<7}{RESET} {svc_info} {cnt:>6} pkt{risky}")

        if report.malware_ports_seen:
            print(f"\n  {RED}{BOLD}  ☠ MALWARE PORTS:{RESET}")
            for port, svc in report.malware_ports_seen:
                print(f"    {RED}{BOLD}  → Port {port} ({svc}){RESET}")

    if show_conversations:
        _divider("·")
        print(f"\n  {BOLD}{WHITE}▶ TCP CONVERSATIONS (Top 20){RESET}")
        for conv in report.tcp_conversations[:20]:
            print(f"    {GREY}{conv}{RESET}")

    if show_dns and report.dns_queries:
        _divider("·")
        print(f"\n  {BOLD}{WHITE}▶ DNS QUERIES ({len(report.dns_queries)}){RESET}")
        for idx, domain in report.dns_queries[:30]:
            ent_flag = ""
            try:
                from .noai import _entropy
                if _entropy(domain.split(".")[0]) > 3.5:
                    ent_flag = f" {YELLOW}[HIGH ENTROPY - TUNNEL?]{RESET}"
            except Exception:
                pass
            print(f"    #{idx:<5} {CYAN}{domain}{RESET}{ent_flag}")
        if report.dns_tunnel_suspect:
            print(f"\n    {YELLOW}{BOLD}⚠ DNS TUNNEL SUSPECT DETECTED!{RESET}")

    if show_timing:
        _divider("·")
        print(f"\n  {BOLD}{WHITE}▶ TIMING ANALYSIS{RESET}")
        timing = [
            ("Min IAT",      f"{report.inter_arrival_min:.6f}s"),
            ("Max IAT",      f"{report.inter_arrival_max:.6f}s"),
            ("Avg IAT",      f"{report.inter_arrival_avg:.6f}s"),
            ("IAT StdDev",   f"{report.inter_arrival_std:.6f}s"),
            ("Burst Periods",f"{len(report.burst_periods)}"),
            ("Idle Periods", f"{len(report.idle_periods)}"),
        ]
        for k, v in timing:
            print(f"    {CYAN}{k:<20}{RESET} {WHITE}{v}{RESET}")
        if report.beacon_suspects:
            print(f"\n    {RED}{BOLD}★ {L('c2_beaconing')}:{RESET}")
            for b in report.beacon_suspects:
                print(f"      {YELLOW}{b}{RESET}")

    if show_ics and report.ics_protocols_seen:
        _divider("·")
        print(f"\n  {BOLD}{WHITE}▶ ICS/SCADA PROTOCOLS{RESET}")
        for svc in report.ics_protocols_seen:
            print(f"    {RED}{BOLD}⚙ {svc}{RESET}")

    if show_crypto and report.crypto_traffic:
        _divider("·")
        print(f"\n  {BOLD}{WHITE}▶ CRYPTO/BLOCKCHAIN TRAFFIC{RESET}")
        for svc in report.crypto_traffic:
            print(f"    {YELLOW}₿ {svc}{RESET}")

    if show_vpn:
        _divider("·")
        print(f"\n  {BOLD}{WHITE}▶ VPN / TUNNEL{RESET}")
        if report.vpn_traffic:
            for svc in report.vpn_traffic:
                print(f"    {GREEN}🔒 {svc}{RESET}")
        else:
            print(f"    {GREY}No VPN traffic detected.{RESET}")
        if report.tunnel_suspects:
            for t in report.tunnel_suspects:
                print(f"    {YELLOW}⚡ Tunnel: {t}{RESET}")

    # --- Recommendations ---
    _divider("·")
    print(f"\n  {BOLD}{WHITE}▶ {L('section_recommendations')}{RESET}")
    for i, rec in enumerate(report.recommendations, 1):
        print(f"    {CYAN}{i}.{RESET} {rec}")

    # --- CTF Hints ---
    if report.ctf_hints:
        _divider("·")
        print(f"\n  {BOLD}{YELLOW}▶ {L('section_ctf_answer')} HINTS{RESET}")
        for hint in report.ctf_hints:
            print(f"    {YELLOW}→ {hint}{RESET}")

    print(f"\n{GREY}{'═' * TERM_WIDTH}{RESET}\n")


def _score_color(score: int) -> str:
    if score >= 80:
        return GREEN
    if score >= 60:
        return YELLOW
    if score >= 40:
        return f"{BOLD}{RED}"
    return f"{BOLD}{RED_BG}"


def is_risky_port(port: int) -> bool:
    from .ports import is_risky_port as _irp
    return _irp(port)
