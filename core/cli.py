"""
PCAP ANALYZER - Production CLI Engine
VCAS.PRIVATE × QNTSOFTWARE
"""

from __future__ import annotations
import sys
import os
import argparse
import textwrap
import json
import dataclasses

from .config    import set_api_key, get_api_key, set_local_ai, get_local_ai
from .parser    import parse_pcap
from .analyzer  import analyze_with_gemini, analyze_with_localai, merge_ai_results
from .noai      import analyze_noai, NoAIReport, _is_private
from .ports     import get_category
from .lang      import set_lang, get_lang, L, list_languages
from .renderer  import (
    render_banner, render_packet_list, render_analysis,
    render_noai_report, render_config_saved, render_error,
    render_info, render_pdf_saved
)
from .reporter  import generate_pdf, generate_noai_pdf


def _run_analysis(
    pcap_path: str,
    description: str,
    wireshark_filter: str,
    api_key: str = None,
    local_ai_model: str = None,
    no_pdf: bool = False,
    pdf_output: str = None,
):
    render_banner()

    if not os.path.isfile(pcap_path):
        render_error(L("file_not_found", path=pcap_path))
        sys.exit(1)

    render_info(L("loading_pcap", path=pcap_path))
    if wireshark_filter:
        render_info(L("applying_filter", f=wireshark_filter))

    packets = parse_pcap(pcap_path, wireshark_filter)
    if not packets:
        render_error(L("no_packets"))
        sys.exit(1)
    render_info(L("packets_loaded", n=len(packets)))

    if local_ai_model:
        analysis = analyze_with_localai(packets, description, local_ai_model)
    elif api_key:
        analysis = analyze_with_gemini(packets, description, api_key)
    else:
        render_error(
            "AI backend not configured.\n"
            "  Gemini API key : pcapanalyzer -api YOUR_KEY\n"
            "  Local AI       : pcapmg -localai MODEL_NAME ...\n"
            "  No-AI Mode     : pcapanalyzer ... --no-ai"
        )
        sys.exit(1)

    packets = merge_ai_results(packets, analysis)
    render_packet_list(packets, analysis)
    render_analysis(analysis)

    if not no_pdf:
        pdf_path = generate_pdf(packets, analysis, pcap_path, description, pdf_output)
        if pdf_path:
            render_pdf_saved(pdf_path)


def _run_noai(
    pcap_path: str,
    description: str,
    wireshark_filter: str,
    no_pdf: bool = False,
    pdf_output: str = None,
    show_only_risky: bool = False,
    show_only_malware: bool = False,
    show_only_external: bool = False,
    min_packet_size: int = 0,
    max_packet_size: int = 0,
    proto_filter: str = "",
    src_ip_filter: str = "",
    dst_ip_filter: str = "",
    port_filter: int = 0,
    min_ttl: int = 0,
    max_ttl: int = 0,
    top_n: int = 0,
    show_conversations: bool = False,
    show_dns: bool = False,
    show_ports: bool = False,
    show_hosts: bool = False,
    show_timing: bool = False,
    show_geo: bool = False,
    show_ics: bool = False,
    show_crypto: bool = False,
    show_vpn: bool = False,
    compact: bool = False,
    json_out: bool = False,
    json_path: str = "",
):
    render_banner()

    if not os.path.isfile(pcap_path):
        render_error(L("file_not_found", path=pcap_path))
        sys.exit(1)

    render_info(L("loading_pcap", path=pcap_path))
    if wireshark_filter:
        render_info(L("applying_filter", f=wireshark_filter))

    packets = parse_pcap(pcap_path, wireshark_filter)
    if not packets:
        render_error(L("no_packets"))
        sys.exit(1)

    filtered = packets[:]
    if show_only_risky:
        filtered = [p for p in filtered if p.is_risky]
    if show_only_malware:
        filtered = [p for p in filtered if get_category(p.dst_port) in ("MALWARE", "C2")
                    or get_category(p.src_port) in ("MALWARE", "C2")]
    if show_only_external:
        filtered = [p for p in filtered if p.dst and not _is_private(p.dst)]
    if min_packet_size:
        filtered = [p for p in filtered if p.length >= min_packet_size]
    if max_packet_size:
        filtered = [p for p in filtered if p.length <= max_packet_size]
    if proto_filter:
        pf = proto_filter.upper()
        filtered = [p for p in filtered if pf in p.protocol.upper() or pf in p.service.upper()]
    if src_ip_filter:
        filtered = [p for p in filtered if src_ip_filter in (p.src or "")]
    if dst_ip_filter:
        filtered = [p for p in filtered if dst_ip_filter in (p.dst or "")]
    if port_filter:
        filtered = [p for p in filtered if p.dst_port == port_filter or p.src_port == port_filter]
    if min_ttl:
        filtered = [p for p in filtered if p.ttl >= min_ttl]
    if max_ttl:
        filtered = [p for p in filtered if p.ttl <= max_ttl]
    if top_n:
        filtered = filtered[:top_n]

    render_info(f"{len(packets)} packets loaded -> {len(filtered)} displayed.")

    report: NoAIReport = analyze_noai(filtered, description)

    render_noai_report(
        filtered, report,
        show_conversations=show_conversations,
        show_dns=show_dns,
        show_ports=show_ports,
        show_hosts=show_hosts,
        show_timing=show_timing,
        show_ics=show_ics,
        show_crypto=show_crypto,
        show_vpn=show_vpn,
        compact=compact,
    )

    if json_out or json_path:
        def _serial(obj):
            if dataclasses.is_dataclass(obj):
                return dataclasses.asdict(obj)
            return str(obj)
        out = json.dumps(dataclasses.asdict(report), default=_serial, indent=2, ensure_ascii=False)
        path = json_path or pcap_path.replace(".pcapng", "_noai.json").replace(".pcap", "_noai.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
        render_info(f"JSON output: {path}")

    if not no_pdf:
        pdf_path = generate_noai_pdf(filtered, report, pcap_path, description, pdf_output)
        if pdf_path:
            render_pdf_saved(pdf_path)


def _base_parser(prog: str, epilog_extra: str = "") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(f"""
        ╔══════════════════════════════════════════════════════════════════════╗
        ║   PCAP ANALYZER — Network Intelligence & Security Audit Platform     ║
        ║   VCAS.PRIVATE × QNTSOFTWARE                                         ║
        ╚══════════════════════════════════════════════════════════════════════╝
        """),
        epilog=textwrap.dedent(epilog_extra)
    )

    core_grp = p.add_argument_group("CORE PARAMETERS")
    core_grp.add_argument("-path", "--path", metavar="<file>", help="Path to .pcap or .pcapng file")
    core_grp.add_argument("-f", "--filter", metavar="<filter>", help="Wireshark display filter (e.g. 'http', 'ssl', 'dns', 'tcp.port==443')")
    core_grp.add_argument("-des", "--description", metavar="<desc>", help="Task description for AI (e.g. 'Solve CTF challenge', 'Audit intrusion')")
    core_grp.add_argument("-lang", "--lang", metavar="<code|help>", default=None,
                          help="Language code: eng, tr, de, ru, fr, es, ar, zh, ja, it, pt, ko, nl, pl, sv (or 'help')")
    core_grp.add_argument("-o", "--output", metavar="<pdf_path>", help="Custom path for generated PDF report")
    core_grp.add_argument("--no-pdf", action="store_true", help="Disable automatic PDF report generation")

    noai_grp = p.add_argument_group("OFFLINE NO-AI ANALYSIS ENGINE")
    noai_grp.add_argument("--no-ai", action="store_true", help="Execute 100+ parameter deep heuristic analysis without calling AI")

    flt_grp = p.add_argument_group("PACKET FILTERING (NO-AI)")
    flt_grp.add_argument("--only-risky", action="store_true", help="Display only packets associated with risky ports")
    flt_grp.add_argument("--only-malware", action="store_true", help="Display only packets on known malware / C2 ports")
    flt_grp.add_argument("--only-external", action="store_true", help="Filter traffic destined to non-private public IP addresses")
    flt_grp.add_argument("--proto", metavar="<proto>", help="Protocol filter (e.g. HTTP, TLS, DNS, SMB, SSH, ICMP)")
    flt_grp.add_argument("--src-ip", metavar="<ip>", help="Filter by source IP address")
    flt_grp.add_argument("--dst-ip", metavar="<ip>", help="Filter by destination IP address")
    flt_grp.add_argument("--port", type=int, default=0, metavar="<port>", help="Filter by source or destination port (0-65535)")
    flt_grp.add_argument("--min-size", type=int, default=0, metavar="<bytes>", help="Minimum packet size threshold")
    flt_grp.add_argument("--max-size", type=int, default=0, metavar="<bytes>", help="Maximum packet size threshold")
    flt_grp.add_argument("--min-ttl", type=int, default=0, metavar="<ttl>", help="Minimum TTL threshold")
    flt_grp.add_argument("--max-ttl", type=int, default=0, metavar="<ttl>", help="Maximum TTL threshold")
    flt_grp.add_argument("--top", type=int, default=0, metavar="<n>", help="Limit output to first N packets")

    out_grp = p.add_argument_group("DISPLAY & EXPORT OPTIONS (NO-AI)")
    out_grp.add_argument("--convs", action="store_true", help="Display top TCP conversation endpoints")
    out_grp.add_argument("--dns", action="store_true", help="Display DNS queries and tunnel detection analysis")
    out_grp.add_argument("--ports", action="store_true", help="Display full 65,535 port usage and service breakdown")
    out_grp.add_argument("--hosts", action="store_true", help="Display Top Talkers and Top Destinations")
    out_grp.add_argument("--timing", action="store_true", help="Display inter-arrival time and C2 beaconing analysis")
    out_grp.add_argument("--ics", action="store_true", help="Display ICS / SCADA industrial protocol activity")
    out_grp.add_argument("--crypto", action="store_true", help="Display cryptocurrency and blockchain network activity")
    out_grp.add_argument("--vpn", action="store_true", help="Display VPN and tunneling protocols (IPSec, OpenVPN, WireGuard)")
    out_grp.add_argument("--compact", action="store_true", help="Render concise single-line packet output")
    out_grp.add_argument("--json", action="store_true", help="Export structured report to JSON file")
    out_grp.add_argument("--json-path", metavar="<file>", help="Custom path for exported JSON file")

    return p


def pcapanalyzer_main():
    p = _base_parser("pcapanalyzer", epilog_extra="""
PARAMETER COMBINATIONS & EXAMPLES:

  [1] Set Gemini API Key (Saved to ~/.pcapanalyzer/config.json):
      pcapanalyzer -api AIzaSy...

  [2] AI CTF Solving with Language Selection:
      pcapanalyzer -path ctf.pcap -des "Find the flag in SSL/HTTP exchange" -lang eng
      pcapanalyzer -path ctf.pcap -des "Root-Me SSL HTTP exchange CTF flag bul" -lang tr
      pcapanalyzer -path ctf.pcap -des "Finde Flaggen und Anmeldedaten" -lang de
      pcapanalyzer -path ctf.pcap -des "Найти пароли и флаг в трафике" -lang ru

  [3] Wireshark Filter + AI Analysis + Custom PDF:
      pcapanalyzer -path capture.pcap -f "http or ftp" -des "Extract cleartext passwords" -o report.pdf -lang tr

  [4] Full 100+ Parameter Offline Heuristic Analysis (No AI required):
      pcapanalyzer -path capture.pcap --no-ai -lang tr

  [5] Malware & Security Triage (No-AI):
      pcapanalyzer -path traffic.pcap --no-ai --only-malware --ports --timing --json

  [6] Enterprise Incident Response & Data Exfiltration Triage (No-AI):
      pcapanalyzer -path corp.pcap --no-ai --only-external --min-size 1200 --hosts --dns --json -lang eng

  [7] SCADA / ICS Industrial Protocol Audit:
      pcapanalyzer -path scada.pcap --no-ai --ics --ports --hosts -lang tr

  [8] Protocol Specific Extraction:
      pcapanalyzer -path net.pcap --no-ai --proto DNS --dns --top 100 --compact -lang eng
    """)

    p.add_argument("-api", "--api", metavar="<key>", help="Configure and save Google Gemini API Key")
    args = p.parse_args()

    if args.lang:
        if args.lang.lower() in ("help", "list"):
            print(list_languages())
            sys.exit(0)
        set_lang(args.lang)

    if args.api:
        render_banner()
        set_api_key(args.api)
        render_config_saved(args.api)
        return

    if not args.path:
        p.print_help()
        sys.exit(0)

    if args.no_ai:
        _run_noai(
            pcap_path=args.path,
            description=args.description or "General network traffic audit",
            wireshark_filter=args.filter or "",
            no_pdf=args.no_pdf,
            pdf_output=args.output,
            show_only_risky=args.only_risky,
            show_only_malware=args.only_malware,
            show_only_external=args.only_external,
            min_packet_size=args.min_size,
            max_packet_size=args.max_size,
            proto_filter=args.proto or "",
            src_ip_filter=args.src_ip or "",
            dst_ip_filter=args.dst_ip or "",
            port_filter=args.port,
            min_ttl=args.min_ttl,
            max_ttl=args.max_ttl,
            top_n=args.top,
            show_conversations=args.convs,
            show_dns=args.dns,
            show_ports=args.ports,
            show_hosts=args.hosts,
            show_timing=args.timing,
            show_ics=args.ics,
            show_crypto=args.crypto,
            show_vpn=args.vpn,
            compact=args.compact,
            json_out=args.json,
            json_path=args.json_path or "",
        )
        return

    if not args.description:
        render_error("AI mode requires -des '<description>'. To run without AI, add --no-ai")
        sys.exit(1)

    api_key = get_api_key()
    if not api_key:
        render_error(
            "Gemini API key not found. Run: pcapanalyzer -api YOUR_KEY\n"
            "Or run 100% offline without API: pcapanalyzer ... --no-ai\n"
            "Or use local AI models:         pcapmg -localai llama3 ..."
        )
        sys.exit(1)

    _run_analysis(
        pcap_path=args.path,
        description=args.description,
        wireshark_filter=args.filter or "",
        api_key=api_key,
        no_pdf=args.no_pdf,
        pdf_output=args.output,
    )


def pcapmg_main():
    p = _base_parser("pcapmg", epilog_extra="""
PARAMETER COMBINATIONS & EXAMPLES:

  [1] Local AI Analysis (Ollama - Llama 3):
      pcapmg -localai llama3 -path capture.pcap -des "Audit network for intrusion" -lang eng

  [2] Local AI with Wireshark Filter + Multilingual Output:
      pcapmg -localai mistral -path capture.pcap -f "dns" -des "DNS exfiltration check" -lang tr
      pcapmg -localai codellama -path ctf.pcap -des "Finde die Flagge in den HTTP-Daten" -lang de

  [3] Offline Analysis without AI (--no-ai):
      pcapmg --no-ai -path capture.pcap --only-malware --ports --hosts --json

  [4] Targeted Port Investigation:
      pcapmg --no-ai -path capture.pcap --port 4444 --convs -lang tr
    """)

    p.add_argument("-localai", "--localai", metavar="<model>",
                   help="Local AI model name from Ollama (e.g. llama3, mistral, gemma2, qwen2.5)")
    args = p.parse_args()

    if args.lang:
        if args.lang.lower() in ("help", "list"):
            print(list_languages())
            sys.exit(0)
        set_lang(args.lang)

    if not args.path:
        p.print_help()
        sys.exit(0)

    if args.no_ai:
        _run_noai(
            pcap_path=args.path,
            description=args.description or "General network traffic audit",
            wireshark_filter=args.filter or "",
            no_pdf=args.no_pdf,
            pdf_output=args.output,
            show_only_risky=args.only_risky,
            show_only_malware=args.only_malware,
            show_only_external=args.only_external,
            min_packet_size=args.min_size,
            max_packet_size=args.max_size,
            proto_filter=args.proto or "",
            src_ip_filter=args.src_ip or "",
            dst_ip_filter=args.dst_ip or "",
            port_filter=args.port,
            min_ttl=args.min_ttl,
            max_ttl=args.max_ttl,
            top_n=args.top,
            show_conversations=args.convs,
            show_dns=args.dns,
            show_ports=args.ports,
            show_hosts=args.hosts,
            show_timing=args.timing,
            show_ics=args.ics,
            show_crypto=args.crypto,
            show_vpn=args.vpn,
            compact=args.compact,
            json_out=args.json,
            json_path=args.json_path or "",
        )
        return

    if not args.localai:
        render_error("Missing parameter: -localai <model_name>. Or run offline without AI: --no-ai")
        sys.exit(1)

    if not args.description:
        render_error("Missing parameter: -des '<task_description>'")
        sys.exit(1)

    _run_analysis(
        pcap_path=args.path,
        description=args.description,
        wireshark_filter=args.filter or "",
        local_ai_model=args.localai,
        no_pdf=args.no_pdf,
        pdf_output=args.output,
    )
