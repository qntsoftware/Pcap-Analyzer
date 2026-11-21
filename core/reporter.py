"""
PCAP ANALYZER - PDF Report Generator
VCAS.PRIVATE & QNTSOFTWARE

Generates a professional branded PDF report using reportlab.
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from .parser import Packet
from .lang import L, get_lang

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether, PageBreak
    )
    REPORTLAB_AVAILABLE = True
    BRAND_DARK    = colors.HexColor("#0D0D0D")
    BRAND_ACCENT  = colors.HexColor("#00C8FF")   # cyan accent
    BRAND_RED     = colors.HexColor("#FF3B3B")
    BRAND_YELLOW  = colors.HexColor("#FFD600")
    BRAND_GREEN   = colors.HexColor("#00E676")
    BRAND_GREY    = colors.HexColor("#B0BEC5")
    BRAND_MID     = colors.HexColor("#1E1E2E")
    BRAND_TABLE   = colors.HexColor("#161625")
    WHITE         = colors.white
    BLACK         = colors.black
except ImportError:
    REPORTLAB_AVAILABLE = False
    BRAND_DARK = BRAND_ACCENT = BRAND_RED = BRAND_YELLOW = BRAND_GREEN = None
    BRAND_GREY = BRAND_MID = BRAND_TABLE = WHITE = BLACK = None


def _ensure_reportlab():
    if not REPORTLAB_AVAILABLE:
        print("\033[93m[WARN] reportlab not installed. PDF generation disabled.\033[0m")
        print("       Install with: pip install reportlab")
        return False
    return True


def _header_footer(canvas, doc):
    """Draw page header and footer."""
    canvas.saveState()
    w, h = A4

    # Header bar
    canvas.setFillColor(BRAND_MID)
    canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
    canvas.setFillColor(BRAND_ACCENT)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(1*cm, h - 0.8*cm, "PCAP ANALYZER  ×  VCAS.PRIVATE  ×  QNTSOFTWARE")
    canvas.setFillColor(BRAND_GREY)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - 1*cm, h - 0.8*cm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Footer bar
    canvas.setFillColor(BRAND_MID)
    canvas.rect(0, 0, w, 0.8*cm, fill=1, stroke=0)
    canvas.setFillColor(BRAND_GREY)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(1*cm, 0.25*cm, "CONFIDENTIAL — Network Intelligence Report")
    canvas.drawRightString(w - 1*cm, 0.25*cm, f"Page {doc.page}")

    # Accent line under header
    canvas.setStrokeColor(BRAND_ACCENT)
    canvas.setLineWidth(2)
    canvas.line(0, h - 1.2*cm, w, h - 1.2*cm)

    canvas.restoreState()


def generate_pdf(
    packets: list[Packet],
    analysis: dict,
    pcap_path: str,
    description: str,
    output_path: str = None
) -> str:
    """Generate a professional PDF report. Returns the saved file path."""

    if not _ensure_reportlab():
        return ""

    # Default output path
    if not output_path:
        base = Path(pcap_path).stem
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(Path(pcap_path).parent / f"pcap_report_{base}_{ts}.pdf")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        topMargin=1.6*cm,
        bottomMargin=1.4*cm,
        leftMargin=1.5*cm,
        rightMargin=1.5*cm
    )

    styles = getSampleStyleSheet()
    story = []

    # ── Custom Styles ──
    def S(name, **kw):
        return ParagraphStyle(name, **kw)

    title_style = S("Title",
        fontName="Helvetica-Bold", fontSize=22,
        textColor=BRAND_ACCENT, alignment=TA_CENTER, spaceAfter=4)
    subtitle_style = S("Subtitle",
        fontName="Helvetica", fontSize=11,
        textColor=BRAND_GREY, alignment=TA_CENTER, spaceAfter=2)
    section_style = S("Section",
        fontName="Helvetica-Bold", fontSize=13,
        textColor=BRAND_ACCENT, spaceBefore=14, spaceAfter=4,
        borderPad=4)
    body_style = S("Body",
        fontName="Helvetica", fontSize=9,
        textColor=colors.HexColor("#D0D0E0"), leading=14,
        alignment=TA_JUSTIFY)
    mono_style = S("Mono",
        fontName="Courier", fontSize=8,
        textColor=colors.HexColor("#C0F0C0"), leading=11,
        backColor=BRAND_TABLE)
    highlight_style = S("Highlight",
        fontName="Helvetica-Bold", fontSize=9,
        textColor=BRAND_YELLOW)
    answer_style = S("Answer",
        fontName="Helvetica-Bold", fontSize=14,
        textColor=BRAND_GREEN, alignment=TA_CENTER,
        spaceBefore=8, spaceAfter=8)

    # ─────────── COVER PAGE ───────────────────────────────────
    story.append(Spacer(1, 2*cm))

    # Logo area
    story.append(Paragraph(
        '<font color="#00C8FF" size="26"><b>PCAP ANALYZER</b></font>',
        ParagraphStyle("LogoStyle", fontName="Helvetica-Bold", fontSize=26,
                       textColor=BRAND_ACCENT, alignment=TA_CENTER)
    ))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "Network Intelligence & Security Analysis Platform",
        subtitle_style
    ))
    story.append(Paragraph(
        "VCAS.PRIVATE  ×  QNTSOFTWARE",
        S("Brand", fontName="Helvetica-Bold", fontSize=10,
          textColor=BRAND_GREY, alignment=TA_CENTER, spaceAfter=20)
    ))

    story.append(HRFlowable(width="100%", thickness=2, color=BRAND_ACCENT))
    story.append(Spacer(1, 0.5*cm))

    # Threat Level Badge
    threat = analysis.get("threat_level", "UNKNOWN")
    threat_col = {
        "LOW": "#00E676", "MEDIUM": "#FFD600",
        "HIGH": "#FF3B3B", "CRITICAL": "#FF0000", "UNKNOWN": "#90A4AE"
    }.get(threat, "#90A4AE")
    story.append(Paragraph(
        f'<font color="{threat_col}"><b>⚠ {L("section_threat_level")}: {threat}</b></font>',
        S("Threat", fontName="Helvetica-Bold", fontSize=16,
          textColor=colors.HexColor(threat_col), alignment=TA_CENTER,
          spaceAfter=10)
    ))

    story.append(Spacer(1, 0.5*cm))

    # Meta table
    meta_data = [
        ["File", os.path.basename(pcap_path)],
        ["Full Path", pcap_path],
        ["Analysis Task", description],
        [L("total_packets"), str(len(packets))],
        [f"{L('key_packet')}s", str(sum(1 for p in packets if p.is_key_packet))],
        ["Report Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Platform", "PCAP ANALYZER v3.0"],
    ]

    meta_table = Table(meta_data, colWidths=[4*cm, 13*cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), BRAND_MID),
        ("BACKGROUND", (1, 0), (1, -1), BRAND_TABLE),
        ("TEXTCOLOR", (0, 0), (0, -1), BRAND_ACCENT),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#D0D0E0")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [BRAND_MID, BRAND_TABLE]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#303050")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)

    story.append(PageBreak())

    # ─────────── EXECUTIVE SUMMARY ────────────────────────────
    story.append(Paragraph(L("section_executive_summary"), section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ACCENT))
    story.append(Spacer(1, 0.3*cm))
    exec_summary = analysis.get("executive_summary", "No summary available.")
    story.append(Paragraph(exec_summary, body_style))

    # CTF Answer (if any)
    ctf = analysis.get("ctf_answer", "N/A")
    if ctf and ctf != "N/A":
        story.append(Spacer(1, 0.4*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_YELLOW))
        story.append(Paragraph(f"★  {L('section_ctf_answer')}", section_style))
        story.append(Paragraph(ctf, answer_style))
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_YELLOW))

    story.append(Spacer(1, 0.5*cm))

    # ─────────── PACKET TABLE ─────────────────────────────────
    story.append(Paragraph(L("section_packet_list"), section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ACCENT))
    story.append(Spacer(1, 0.3*cm))

    tbl_header = ["#", "Time(s)", "Source", "Destination", "Proto", "Len", "Summary"]
    tbl_rows = [tbl_header]
    tbl_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), BRAND_DARK),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#303050")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BRAND_TABLE, BRAND_MID]),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#D0D0E0")),
    ]

    for i, p in enumerate(packets, 1):
        summary = (p.raw_summary or "")[:80]
        row = [
            str(p.index),
            str(p.timestamp)[:8],
            (p.src or "")[:18],
            (p.dst or "")[:18],
            p.protocol,
            str(p.length),
            summary
        ]
        tbl_rows.append(row)
        if p.is_key_packet:
            row_idx = i  # 0 is header
            tbl_styles.append(("BACKGROUND", (0, row_idx), (-1, row_idx), BRAND_RED))
            tbl_styles.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), WHITE))
            tbl_styles.append(("FONTNAME", (0, row_idx), (-1, row_idx), "Helvetica-Bold"))

    pkt_table = Table(
        tbl_rows,
        colWidths=[1*cm, 1.5*cm, 3*cm, 3*cm, 1.5*cm, 1.2*cm, 7.3*cm],
        repeatRows=1
    )
    pkt_table.setStyle(TableStyle(tbl_styles))
    story.append(pkt_table)
    story.append(Spacer(1, 0.5*cm))

    # ─────────── DETAILED ANALYSIS ────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph(L("section_detailed_analysis"), section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ACCENT))
    story.append(Spacer(1, 0.3*cm))

    detail = analysis.get("detailed_analysis", "No detailed analysis available.")
    for para in detail.split("\n\n"):
        if para.strip():
            story.append(Paragraph(para.strip(), body_style))
            story.append(Spacer(1, 0.2*cm))

    # ─────────── KEY FINDINGS ─────────────────────────────────
    highlights = analysis.get("highlights", [])
    if highlights:
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph(L("section_key_findings"), section_style))
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_YELLOW))
        story.append(Spacer(1, 0.3*cm))

        for h in highlights:
            pkt_i = h.get("packet_index", "?")
            field = h.get("field", "")
            reason = h.get("reason", "")
            story.append(Paragraph(
                f'<font color="#FFD600"><b>● Packet #{pkt_i}:</b></font>  '
                f'<font color="#FFD600">{field}</font>  '
                f'<font color="#B0BEC5">— {reason}</font>',
                S("FindStyle", fontName="Helvetica", fontSize=9,
                  textColor=BRAND_YELLOW, leading=14, spaceAfter=4)
            ))

    # ─────────── SECURITY RECOMMENDATIONS ─────────────────────
    recs = analysis.get("security_recommendations", [])
    if recs:
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph(L("section_recommendations"), section_style))
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_GREEN))
        story.append(Spacer(1, 0.3*cm))

        for i, rec in enumerate(recs, 1):
            story.append(Paragraph(
                f'<font color="#00C8FF"><b>{i}.</b></font>  {rec}',
                S("RecStyle", fontName="Helvetica", fontSize=9,
                  textColor=colors.HexColor("#D0D0E0"), leading=14, spaceAfter=4)
            ))

    # Build PDF
    try:
        doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
        return output_path
    except Exception as e:
        print(f"\033[91m[ERROR] PDF generation failed: {e}\033[0m")
        return ""


# ═══════════════════════════════════════════════════════════════
#  No-AI PDF Generator
# ═══════════════════════════════════════════════════════════════

def generate_noai_pdf(packets, report, pcap_path: str,
                      description: str, output_path: str = None) -> str:
    """Generate a full professional PDF for the No-AI analysis report."""
    if not _ensure_reportlab():
        return ""

    if not output_path:
        base = Path(pcap_path).stem
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(Path(pcap_path).parent / f"pcap_noai_{base}_{ts}.pdf")

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=1.6*cm, bottomMargin=1.4*cm,
        leftMargin=1.5*cm, rightMargin=1.5*cm
    )
    styles = getSampleStyleSheet()
    story  = []

    def S(name, **kw):
        return ParagraphStyle(name, **kw)

    title_style   = S("T",  fontName="Helvetica-Bold", fontSize=22, textColor=BRAND_ACCENT, alignment=TA_CENTER, spaceAfter=4)
    section_style = S("S",  fontName="Helvetica-Bold", fontSize=13, textColor=BRAND_ACCENT, spaceBefore=12, spaceAfter=4)
    body_style    = S("B",  fontName="Helvetica", fontSize=9,  textColor=colors.HexColor("#D0D0E0"), leading=14, alignment=TA_JUSTIFY)
    kv_key        = S("KK", fontName="Helvetica-Bold", fontSize=9, textColor=BRAND_ACCENT)
    kv_val        = S("KV", fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#D0D0E0"))

    sev_colors = {
        "CRITICAL": colors.HexColor("#FF0000"),
        "HIGH":     colors.HexColor("#FF3B3B"),
        "MEDIUM":   colors.HexColor("#FFD600"),
        "LOW":      colors.HexColor("#00C8FF"),
        "INFO":     colors.HexColor("#90A4AE"),
    }

    # ── COVER ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph('<font color="#00C8FF" size="26"><b>PCAP ANALYZER</b></font>', title_style))
    story.append(Paragraph("No-AI Network Intelligence Report", S("Sub", fontName="Helvetica", fontSize=11, textColor=BRAND_GREY, alignment=TA_CENTER, spaceAfter=2)))
    story.append(Paragraph("VCAS.PRIVATE  ×  QNTSOFTWARE", S("Br", fontName="Helvetica-Bold", fontSize=10, textColor=BRAND_GREY, alignment=TA_CENTER, spaceAfter=20)))
    story.append(HRFlowable(width="100%", thickness=2, color=BRAND_ACCENT))
    story.append(Spacer(1, 0.3*cm))

    threat_col = {"LOW":"#00E676","MEDIUM":"#FFD600","HIGH":"#FF3B3B","CRITICAL":"#FF0000"}.get(report.threat_level,"#90A4AE")
    story.append(Paragraph(
        f'<font color="{threat_col}"><b>⚠ THREAT LEVEL: {report.threat_level}  |  SECURITY SCORE: {report.security_score}/100</b></font>',
        S("TH", fontName="Helvetica-Bold", fontSize=14, textColor=colors.HexColor(threat_col), alignment=TA_CENTER, spaceAfter=10)
    ))
    story.append(Spacer(1, 0.4*cm))

    meta_data = [
        ["File",          os.path.basename(pcap_path)],
        ["Full Path",     pcap_path],
        ["Description",   description or "General Analysis"],
        ["Total Packets", f"{report.total_packets:,}"],
        ["Total Bytes",   f"{report.total_bytes:,}"],
        ["Duration",      f"{report.duration_sec:.3f}s"],
        ["Pkt/sec",       f"{report.packets_per_second:.1f}"],
        ["Unique Src IP", str(len(report.unique_src_ips))],
        ["Unique Dst IP", str(len(report.unique_dst_ips))],
        ["Findings",      str(len(report.findings))],
        ["Report Date",   datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Mode",          "No-AI — 100% Local Analysis"],
    ]
    mt = Table(meta_data, colWidths=[4*cm, 13*cm])
    mt.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(0,-1), BRAND_MID),
        ("BACKGROUND",  (1,0),(1,-1), BRAND_TABLE),
        ("TEXTCOLOR",   (0,0),(0,-1), BRAND_ACCENT),
        ("TEXTCOLOR",   (1,0),(1,-1), colors.HexColor("#D0D0E0")),
        ("FONTNAME",    (0,0),(0,-1), "Helvetica-Bold"),
        ("FONTNAME",    (1,0),(1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0),(-1,-1), 9),
        ("GRID",        (0,0),(-1,-1), 0.5, colors.HexColor("#303050")),
        ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0),(-1,-1), 8),
        ("TOPPADDING",  (0,0),(-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
    ]))
    story.append(mt)
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ────────────────────────────────────────────────────
    story.append(Paragraph("EXECUTIVE SUMMARY", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ACCENT))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(report.executive_summary, body_style))
    story.append(Spacer(1, 0.4*cm))

    # ── PROTOCOL DISTRIBUTION ───────────────────────────────────────────────
    story.append(Paragraph("PROTOCOL DISTRIBUTION", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ACCENT))
    story.append(Spacer(1, 0.3*cm))
    if report.protocol_counts:
        pd_data = [["Protocol", "Packets", "Bytes"]]
        for proto, cnt in list(report.protocol_counts.items())[:20]:
            byt = report.protocol_bytes.get(proto, 0)
            pd_data.append([proto, str(cnt), f"{byt:,}"])
        pd_tbl = Table(pd_data, colWidths=[5*cm, 5*cm, 7.5*cm])
        pd_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,0), BRAND_ACCENT),
            ("TEXTCOLOR",  (0,0),(-1,0), BRAND_DARK),
            ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0),(-1,-1), 8),
            ("GRID",       (0,0),(-1,-1), 0.3, colors.HexColor("#303050")),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [BRAND_TABLE, BRAND_MID]),
            ("TEXTCOLOR",  (0,1),(-1,-1), colors.HexColor("#D0D0E0")),
            ("LEFTPADDING",(0,0),(-1,-1), 6),
            ("TOPPADDING", (0,0),(-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
        ]))
        story.append(pd_tbl)

    story.append(PageBreak())

    # ── PACKET TABLE ────────────────────────────────────────────────────────
    story.append(Paragraph("PACKET ANALYSIS TABLE", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ACCENT))
    story.append(Spacer(1, 0.3*cm))

    tbl_hdr  = ["#", "Time(s)", "Source", "Destination", "Proto", "Service", "Port", "Len", "TTL", "Summary"]
    tbl_rows = [tbl_hdr]
    tbl_styl = [
        ("BACKGROUND", (0,0),(-1,0), BRAND_ACCENT),
        ("TEXTCOLOR",  (0,0),(-1,0), BRAND_DARK),
        ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0),(-1,-1), 6),
        ("GRID",       (0,0),(-1,-1), 0.3, colors.HexColor("#303050")),
        ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
        ("LEFTPADDING",(0,0),(-1,-1), 3),
        ("TOPPADDING", (0,0),(-1,-1), 2),
        ("BOTTOMPADDING",(0,0),(-1,-1), 2),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [BRAND_TABLE, BRAND_MID]),
        ("TEXTCOLOR",  (0,1),(-1,-1), colors.HexColor("#D0D0E0")),
    ]
    for i, p in enumerate(packets, 1):
        row = [
            str(p.index),
            str(p.timestamp)[:8],
            (p.src or "")[:16],
            (p.dst or "")[:16],
            p.protocol,
            (p.service or "")[:12],
            str(p.dst_port) if p.dst_port else "",
            str(p.length),
            str(p.ttl) if p.ttl else "",
            (p.raw_summary or "")[:60],
        ]
        tbl_rows.append(row)
        if p.is_key_packet:
            tbl_styl += [
                ("BACKGROUND", (0,i),(-1,i), BRAND_RED),
                ("TEXTCOLOR",  (0,i),(-1,i), WHITE),
                ("FONTNAME",   (0,i),(-1,i), "Helvetica-Bold"),
            ]
        elif p.is_risky:
            tbl_styl.append(("TEXTCOLOR", (0,i),(-1,i), colors.HexColor("#FFD600")))

    pkt_tbl = Table(tbl_rows,
        colWidths=[0.8*cm,1.5*cm,2.8*cm,2.8*cm,1.4*cm,1.8*cm,1.1*cm,1.1*cm,0.8*cm,5.4*cm],
        repeatRows=1)
    pkt_tbl.setStyle(TableStyle(tbl_styl))
    story.append(pkt_tbl)
    story.append(PageBreak())

    # ── SECURITY FINDINGS ───────────────────────────────────────────────────
    if report.findings:
        story.append(Paragraph("SECURITY FINDINGS", section_style))
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_RED))
        story.append(Spacer(1, 0.3*cm))

        for f in sorted(report.findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity)):
            sc = sev_colors.get(f.severity, BRAND_GREY)
            story.append(Paragraph(
                f'<font color="#{hex(sc.hexval())[2:].upper()}"><b>[{f.severity}]  {f.category} — {f.title}</b></font>',
                S("FH", fontName="Helvetica-Bold", fontSize=10,
                  textColor=sc, spaceBefore=6, spaceAfter=2)
            ))
            story.append(Paragraph(f.description, body_style))
            if f.evidence:
                story.append(Paragraph(f"Evidence: {f.evidence[:100]}", S("EV", fontName="Courier", fontSize=7, textColor=BRAND_GREY, spaceAfter=4)))
            if f.packets:
                story.append(Paragraph(f"Related packets: {f.packets[:8]}", S("RP", fontName="Helvetica", fontSize=7, textColor=BRAND_GREY, spaceAfter=6)))

    # ── RECOMMENDATIONS ─────────────────────────────────────────────────────
    if report.recommendations:
        story.append(PageBreak())
        story.append(Paragraph("SECURITY RECOMMENDATIONS", section_style))
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_GREEN))
        story.append(Spacer(1, 0.3*cm))
        for i, rec in enumerate(report.recommendations, 1):
            story.append(Paragraph(
                f'<font color="#00C8FF"><b>{i}.</b></font>  {rec}',
                S("REC", fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#D0D0E0"), leading=14, spaceAfter=4)
            ))

    # ── TOP TALKERS ─────────────────────────────────────────────────────────
    if report.top_talkers:
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph("TOP TALKERS", section_style))
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ACCENT))
        story.append(Spacer(1, 0.2*cm))
        tt_data = [["IP Address", "Packets"]] + [[ip, str(cnt)] for ip, cnt in report.top_talkers[:15]]
        tt_tbl  = Table(tt_data, colWidths=[10*cm, 7.5*cm])
        tt_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,0), BRAND_ACCENT),
            ("TEXTCOLOR",  (0,0),(-1,0), BRAND_DARK),
            ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0),(-1,-1), 9),
            ("GRID",       (0,0),(-1,-1), 0.3, colors.HexColor("#303050")),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [BRAND_TABLE, BRAND_MID]),
            ("TEXTCOLOR",  (0,1),(-1,-1), colors.HexColor("#D0D0E0")),
            ("LEFTPADDING",(0,0),(-1,-1), 6),
            ("TOPPADDING", (0,0),(-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
        ]))
        story.append(tt_tbl)

    try:
        doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
        return output_path
    except Exception as e:
        print(f"\033[91m[ERROR] No-AI PDF generation failed: {e}\033[0m")
        return ""
