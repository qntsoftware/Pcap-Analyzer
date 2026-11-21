"""
PCAP ANALYZER — pcapbib
VCAS.PRIVATE × QNTSOFTWARE

pcapbib: Universal Binary/File Intelligence Tool
PCAP dosyalarının ÖTESİNDE her şeyi analiz eder:

  • Wireshark hex dump dosyaları
  • Raw binary dosyalar
  • ASCII/metin içerikli ağ verileri
  • Cisco/router config dosyaları
  • SIP/VoIP kayıt dosyaları
  • Network log dosyaları
  • Base64/hex encoded veriler
  • Şifreli parola hash'leri
  • Steganografik içerik tespiti
  • File carving (binary içinde gömülü dosyalar)

20 özgün parametre ile çalışır.
"""

import os
import sys
import re
import json
import math
import struct
import base64
import binascii
import hashlib
import argparse
import textwrap
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional
from .lang import set_lang, get_lang, L, list_languages, get_ai_language_instruction


# ─── Veri Yapıları ──────────────────────────────────────────────────────────

@dataclass
class BibFinding:
    category:    str    # HEX / ASCII / CREDENTIAL / HASH / BINARY / CIPHER / STEG / CONFIG
    severity:    str    # INFO / LOW / MEDIUM / HIGH / CRITICAL
    title:       str
    value:       str
    decoded:     str    = ""
    line_number: int    = 0
    offset:      int    = 0
    confidence:  float  = 1.0


@dataclass
class BibReport:
    file_path:    str
    file_type:    str    = "UNKNOWN"
    file_size:    int    = 0
    file_hash_md5:  str  = ""
    file_hash_sha1: str  = ""
    file_hash_sha256: str = ""
    entropy:      float  = 0.0
    is_binary:    bool   = False
    magic_bytes:  str    = ""
    detected_protocols: list = field(default_factory=list)
    findings:     list[BibFinding] = field(default_factory=list)
    hex_blocks:   list   = field(default_factory=list)
    ascii_strings: list  = field(default_factory=list)
    credentials:  list   = field(default_factory=list)
    hashes:       list   = field(default_factory=list)
    decoded_data: list   = field(default_factory=list)
    embedded_files: list = field(default_factory=list)
    network_iocs: list   = field(default_factory=list)   # IP, domain, URL
    cipher_texts: list   = field(default_factory=list)
    executive_summary: str = ""
    ai_analysis:  str    = ""


# ─── Magic Bytes Veritabanı ──────────────────────────────────────────────────

MAGIC_DB = [
    (b"\xff\xd8\xff",           "JPEG image"),
    (b"\x89PNG\r\n\x1a\n",     "PNG image"),
    (b"%PDF",                   "PDF document"),
    (b"MZ",                     "Windows PE executable"),
    (b"\x7fELF",                "Linux ELF executable"),
    (b"PK\x03\x04",            "ZIP archive (or JAR/DOCX/XLSX)"),
    (b"Rar!\x1a\x07",          "RAR archive"),
    (b"\x1f\x8b\x08",          "GZIP compressed"),
    (b"BZh",                    "BZIP2 compressed"),
    (b"7z\xbc\xaf'\"",         "7-ZIP archive"),
    (b"\xd0\xcf\x11\xe0",      "MS Office (DOC/XLS/PPT)"),
    (b"OggS",                   "OGG media"),
    (b"ID3",                    "MP3 audio (ID3)"),
    (b"\xff\xfb",               "MP3 audio"),
    (b"RIFF",                   "RIFF (WAV/AVI)"),
    (b"\x00\x00\x00\x20ftyp",  "MP4/MOV video"),
    (b"SQLite format",          "SQLite database"),
    (b"-----BEGIN",             "PEM certificate/key"),
    (b"<?xml",                  "XML document"),
    (b"<!DOCTYPE",              "HTML document"),
    (b"{\n",                    "JSON data (likely)"),
    (b"[0x",                    "Hex dump"),
    (b"0x0000",                 "Wireshark hex dump"),
    (b">>> INGRESS",            "Network ingress/egress dump"),
    (b"version ",               "Config file (possible)"),
    (b"hostname ",              "Cisco/network config"),
]

# ─── Cisco Type 7 Decoder ───────────────────────────────────────────────────

CISCO7_XOR = "dsfd;kfoA,.isdfjkv"

def decode_cisco_type7(ciphertext: str) -> str:
    try:
        ciphertext = ciphertext.strip()
        seed = int(ciphertext[:2])
        cipher = ciphertext[2:]
        result = []
        for i in range(0, len(cipher), 2):
            byte = int(cipher[i:i+2], 16)
            xor  = ord(CISCO7_XOR[(seed + i // 2) % len(CISCO7_XOR)])
            result.append(chr(byte ^ xor))
        return "".join(result)
    except Exception:
        return "[decode failed]"


# ─── Entropi Hesaplama ───────────────────────────────────────────────────────

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


# ─── Ana Analiz Sınıfı ──────────────────────────────────────────────────────

class BibAnalyzer:
    def __init__(self, file_path: str):
        self.path   = Path(file_path)
        self.report = BibReport(file_path=file_path)

    def run(self,
            # Analiz parametreleri
            decode_hex:      bool = True,
            decode_base64:   bool = True,
            decode_ascii:    bool = True,
            find_creds:      bool = True,
            find_hashes:     bool = True,
            find_iocs:       bool = True,
            crack_cisco7:    bool = True,
            file_carve:      bool = True,
            find_strings:    bool = True,
            min_string_len:  int  = 4,
            check_steg:      bool = False,  # computationally heavier
            show_entropy:    bool = True,
            compute_hashes:  bool = True,
            # Özel arama
            search_pattern:  str  = "",
            search_hex:      str  = "",
            find_flags:      bool = True,
            flag_formats:    list = None,
            # Çıktı
            max_strings:     int  = 200,
            context_lines:   int  = 2,
            ) -> BibReport:

        r = self.report

        if not self.path.exists():
            r.executive_summary = f"Dosya bulunamadı: {self.path}"
            return r

        # ── 1. Temel bilgiler ──────────────────────────────────
        r.file_size = self.path.stat().st_size

        raw = self.path.read_bytes()
        try:
            text = raw.decode("utf-8", errors="replace")
            r.is_binary = False
        except Exception:
            text = raw.decode("latin-1", errors="replace")
            r.is_binary = True

        lines = text.splitlines()

        # ── 2. Magic bytes tespiti ─────────────────────────────
        r.magic_bytes = raw[:8].hex() if raw else ""
        for magic, desc in MAGIC_DB:
            if raw[:len(magic)] == magic or magic in raw[:64]:
                r.file_type = desc
                _add_finding(r, "BINARY", "INFO", f"Dosya Tipi: {desc}",
                              f"Magic: {magic[:8]!r}")
                break
        if r.file_type == "UNKNOWN":
            r.file_type = "Binary" if r.is_binary else "Text/Config"

        # ── 3. Hash hesapla ────────────────────────────────────
        if compute_hashes:
            r.file_hash_md5    = hashlib.md5(raw).hexdigest()
            r.file_hash_sha1   = hashlib.sha1(raw).hexdigest()
            r.file_hash_sha256 = hashlib.sha256(raw).hexdigest()

        # ── 4. Entropi ─────────────────────────────────────────
        if show_entropy:
            r.entropy = entropy(raw)
            if r.entropy > 7.5:
                _add_finding(r, "BINARY", "HIGH",
                    "Yüksek Entropi (Şifreli/Paketlenmiş)",
                    f"Entropi: {r.entropy:.2f}/8.0 — şifreli veya sıkıştırılmış olabilir",
                    confidence=0.9)
            elif r.entropy > 6.0:
                _add_finding(r, "BINARY", "MEDIUM",
                    "Orta Entropi",
                    f"Entropi: {r.entropy:.2f}/8.0")

        # ── 5. Wireshark hex dump analizi ──────────────────────
        if decode_hex:
            self._parse_wireshark_hex(text, lines, r)

        # ── 6. ASCII string çıkarma ────────────────────────────
        if find_strings or decode_ascii:
            self._extract_strings(raw, r, min_string_len, max_strings)

        # ── 7. Base64 decode ───────────────────────────────────
        if decode_base64:
            self._find_base64(text, r)

        # ── 8. Kimlik bilgisi arama ────────────────────────────
        if find_creds:
            self._find_credentials(text, lines, r)

        # ── 9. Hash tespiti ────────────────────────────────────
        if find_hashes:
            self._find_hashes(text, r)

        # ── 10. Cisco Type 7 şifre çözme ──────────────────────
        if crack_cisco7:
            self._crack_cisco_passwords(text, lines, r)

        # ── 11. IOC çıkarma (IP, domain, URL) ─────────────────
        if find_iocs:
            self._extract_iocs(text, r)

        # ── 12. Gömülü dosya tespiti (file carving) ───────────
        if file_carve:
            self._carve_files(raw, r)

        # ── 13. Flag arama ─────────────────────────────────────
        if find_flags:
            self._find_flags(text, raw, r, flag_formats)

        # ── 14. Özel desen arama ───────────────────────────────
        if search_pattern:
            self._search_pattern(text, lines, r, search_pattern, context_lines)
        if search_hex:
            self._search_hex_pattern(raw, r, search_hex)

        # ── 15. Protokol tespiti ───────────────────────────────
        self._detect_protocols(text, r)

        # ── 16. Steganografi kontrolü ──────────────────────────
        if check_steg:
            self._check_steganography(raw, r)

        # ── Özet ──────────────────────────────────────────────
        r.executive_summary = self._build_summary(r)
        return r

    # ─────────────────────────────────────────────────────────────

    def _parse_wireshark_hex(self, text: str, lines: list[str], r: BibReport):
        """Wireshark hex dump formatını parse et ve decode et."""
        # 1. Format: 0x0000: 4500 0028 ... veya 0000 45 00 ...
        hex_offset_pattern = re.compile(
            r'^\s*(?:0x)?([0-9a-fA-F]{4,8}):?\s+((?:[0-9a-fA-F\?]{2,4}\s*){1,16})', re.IGNORECASE
        )
        # 2. Format: pure hex line (e.g. 00 05 73 a0 ... or 0050 569e 7bf9 ...)
        pure_hex_pattern = re.compile(
            r'^\s*((?:[0-9a-fA-F]{2,4}\s+){2,}[0-9a-fA-F]{2,4})\s*$', re.IGNORECASE
        )

        current_block = []
        block_offset  = None
        all_decoded   = []

        for i, line in enumerate(lines):
            line_str = line.strip()
            if not line_str:
                if current_block:
                    decoded_ascii = "".join(chr(b) if 32 <= b < 127 else "." for b in current_block)
                    r.hex_blocks.append({
                        "offset": block_offset or 0,
                        "hex": bytes(current_block[:16]).hex() + ("..." if len(current_block) > 16 else ""),
                        "ascii": decoded_ascii[:80],
                        "length": len(current_block),
                    })
                    self._analyze_decoded_bytes(bytes(current_block), decoded_ascii, r, block_offset or 0)
                    all_decoded.extend(current_block)
                    current_block = []
                    block_offset = None
                continue

            m_off = hex_offset_pattern.search(line_str)
            m_pure = pure_hex_pattern.search(line_str) if not m_off else None

            if m_off:
                offset_str = m_off.group(1)
                hex_part   = m_off.group(2).replace(" ", "").replace("?", "0")
                if block_offset is None:
                    try:
                        block_offset = int(offset_str, 16)
                    except ValueError:
                        block_offset = 0
                try:
                    block_bytes = bytes.fromhex(hex_part)
                    current_block.extend(block_bytes)
                except ValueError:
                    pass
            elif m_pure:
                hex_part = m_pure.group(1).replace(" ", "")
                if block_offset is None:
                    block_offset = len(all_decoded) + len(current_block)
                try:
                    block_bytes = bytes.fromhex(hex_part)
                    current_block.extend(block_bytes)
                except ValueError:
                    pass
            else:
                if current_block:
                    decoded_ascii = "".join(
                        chr(b) if 32 <= b < 127 else "." for b in current_block
                    )
                    block_info = {
                        "offset":    block_offset or 0,
                        "hex":       bytes(current_block[:16]).hex() + ("..." if len(current_block) > 16 else ""),
                        "ascii":     decoded_ascii[:80],
                        "length":    len(current_block),
                        "raw_bytes": current_block[:256],
                    }
                    r.hex_blocks.append(block_info)

                    # Decode edilebilir içerik analizi
                    self._analyze_decoded_bytes(bytes(current_block), decoded_ascii, r, block_offset or 0)
                    all_decoded.extend(current_block)
                    current_block  = []
                    block_offset   = None

        # Son blok
        if current_block:
            decoded_ascii = "".join(chr(b) if 32 <= b < 127 else "." for b in current_block)
            r.hex_blocks.append({
                "offset": block_offset or 0,
                "hex":    bytes(current_block[:16]).hex(),
                "ascii":  decoded_ascii[:80],
                "length": len(current_block),
            })
            self._analyze_decoded_bytes(bytes(current_block), decoded_ascii, r, block_offset or 0)

        # Tüm decode edilmiş veriyi bir bütün olarak analiz et
        if all_decoded:
            full = bytes(all_decoded)
            self._parse_network_header(full, r)

    def _analyze_decoded_bytes(self, data: bytes, ascii_text: str, r: BibReport, offset: int):
        """Decode edilmiş bytes'ı analiz et."""
        # HTTP tespit
        if b"GET " in data or b"POST " in data or b"HTTP/" in data:
            _add_finding(r, "ASCII", "HIGH", "HTTP İsteği Tespit Edildi",
                ascii_text[:200], offset=offset)
            # Basic Auth
            auth_m = re.search(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", data)
            if auth_m:
                b64 = auth_m.group(1)
                try:
                    decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                    _add_finding(r, "CREDENTIAL", "CRITICAL",
                        "HTTP Basic Auth Kimlik Bilgisi",
                        f"Encoded: {b64.decode()}\nDecoded: {decoded}",
                        decoded=decoded, offset=offset)
                    r.credentials.append({"type": "HTTP Basic Auth", "value": decoded, "offset": offset})
                    r.decoded_data.append({"type": "base64", "original": b64.decode(), "decoded": decoded})
                except Exception:
                    pass

        # FTP komutları
        for cmd in [b"USER ", b"PASS ", b"RETR ", b"STOR ", b"LIST"]:
            if cmd in data:
                idx = data.index(cmd)
                val = data[idx:idx+80].decode("ascii", errors="replace").strip()
                sev = "CRITICAL" if cmd in (b"USER ", b"PASS ") else "HIGH"
                _add_finding(r, "CREDENTIAL" if cmd in (b"USER ", b"PASS ") else "ASCII",
                    sev, f"FTP Komutu: {cmd.decode().strip()}", val, offset=offset)
                if cmd in (b"USER ", b"PASS "):
                    r.credentials.append({"type": f"FTP {cmd.decode().strip()}", "value": val, "offset": offset})

        # Printable strings in decoded bytes
        printable_chunks = re.findall(rb'[ -~]{6,}', data)
        for chunk in printable_chunks:
            chunk_str = chunk.decode('ascii', errors='replace').strip()
            if any(kw in chunk_str.lower() for kw in ("root-me", "flag", "key", "secret", "token", "password", "user", ".org", ".com", ".net")):
                _add_finding(r, "ASCII", "HIGH", f"Decoded Text Payload: {chunk_str[:40]}", chunk_str, offset=offset)

    def _parse_network_header(self, data: bytes, r: BibReport):
        """Ethernet/IP/TCP header'larını parse et."""
        try:
            if len(data) < 14:
                return
            # Ethernet
            dst_mac = ":".join(f"{b:02x}" for b in data[0:6])
            src_mac = ":".join(f"{b:02x}" for b in data[6:12])
            ethertype = struct.unpack("!H", data[12:14])[0]

            if ethertype == 0x0800 and len(data) >= 34:  # IPv4
                ip_src = ".".join(str(b) for b in data[26:30])
                ip_dst = ".".join(str(b) for b in data[30:34])
                proto  = data[23]
                r.network_iocs.extend([ip for ip in [ip_src, ip_dst]
                                       if ip not in r.network_iocs])
                _add_finding(r, "BINARY", "INFO",
                    f"IP Header: {ip_src} → {ip_dst}",
                    f"Proto={proto} EtherType=0x{ethertype:04x}")

                if proto == 6 and len(data) >= 54:   # TCP
                    src_port = struct.unpack("!H", data[34:36])[0]
                    dst_port = struct.unpack("!H", data[36:38])[0]
                    _add_finding(r, "BINARY", "INFO",
                        f"TCP Ports: {src_port} → {dst_port}", "")

            elif ethertype == 0x86dd and len(data) >= 54:  # IPv6
                ip6_src = ":".join(f"{data[22+i*2]:02x}{data[23+i*2]:02x}" for i in range(8))
                ip6_dst = ":".join(f"{data[38+i*2]:02x}{data[39+i*2]:02x}" for i in range(8))
                _add_finding(r, "BINARY", "INFO",
                    f"IPv6: {ip6_src} → {ip6_dst}", "")
        except Exception:
            pass

    def _extract_strings(self, raw: bytes, r: BibReport, min_len: int, max_count: int):
        """Binary'den printable ASCII string'leri çıkar."""
        pattern = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
        matches = pattern.findall(raw)
        seen = set()
        for m in matches[:max_count]:
            s = m.decode("ascii", errors="replace")
            if s not in seen:
                seen.add(s)
                r.ascii_strings.append(s)

    def _find_base64(self, text: str, r: BibReport):
        """Base64 blokları bul ve decode et."""
        # Minimum 20 karakter Base64
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        for m in b64_pattern.finditer(text):
            b64 = m.group()
            try:
                decoded = base64.b64decode(b64 + "==").decode("utf-8", errors="strict")
                if any(32 <= ord(c) < 127 for c in decoded[:10]):
                    r.decoded_data.append({"type": "base64", "original": b64[:60], "decoded": decoded[:200]})
                    _add_finding(r, "ASCII", "MEDIUM", "Base64 Decode",
                        f"Input: {b64[:40]}...\nDecoded: {decoded[:100]}",
                        decoded=decoded[:200])
                    # Kimlik bilgisi deseni
                    if ":" in decoded and len(decoded.split(":")) == 2:
                        r.credentials.append({"type": "Base64 credential", "value": decoded})
                        _add_finding(r, "CREDENTIAL", "CRITICAL",
                            "Base64 Kimlik Bilgisi",
                            decoded, decoded=decoded)
            except Exception:
                pass

    def _find_credentials(self, text: str, lines: list[str], r: BibReport):
        """Kimlik bilgisi kalıpları ara."""
        patterns = [
            (r'(?:username|user|login)\s*[=:]\s*["\']?(\S+)["\']?', "USERNAME"),
            (r'(?:password|passwd|pass|pwd)\s*[=:]\s*["\']?(\S+)["\']?', "PASSWORD"),
            (r'USER\s+(\S+)',                                             "FTP USER"),
            (r'PASS\s+(\S+)',                                             "FTP PASS"),
            (r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)',              "HTTP Basic Auth"),
            (r'Authorization:\s*Bearer\s+([A-Za-z0-9._-]+)',             "JWT Token"),
            (r'(?:api[_-]?key|apikey|api_token)\s*[=:]\s*["\']?(\w+)',   "API Key"),
            (r'(?:secret|token)\s*[=:]\s*["\']?(\w{8,})',                "Secret/Token"),
            (r'username\s+"(\S+)"\s+password\s+7\s+([0-9A-F]+)',         "Cisco User Type7"),
            (r'enable secret\s+\d+\s+(\S+)',                              "Cisco Enable Secret"),
            (r'password\s+7\s+([0-9A-F]+)',                               "Cisco Type7 Pwd"),
            (r'["\']?(?:PLAIN|CLEAR)["\']?\s*[,:]?\s*["\']?([^"\'\r\n,]+)["\']?', "Cleartext Pwd"),
            (r'["\']?asterisk["\']?\s*[,:]?\s*["\']?(REGISTER|INVITE|BYE)["\']?', "Asterisk VoIP Session"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cred_type in patterns:
                m = re.search(pattern, line, re.IGNORECASE)
                if m:
                    val = m.group(1) if m.lastindex >= 1 else m.group(0)
                    r.credentials.append({
                        "type": cred_type, "value": val, "line": i
                    })
                    _add_finding(r, "CREDENTIAL", "CRITICAL",
                        f"Kimlik Bilgisi: {cred_type}",
                        f"Satır {i}: {line.strip()[:100]}",
                        line_number=i)

    def _crack_cisco_passwords(self, text: str, lines: list[str], r: BibReport):
        """Cisco Type 7 şifrelerini çöz."""
        type7_pattern = re.compile(r'password\s+7\s+([0-9A-Fa-f]{4,})', re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            m = type7_pattern.search(line)
            if m:
                cipher = m.group(1)
                plain  = decode_cisco_type7(cipher)
                r.credentials.append({
                    "type": "Cisco Type7 (CRACKED)",
                    "value": plain, "line": i,
                    "cipher": cipher
                })
                _add_finding(r, "CREDENTIAL", "CRITICAL",
                    "Cisco Type 7 Şifre Çözüldü!",
                    f"Şifreli: {cipher} → Açık: {plain}",
                    decoded=plain, line_number=i)
                r.decoded_data.append({
                    "type": "cisco_type7",
                    "original": cipher,
                    "decoded": plain
                })

    def _find_hashes(self, text: str, r: BibReport):
        """Hash kalıpları tespit et."""
        hash_patterns = [
            (r'\b[0-9a-fA-F]{32}\b',  "MD5"),
            (r'\b[0-9a-fA-F]{40}\b',  "SHA1"),
            (r'\b[0-9a-fA-F]{64}\b',  "SHA256"),
            (r'\b[0-9a-fA-F]{128}\b', "SHA512"),
            (r'\$1\$[./0-9A-Za-z]{8}\$[./0-9A-Za-z]{22}', "Cisco MD5 (Type5)"),
            (r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}',       "bcrypt"),
            (r'\$6\$[./0-9A-Za-z]{8,16}\$[./0-9A-Za-z]{86}', "SHA512crypt"),
            (r'[0-9a-fA-F]{32}:[0-9a-fA-F]{32}',          "NTLMv1"),
            (r'[0-9a-fA-F]{32}:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}', "NTLMv2 (partial)"),
        ]

        seen = set()
        for pattern, hash_type in hash_patterns:
            for m in re.finditer(pattern, text):
                val = m.group()
                if val not in seen:
                    seen.add(val)
                    r.hashes.append({"type": hash_type, "value": val})
                    _add_finding(r, "HASH", "HIGH",
                        f"Hash Tespit: {hash_type}",
                        val)

    def _extract_iocs(self, text: str, r: BibReport):
        """IP adresi, domain, URL çıkar."""
        # IPv4
        for m in re.finditer(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
            ip = m.group()
            if ip not in r.network_iocs and not ip.startswith("0."):
                r.network_iocs.append(ip)

        # IPv6 (kısa format)
        for m in re.finditer(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', text):
            ip6 = m.group()
            if ip6 not in r.network_iocs:
                r.network_iocs.append(ip6)

        # URL
        for m in re.finditer(r'https?://[^\s"\'<>]+', text):
            url = m.group()
            if url not in r.network_iocs:
                r.network_iocs.append(url)
                _add_finding(r, "ASCII", "MEDIUM", "URL Tespit", url)

        # Domain (basit)
        for m in re.finditer(r'\b(?:[a-zA-Z0-9-]+\.){2,}[a-zA-Z]{2,}\b', text):
            dom = m.group()
            if dom not in r.network_iocs and "." in dom:
                r.network_iocs.append(dom)

    def _carve_files(self, raw: bytes, r: BibReport):
        """Binary içinde gömülü dosyaları bul (file carving)."""
        signatures = [
            (b"\xff\xd8\xff", b"\xff\xd9",    "JPEG"),
            (b"\x89PNG\r\n",  b"\x00IEND\xaeB`\x82", "PNG"),
            (b"%PDF",         b"%%EOF",        "PDF"),
            (b"PK\x03\x04",   None,            "ZIP"),
            (b"MZ",           None,            "PE EXE"),
            (b"\x7fELF",      None,            "ELF"),
        ]

        for start_sig, end_sig, ftype in signatures:
            pos = 0
            while True:
                idx = raw.find(start_sig, pos)
                if idx == -1:
                    break
                end_idx = -1
                if end_sig:
                    end_idx = raw.find(end_sig, idx + len(start_sig))
                    if end_idx != -1:
                        end_idx += len(end_sig)

                carved_len = end_idx - idx if end_idx > idx else min(1024, len(raw) - idx)
                r.embedded_files.append({
                    "type":   ftype,
                    "offset": idx,
                    "size":   carved_len,
                })
                _add_finding(r, "BINARY", "HIGH",
                    f"Gömülü Dosya Tespit: {ftype}",
                    f"Offset: 0x{idx:08x}, Boyut: ~{carved_len} byte")
                pos = idx + 1
                if pos >= len(raw):
                    break

    def _find_flags(self, text: str, raw: bytes, r: BibReport, formats: list = None):
        """CTF flag formatlarını ara."""
        default_formats = [
            r"FLAG\{[^}]+\}",
            r"CTF\{[^}]+\}",
            r"flag\{[^}]+\}",
            r"picoCTF\{[^}]+\}",
            r"ASIS\{[^}]+\}",
            r"HTB\{[^}]+\}",
            r"THM\{[^}]+\}",
            r"Root-Me\{[^}]+\}",
            r"FCSC\{[^}]+\}",
            r"[A-Z]{2,8}\{[0-9a-fA-F_\-]+\}",
        ]
        formats = formats or default_formats

        for fmt in formats:
            for m in re.finditer(fmt, text, re.IGNORECASE):
                flag = m.group()
                _add_finding(r, "ASCII", "CRITICAL",
                    f"🚩 FLAG BULUNDU!",
                    flag, confidence=1.0)

        # Hex/raw içinde de ara
        try:
            raw_text = raw.decode("latin-1", errors="replace")
            for fmt in default_formats:
                for m in re.finditer(fmt, raw_text, re.IGNORECASE):
                    flag = m.group()
                    offset = m.start()
                    _add_finding(r, "BINARY", "CRITICAL",
                        f"🚩 FLAG BULUNDU (Binary)!",
                        flag, offset=offset, confidence=1.0)
        except Exception:
            pass

    def _search_pattern(self, text: str, lines: list[str], r: BibReport,
                         pattern: str, context: int):
        """Özel desen arama."""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            _add_finding(r, "ASCII", "INFO", "Geçersiz Regex", str(e))
            return

        for i, line in enumerate(lines, 1):
            if compiled.search(line):
                ctx_start = max(0, i - 1 - context)
                ctx_end   = min(len(lines), i + context)
                ctx_lines = "\n".join(lines[ctx_start:ctx_end])
                _add_finding(r, "ASCII", "MEDIUM",
                    f"Desen Eşleşmesi (satır {i})",
                    ctx_lines)

    def _search_hex_pattern(self, raw: bytes, r: BibReport, hex_pattern: str):
        """Hex byte deseni ara."""
        try:
            needle = bytes.fromhex(hex_pattern.replace(" ", ""))
        except ValueError:
            _add_finding(r, "BINARY", "INFO", "Geçersiz Hex", hex_pattern)
            return

        pos = 0
        count = 0
        while True:
            idx = raw.find(needle, pos)
            if idx == -1:
                break
            context = raw[max(0, idx-8):idx+8+len(needle)]
            _add_finding(r, "BINARY", "HIGH",
                f"Hex Deseni Bulundu @ 0x{idx:08x}",
                f"Bağlam: {context.hex()} ({context.decode('latin-1', errors='replace')})",
                offset=idx)
            pos = idx + 1
            count += 1
            if count > 50:
                break

    def _detect_protocols(self, text: str, r: BibReport):
        """Metin içinde protokol imzaları bul."""
        proto_sigs = {
            "FTP":     [r"\bUSER\s+\w+", r"\bPASS\s+\S+", r"\bRETR\s+\S+"],
            "HTTP":    [r"\bGET\s+/", r"\bPOST\s+/", r"\bHTTP/1\.[01]\b"],
            "SIP":     [r"\bREGISTER\b", r"\bINVITE\b", r"\bBYE\b", r"sip:"],
            "SMTP":    [r"\bEHLO\s+\S+", r"\bMAIL FROM:", r"\bRCPT TO:"],
            "Cisco":   [r"\benable secret\b", r"\busername\s+\S+\s+password\s+7\b"],
            "BGP":     [r"\brouter bgp\s+\d+", r"\bneighbor\s+\d+\.\d+\.\d+\.\d+\b"],
            "SSH":     [r"\bSSH-2\.0-", r"\bSSH-1\."],
        }

        for proto, patterns in proto_sigs.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    if proto not in r.detected_protocols:
                        r.detected_protocols.append(proto)
                    break

    def _check_steganography(self, raw: bytes, r: BibReport):
        """Temel steganografi tespiti."""
        # PNG LSB analizi
        if raw[:8] == b"\x89PNG\r\n\x1a\n":
            # En az 2 renk kanalında entropi
            lsb_data = bytes(b & 1 for b in raw[8:8+1024])
            lsb_entropy = entropy(lsb_data)
            if lsb_entropy > 0.9:
                _add_finding(r, "STEG", "MEDIUM",
                    "PNG LSB Steganografi Şüphesi",
                    f"LSB entropi: {lsb_entropy:.3f} (>0.9 şüpheli)",
                    confidence=0.6)

        # JPEG comment
        jpeg_comment = re.search(rb"\xff\xfe(.{2})(.+?)(?=\xff)", raw)
        if jpeg_comment:
            try:
                length = struct.unpack("!H", jpeg_comment.group(1))[0]
                comment = jpeg_comment.group(2)[:length].decode("utf-8", errors="replace")
                if comment.strip():
                    _add_finding(r, "STEG", "MEDIUM",
                        "JPEG Yorum Alanı",
                        comment[:200])
            except Exception:
                pass

    def _build_summary(self, r: BibReport) -> str:
        lines = [
            f"Dosya: {Path(r.file_path).name} ({r.file_type}, {r.file_size:,} byte)",
            f"MD5: {r.file_hash_md5}",
            f"Entropi: {r.entropy:.2f}/8.0",
            f"Tespit edilen protokoller: {', '.join(r.detected_protocols) or 'Yok'}",
            f"Bulgular: {len(r.findings)} | Kimlik: {len(r.credentials)} | Hash: {len(r.hashes)}",
            f"Gömülü dosya: {len(r.embedded_files)} | IOC: {len(r.network_iocs)} | Base64 decode: {len(r.decoded_data)}",
        ]
        crit = [f for f in r.findings if f.severity == "CRITICAL"]
        if crit:
            lines.append(f"KRİTİK BULGULAR ({len(crit)}): " + "; ".join(f.title for f in crit[:3]))
        return " | ".join(lines)


def _add_finding(r: BibReport, category: str, severity: str, title: str,
                  value: str, decoded: str = "", line_number: int = 0,
                  offset: int = 0, confidence: float = 1.0):
    for f in r.findings:
        if f.title == title and f.value[:30] == value[:30]:
            return
    r.findings.append(BibFinding(
        category=category, severity=severity, title=title,
        value=value, decoded=decoded, line_number=line_number,
        offset=offset, confidence=confidence
    ))


# ─── Terminal Renderer ───────────────────────────────────────────────────────

RESET  = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
RED    = "\033[91m"; RED_BG = "\033[41m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; GREEN = "\033[92m"; MAGENTA = "\033[95m"
WHITE  = "\033[97m"; GREY  = "\033[90m"
SEV_C  = {"CRITICAL": f"\033[41m\033[1m", "HIGH": f"\033[91m\033[1m",
          "MEDIUM": "\033[93m", "LOW": "\033[96m", "INFO": "\033[90m"}


def render_bib_report(report: BibReport, verbose: bool = False):
    import shutil
    W = shutil.get_terminal_size((120, 40)).columns

    def div(c="─"): print(f"{GREY}{c*W}{RESET}")

    print(f"\n{CYAN}{BOLD}")
    print("  ██████╗  ██╗██████╗     ██████╗ ██╗██████╗")
    print("  ██╔══██╗ ██║██╔══██╗    ██╔══██╗██║██╔══██╗")
    print("  ██████╔╝ ██║██████╔╝    ██████╔╝██║██████╔╝")
    print("  ██╔══██╗ ██║██╔══██╗    ██╔══██╗██║██╔══██╗")
    print("  ██████╔╝ ██║██████╔╝    ██████╔╝██║██████╔╝")
    print("  ╚═════╝  ╚═╝╚═════╝     ╚═════╝ ╚═╝╚═════╝")
    print(f"{RESET}{GREY}  VCAS.PRIVATE × QNTSOFTWARE — Binary Intelligence{RESET}\n")
    div()

    # Dosya bilgisi
    print(f"\n  {BOLD}DOSYA:{RESET} {WHITE}{report.file_path}{RESET}")
    print(f"  {BOLD}TİP:{RESET}   {CYAN}{report.file_type}{RESET}  |  "
          f"{BOLD}BOYUT:{RESET} {report.file_size:,} byte  |  "
          f"{BOLD}ENTROPİ:{RESET} {report.entropy:.2f}/8.0")
    print(f"  {BOLD}MD5:{RESET}   {GREY}{report.file_hash_md5}{RESET}")
    print(f"  {BOLD}SHA1:{RESET}  {GREY}{report.file_hash_sha1}{RESET}")
    div("·")

    # Tespit edilen protokoller
    if report.detected_protocols:
        print(f"\n  {BOLD}TESPİT EDİLEN PROTOKOLLER:{RESET} " +
              "  ".join(f"{CYAN}[{p}]{RESET}" for p in report.detected_protocols))

    # Kritik bulgular
    div("·")
    crit_findings = sorted(report.findings,
                           key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(f.severity))
    if crit_findings:
        print(f"\n  {BOLD}BULGULAR ({len(crit_findings)}){RESET}\n")
        for f in crit_findings:
            sc = SEV_C.get(f.severity, "")
            loc = f"satır {f.line_number}" if f.line_number else (f"0x{f.offset:08x}" if f.offset else "")
            print(f"  {sc}[{f.severity}]{RESET}  {BOLD}{f.category}{RESET}  {f.title}  {GREY}{loc}{RESET}")
            # Value (truncate)
            val = f.value.replace("\n", " | ")[:120]
            print(f"           {WHITE}{val}{RESET}")
            if f.decoded:
                print(f"           {GREEN}→ ÇÖZÜLDÜ: {f.decoded[:100]}{RESET}")
            print()

    # Kimlik bilgileri
    if report.credentials:
        div("·")
        print(f"\n  {RED}{BOLD}☠ KİMLİK BİLGİLERİ ({len(report.credentials)}){RESET}\n")
        for c in report.credentials:
            print(f"    {RED}{BOLD}[{c['type']}]{RESET}  {YELLOW}{c['value'][:100]}{RESET}  "
                  f"{GREY}{'satır '+str(c.get('line','')) if c.get('line') else ''}{RESET}")

    # Hash'ler
    if report.hashes:
        div("·")
        print(f"\n  {BOLD}HASHLER ({len(report.hashes)}){RESET}\n")
        for h in report.hashes[:20]:
            print(f"    {YELLOW}[{h['type']}]{RESET}  {h['value'][:80]}")

    # Decode edilmiş veriler
    if report.decoded_data:
        div("·")
        print(f"\n  {BOLD}DECODE EDİLEN VERİLER ({len(report.decoded_data)}){RESET}\n")
        for d in report.decoded_data[:15]:
            print(f"    {CYAN}[{d['type']}]{RESET}")
            print(f"    Orijinal: {GREY}{d['original'][:60]}{RESET}")
            print(f"    Çözüldü: {GREEN}{BOLD}{d['decoded'][:100]}{RESET}\n")

    # Gömülü dosyalar
    if report.embedded_files:
        div("·")
        print(f"\n  {BOLD}GÖMÜLÜ DOSYALAR ({len(report.embedded_files)}){RESET}\n")
        for ef in report.embedded_files:
            print(f"    {MAGENTA}[{ef['type']}]{RESET}  offset=0x{ef['offset']:08x}  ~{ef['size']} byte")

    # IOC'ler
    if report.network_iocs:
        div("·")
        print(f"\n  {BOLD}AĞSAL IOC'LER ({len(report.network_iocs)}){RESET}\n")
        for ioc in report.network_iocs[:30]:
            print(f"    {CYAN}{ioc}{RESET}")

    # Hex blokları (verbose modda)
    if verbose and report.hex_blocks:
        div("·")
        print(f"\n  {BOLD}HEX BLOKLAR ({len(report.hex_blocks)}){RESET}\n")
        for blk in report.hex_blocks[:10]:
            print(f"  {GREY}Offset 0x{blk['offset']:08x} ({blk['length']} byte):{RESET}")
            print(f"  HEX: {GREY}{blk['hex']}{RESET}")
            print(f"  ASC: {WHITE}{blk['ascii'][:60]}{RESET}\n")

    div()
    print(f"\n  {BOLD}ÖZET:{RESET} {report.executive_summary}\n")
    div("═")


# ─── CLI Entry Point ─────────────────────────────────────────────────────────

def pcapbib_main():
    parser = argparse.ArgumentParser(
        prog="pcapbib",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""
        ╔══════════════════════════════════════════════════════════════════════╗
        ║   pcapbib — Universal Binary & File Intelligence Analyzer            ║
        ║   VCAS.PRIVATE × QNTSOFTWARE                                         ║
        ╚══════════════════════════════════════════════════════════════════════╝
        
        Deep inspection of Wireshark hex dumps, raw binary payloads, Cisco/router
        configs, SIP/VoIP authentication logs, memory dumps, and protocol streams.
        """),
        epilog=textwrap.dedent("""
PARAMETER COMBINATIONS & EXAMPLES:

  [1] Wireshark Hex Dump Inspection & Authentication Extraction:
      pcapbib -i dump.txt --hex --b64 --creds -lang tr
      pcapbib -i dump.txt --hex --ascii --ioc -lang eng

  [2] Cisco & Router Configuration Audit (Type 7 Cracking + Hash Identification):
      pcapbib -i cisco.cfg --cisco --hashes --ioc --pdf -o cisco_audit.pdf -lang tr
      pcapbib -i router.cfg --cisco --creds -lang de

  [3] SIP / VoIP Security & Authentication Analysis:
      pcapbib -i sip.log --creds --hashes --proto -lang ru
      pcapbib -i asterisk.csv --creds --hashes --ioc -lang eng

  [4] CTF Binary Analysis & Flag Extraction:
      pcapbib -i challenge.bin --carve --flags --b64 --entropy -lang eng
      pcapbib -i ctf.bin --flags --flag-format "Root-Me\\{[^\\}]+\\}" -lang tr

  [5] Steganography & High-Entropy Packing Verification:
      pcapbib -i suspect.png --steg --entropy --magic
      pcapbib -i evidence.bin --entropy --magic --hashes

  [6] Pattern & Raw Byte Hunting:
      pcapbib -i memory.dmp --search "password" --ctx 4 -lang eng
      pcapbib -i firmware.bin --search-hex "FF D8 FF" --carve

  [7] Full Automated Triage with AI Interpretation:
      pcapbib -i sample.txt --all --ai-api AIzaSy... --ai-task "Perform security audit" -lang tr
      pcapbib -i sample.bin --all --ai-local llama3 --ai-task "Analyze suspicious payload" -lang eng

  [8] Structured JSON Export for Automated Pipelines:
      pcapbib -i capture_dump.txt --all --json -o analysis.json
        """)
    )

    inp = parser.add_argument_group("INPUT & LOCALIZATION")
    inp.add_argument("-i", "--input", metavar="<file>", required=True, help="Target file to analyze (hex dump, binary, config, log)")
    inp.add_argument("--batch", action="store_true", help="Batch analyze multiple files matching glob pattern")
    inp.add_argument("-lang", "--lang", metavar="<code|help>", default=None,
                     help="Language: eng, tr, de, ru, fr, es, ar, zh, ja, it, pt, ko, nl, pl, sv (or 'help')")

    ana = parser.add_argument_group("ANALYSIS CAPABILITIES (20 UNIQUE ENGINES)")
    ana.add_argument("--hex", action="store_true", help="[1] Parse Wireshark hex dump and reconstruct network layers")
    ana.add_argument("--ascii", action="store_true", help="[2] Extract and display clean ASCII strings")
    ana.add_argument("--b64", action="store_true", help="[3] Detect and decode Base64 encoded streams")
    ana.add_argument("--creds", action="store_true", help="[4] Harvest credentials (usernames, passwords, tokens, API keys)")
    ana.add_argument("--hashes", action="store_true", help="[5] Identify cryptographic hashes (MD5, SHA1/256/512, NTLM, bcrypt, Cisco)")
    ana.add_argument("--cisco", action="store_true", help="[6] Decrypt Cisco Type 7 reversible XOR passwords")
    ana.add_argument("--ioc", action="store_true", help="[7] Extract network IOCs (IPv4, IPv6, domains, URLs)")
    ana.add_argument("--carve", action="store_true", help="[8] File carving (recover embedded PNG, JPEG, PDF, ZIP, ELF, PE)")
    ana.add_argument("--strings", action="store_true", help="[9] Extract all printable strings")
    ana.add_argument("--entropy", action="store_true", help="[10] Calculate Shannon entropy to detect packed/encrypted data")
    ana.add_argument("--magic", action="store_true", help="[11] Detect true file type using Magic Bytes signatures")
    ana.add_argument("--proto", action="store_true", help="[12] Identify protocol signatures (FTP, HTTP, SIP, SMTP, SSH, Cisco, BGP)")
    ana.add_argument("--flags", action="store_true", help="[13] Hunt for CTF flag formats (FLAG{...}, Root-Me{...}, etc.)")
    ana.add_argument("--steg", action="store_true", help="[14] Steganography verification (PNG LSB channel, JPEG markers)")
    ana.add_argument("--all", action="store_true", help="[15] Enable all 14 core analysis engines simultaneously")

    sea = parser.add_argument_group("TARGETED SEARCH")
    sea.add_argument("--search", metavar="<regex>", help="[16] Search with custom regular expression")
    sea.add_argument("--search-hex", metavar="<hex>", help="[17] Search for exact hex byte sequences (e.g. 'FF D8 FF')")
    sea.add_argument("--ctx", type=int, default=2, metavar="<lines>", help="Number of context lines surrounding regex matches")
    sea.add_argument("--flag-format", metavar="<regex>", help="[18] Define custom regex pattern for CTF flag hunting")

    str_grp = parser.add_argument_group("STRING TUNING")
    str_grp.add_argument("--min-str", type=int, default=4, metavar="<len>", help="[19] Minimum length for string extraction (default: 4)")
    str_grp.add_argument("--max-str", type=int, default=200, metavar="<count>", help="[20] Maximum number of extracted strings to list (default: 200)")

    out = parser.add_argument_group("OUTPUT & REPORTING")
    out.add_argument("-o", metavar="<file>", help="Custom path for output report")
    out.add_argument("--json", action="store_true", help="Export structured report in JSON format")
    out.add_argument("--pdf", action="store_true", help="Generate executive PDF intelligence report")
    out.add_argument("--verbose", action="store_true", help="Verbose display including raw hex offsets and blocks")
    out.add_argument("--no-color", action="store_true", help="Disable ANSI color formatting")
    out.add_argument("--compute-hashes", action="store_true", default=True, help="Compute file MD5, SHA1, and SHA256 hashes")

    ai_grp = parser.add_argument_group("AI ASSISTANCE (OPTIONAL)")
    ai_grp.add_argument("--ai-api", metavar="<key>", help="Gemini API Key for expert AI interpretation")
    ai_grp.add_argument("--ai-local", metavar="<model>", help="Local Ollama model name for offline AI interpretation")
    ai_grp.add_argument("--ai-task", metavar="<desc>", help="Task brief for AI analysis")

    args = parser.parse_args()

    if args.lang:
        if args.lang.lower() in ("help", "list"):
            print(list_languages())
            sys.exit(0)
        set_lang(args.lang)

    # all flag
    if args.all:
        args.hex = args.ascii = args.b64 = args.creds = args.hashes = True
        args.cisco = args.ioc = args.carve = args.strings = args.entropy = True
        args.magic = args.proto = args.flags = True

    # Varsayılan: en azından temel analiz
    any_mode = any([args.hex, args.ascii, args.b64, args.creds, args.hashes,
                    args.cisco, args.ioc, args.carve, args.strings, args.entropy,
                    args.magic, args.proto, args.flags])
    if not any_mode:
        # Temel mod: hepsi açık
        args.hex = args.ascii = args.b64 = args.creds = args.hashes = True
        args.cisco = args.ioc = args.flags = args.proto = True

    analyzer = BibAnalyzer(args.input)
    report   = analyzer.run(
        decode_hex      = args.hex,
        decode_ascii    = args.ascii or args.strings,
        decode_base64   = args.b64,
        find_creds      = args.creds,
        find_hashes     = args.hashes,
        crack_cisco7    = args.cisco,
        find_iocs       = args.ioc,
        file_carve      = args.carve,
        find_strings    = args.strings,
        min_string_len  = args.min_str,
        check_steg      = args.steg,
        show_entropy    = args.entropy,
        compute_hashes  = args.compute_hashes,
        search_pattern  = args.search or "",
        search_hex      = args.search_hex or "",
        find_flags      = args.flags,
        flag_formats    = [args.flag_format] if args.flag_format else None,
        max_strings     = args.max_str,
        context_lines   = args.ctx,
    )

    # AI desteği
    if args.ai_api or args.ai_local:
        _bib_ai_analysis(report, args)

    # Çıktı
    if args.json:
        import dataclasses
        def _ser(o):
            if dataclasses.is_dataclass(o): return dataclasses.asdict(o)
            return str(o)
        out_json = json.dumps(dataclasses.asdict(report), default=_ser, indent=2, ensure_ascii=False)
        path = args.o or args.input + "_bib.json"
        with open(path, "w", encoding="utf-8") as f:
            f.write(out_json)
        print(f"\033[92m✔ JSON → {path}\033[0m")
    else:
        render_bib_report(report, verbose=args.verbose)

    if args.pdf:
        _bib_pdf(report, args.o)


def _bib_ai_analysis(report: BibReport, args):
    """AI ile ek analiz."""
    try:
        from .prompt_engine import _load_persona
        persona = _load_persona()
    except Exception:
        persona = ""

    summary = report.executive_summary
    creds   = "\n".join(f"- [{c['type']}] {c['value']}" for c in report.credentials[:20])
    hashes  = "\n".join(f"- [{h['type']}] {h['value']}" for h in report.hashes[:10])
    strings = "\n".join(report.ascii_strings[:50])
    task    = args.ai_task or "Bu dosyayı güvenlik açısından tam analiz et"

    prompt = f"""{persona}

═══════════════════════════════════════════════════════════════════
LANGUAGE INSTRUCTION
═══════════════════════════════════════════════════════════════════
{get_ai_language_instruction()}

GÖREV: {task}
DOSYA: {report.file_path} ({report.file_type}, entropi={report.entropy:.2f})

TESPİT EDİLEN PROTOKOLLER: {', '.join(report.detected_protocols)}

KİMLİK BİLGİLERİ:
{creds or 'Yok'}

HASHLER:
{hashes or 'Yok'}

STRINGS (ilk 50):
{strings}

BULGULAR:
{chr(10).join(f'[{f.severity}] {f.title}: {f.value[:80]}' for f in report.findings[:30])}

Kapsamlı güvenlik analizi yap, şifre/hash kırma önerileri ver, flag varsa göster.
"""

    if args.ai_api:
        try:
            import google.generativeai as genai
            genai.configure(api_key=args.ai_api)
            model = genai.GenerativeModel("gemini-2.0-flash")
            resp  = model.generate_content(prompt)
            report.ai_analysis = resp.text
            print(f"\n\033[96m[AI ANALİZ]\033[0m\n{resp.text}\n")
        except Exception as e:
            print(f"\033[91m[AI HATA] {e}\033[0m")

    elif args.ai_local:
        try:
            import requests
            resp = requests.post("http://localhost:11434/api/generate",
                json={"model": args.ai_local, "prompt": prompt, "stream": False},
                timeout=300)
            resp.raise_for_status()
            analysis = resp.json().get("response", "")
            report.ai_analysis = analysis
            print(f"\n\033[96m[AI ANALİZ]\033[0m\n{analysis}\n")
        except Exception as e:
            print(f"\033[91m[AI HATA] {e}\033[0m")


def _bib_pdf(report: BibReport, output_path: str = None):
    """PDF rapor üret."""
    try:
        from .reporter import _ensure_reportlab
        if not _ensure_reportlab():
            return

        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from datetime import datetime
        import dataclasses

        path = output_path or report.file_path + "_bib_report.pdf"
        doc  = SimpleDocTemplate(path, pagesize=A4, topMargin=1.5*cm, bottomMargin=1.5*cm,
                                 leftMargin=1.5*cm, rightMargin=1.5*cm)
        story = []
        style = lambda n, **kw: ParagraphStyle(n, **kw)

        ACCENT = colors.HexColor("#00C8FF")
        DARK   = colors.HexColor("#0D0D0D")
        MID    = colors.HexColor("#1E1E2E")
        BODY   = colors.HexColor("#D0D0E0")
        RED_C  = colors.HexColor("#FF3B3B")

        story.append(Paragraph('<font color="#00C8FF" size="24"><b>pcapbib — Binary Intelligence Report</b></font>',
            style("T", fontName="Helvetica-Bold", fontSize=24, textColor=ACCENT, alignment=1, spaceAfter=4)))
        story.append(Paragraph("VCAS.PRIVATE × QNTSOFTWARE",
            style("S", fontName="Helvetica-Bold", fontSize=10, textColor=colors.HexColor("#B0BEC5"), alignment=1)))
        story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
        story.append(Spacer(1, 0.4*cm))

        meta = [
            ["File", report.file_path],
            ["Type", report.file_type],
            ["Size", f"{report.file_size:,} bytes"],
            ["Entropy", f"{report.entropy:.2f} / 8.00"],
            ["MD5", report.file_hash_md5],
            ["SHA256", report.file_hash_sha256],
            ["Protocols", ", ".join(report.detected_protocols) or "None"],
            ["Findings", str(len(report.findings))],
            ["Credentials", str(len(report.credentials))],
            ["Hashes", str(len(report.hashes))],
            ["Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ]
        mt = Table(meta, colWidths=[4*cm, 13*cm])
        mt.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(0,-1), MID),
            ("BACKGROUND", (1,0),(1,-1), colors.HexColor("#161625")),
            ("TEXTCOLOR",  (0,0),(0,-1), ACCENT),
            ("TEXTCOLOR",  (1,0),(1,-1), BODY),
            ("FONTNAME",   (0,0),(0,-1), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0),(-1,-1), 9),
            ("GRID",       (0,0),(-1,-1), 0.5, colors.HexColor("#303050")),
            ("LEFTPADDING",(0,0),(-1,-1), 8),
            ("TOPPADDING", (0,0),(-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1), 4),
        ]))
        story.append(mt)
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph("SUMMARY", style("SH", fontName="Helvetica-Bold", fontSize=12, textColor=ACCENT, spaceBefore=10)))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Paragraph(report.executive_summary,
            style("B", fontName="Helvetica", fontSize=9, textColor=BODY, leading=14)))

        doc.build(story)
        print(f"\033[92m✔ PDF → {path}\033[0m")
    except Exception as e:
        print(f"\033[91m[PDF HATA] {e}\033[0m")
