# PCAP ANALYZER
### Network Intelligence & Security Analysis Platform
#### Developed by **VCAS.PRIVATE** × **QNTSOFTWARE**

---

## Overview

**PCAP ANALYZER** is a powerful command-line tool for Kali Linux that combines deep packet analysis with AI-powered intelligence. It supports both Google Gemini API and fully offline local AI (via Ollama).

---

## Installation

```bash
git clone https://github.com/qntsoftware/Pcap-Analyzer.git
cd Pcap-Analyzer
chmod +x install.sh
sudo ./install.sh
```

After installation, the following commands are available globally:

| Command        | Purpose                                       |
|----------------|-----------------------------------------------|
| `pcapanalyzer` | Main tool (Gemini API mode & No-AI mode)      |
| `pcapmg`       | Local AI mode (Ollama / offline & No-AI mode) |
| `pcapbib`      | Binary / Hex dump / Config intelligence tool  |

---

## Commands Reference

### 1. Set Gemini API Key
```bash
pcapanalyzer -api YOUR_GEMINI_API_KEY
```
Saves your key to `~/.pcapanalyzer/config.json`. Only needed once.

---

### 2. Analyze a PCAP File
```bash
pcapanalyzer -path "capture.pcap" -des "Task description"
```

**All parameters:**

| Flag | Description |
|------|-------------|
| `-path` | Path to `.pcap` or `.pcapng` file |
| `-f`    | Wireshark display filter (e.g. `http`, `dns`, `tcp.port==443`) |
| `-des`  | AI task description — tells the AI what to look for |
| `-lang` | Language selection: `eng`, `tr`, `de`, `ru`, `fr`, `es`, `zh`, `ja`, etc. |
| `-o`    | Custom PDF output path |
| `--no-pdf` | Skip PDF generation |
| `--no-ai` | Complete local analysis without AI (100+ parameters) |

---

### 3. Multilingual Support (`-lang`)
Run in any supported language:
```bash
# English (default)
pcapanalyzer -path capture.pcap -des "Find the flag" -lang eng

# Türkçe (Turkish)
pcapanalyzer -path capture.pcap -des "Flag ve kimlik bilgilerini bul" -lang tr

# Deutsch (German)
pcapanalyzer -path capture.pcap -des "Finde die Anmeldedaten im Datenverkehr" -lang de

# Русский (Russian)
pcapanalyzer -path capture.pcap -des "Найти пароли и флаг" -lang ru
```

Supported languages: `eng`, `tr`, `de`, `ru`, `fr`, `es`, `ar`, `zh`, `ja`, `it`, `pt`, `ko`, `nl`, `pl`, `sv`.

---

### 4. Binary Intelligence Tool (`pcapbib`)
Analyzes hex dumps, raw binaries, Cisco router configs, SIP traces, and logs:
```bash
# General analysis
pcapbib -i dump.txt --hex --ascii --creds

# Cisco config decryption (Type 7 passwords + MD5 hashes)
pcapbib -i cisco.cfg --cisco --hashes --ioc

# CTF binary analysis & file carving
pcapbib -i challenge.bin --carve --flags --b64 -lang tr

# SIP/VoIP authentication audit
pcapbib -i sip.log --creds --hashes --proto
```

---

### 3. Local AI Mode (Offline)
```bash
pcapmg -localai MODEL_NAME -path "capture.pcap" -des "Task description"
```

Requires [Ollama](https://ollama.ai) to be running:
```bash
ollama serve
ollama pull llama3   # or mistral, gemma2, etc.
```

---

## Examples

### CTF — SSL/HTTP Exchange
```bash
pcapanalyzer -path ssl_exchange.pcap \
  -f "ssl or http" \
  -des "Solve the Root-Me SSL HTTP exchange CTF. Find the flag hidden in SSL/HTTP traffic."
```

### Network Security Audit
```bash
pcapanalyzer -path network_capture.pcap \
  -des "Full network security audit. Identify threats, anomalies, unauthorized access attempts."
```

### DNS Exfiltration Check
```bash
pcapanalyzer -path traffic.pcap \
  -f "dns" \
  -des "Check for DNS tunneling or data exfiltration via DNS queries."
```

### Local AI — Offline CTF Solving
```bash
pcapmg -localai llama3 \
  -path ctf_challenge.pcap \
  -des "Find the hidden flag in HTTP traffic"
```

### Custom PDF Output
```bash
pcapanalyzer -path capture.pcap \
  -des "Intrusion analysis" \
  -o /home/kali/reports/my_report.pdf
```

---

## Terminal Output

- 🔴 **KEY PACKETS** — Red background, the packet(s) that contain the answer
- 🟡 **Yellow text** — Important field values (passwords, hashes, flags, certs)
- 🔵 **Cyan badge** — Protocol identifier
- 📄 Each packet displayed as a single descriptive line

---

## PDF Report

Each analysis generates a professional PDF report containing:
- Cover page with metadata and threat level
- Packet analysis table (key packets highlighted in red)
- Executive summary
- Detailed analysis
- Key findings & highlighted values
- Security recommendations
- CTF flag/answer (if applicable)

---

## Configuration

Config file: `~/.pcapanalyzer/config.json`

```json
{
  "gemini_api_key": "YOUR_KEY_HERE",
  "local_ai_model": "llama3"
}
```

Environment variable override:
```bash
export GEMINI_API_KEY="your_key"
```

---

## Dependencies

| Dependency | Purpose |
|------------|---------|
| `tshark` | Deep packet parsing (Wireshark CLI) |
| `scapy` | Fallback packet parser |
| `google-generativeai` | Gemini API client |
| `reportlab` | PDF generation |
| `requests` | Ollama API communication |
| `ollama` | Local AI inference (optional) |

---

## Architecture

```
pcap-analyzer/
├── core/
│   ├── cli.py        ← Entry points (pcapanalyzer / pcapmg)
│   ├── parser.py     ← PCAP reader (tshark + scapy fallback)
│   ├── analyzer.py   ← AI bridge (Gemini + Ollama)
│   ├── renderer.py   ← Terminal color output
│   ├── reporter.py   ← PDF report generator
│   └── config.py     ← API key management
├── install.sh        ← Kali Linux installer
└── pyproject.toml    ← Package metadata
```

---

*PCAP ANALYZER v2.0 — VCAS.PRIVATE × QNTSOFTWARE*
