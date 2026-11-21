<div align="center">

# PCAP ANALYZER

### AI-Powered Network Intelligence & Security Analysis Platform

**Deep packet inspection, binary forensics, and LLM reasoning — fully offline or cloud-powered.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20WSL-557C94?logo=linux&logoColor=white)](#installation)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](#dependencies)
[![Stars](https://img.shields.io/github/stars/qntsoftware/Pcap-Analyzer?style=social)](https://github.com/qntsoftware/Pcap-Analyzer/stargazers)

**Developed by [VCAS.PRIVATE](https://www.youtube.com/@vcas.private) × [QNTSOFTWARE](https://github.com/qntsoftware)**

[Installation](#-installation) • [Commands](#-three-tools-one-platform) • [No-AI Engine](#-no-ai-deep-heuristic-engine) • [pcapbib](#-pcapbib--binary--file-intelligence) • [Architecture](#-architecture)

</div>

---

[![PCAP ANALYZER Demo](https://img.youtube.com/vi/hMsXwUo6DLg/hqdefault.jpg)](https://www.youtube.com/watch?v=hMsXwUo6DLg)

##  Overview

**PCAP ANALYZER** is a command-line network forensics platform for Kali Linux (and WSL) that combines `tshark`/`scapy`-based deep packet inspection with LLM reasoning. It ships as **three tools**:

| Command | Purpose |
|---|---|
| `pcapanalyzer` | Main engine — Gemini API analysis, or fully offline No-AI heuristic mode |
| `pcapmg` | Same engine, powered by a **local Ollama model** instead of the cloud |
| `pcapbib` | Standalone binary/hex-dump/config intelligence tool — 20 analysis engines |

Every AI-backed analysis is guided by **CIPHER**, a WCNA/GNFA-level analyst persona (`core/persona/expert_analyst.md`) that is automatically injected into every prompt — it enforces a fixed methodology (overview → protocol filtering → flag hunting → stream reassembly) instead of letting the model free-associate over your capture.

---

##  Features

-  **Dual-engine packet parsing** — `tshark` primary, `scapy` fallback, full `frame.protocols` chain resolution
- **Three AI backends** — Google Gemini API, local Ollama models, or a 100%-deterministic No-AI heuristic engine
-  **CTF-tuned prompt engine** — auto-detects the relevant protocol from your task description and pre-filters accordingly
-  **`pcapbib`** — 20 standalone engines for hex dumps, Cisco configs, SIP logs, file carving, and steganography checks
-  **Complete port intelligence** — a 0–65,535 port database tagged `STANDARD / SECURE / RISKY / MALWARE / ADMIN / VOIP / GAME / DATABASE / INDUSTRIAL`
-  **Professional PDF & JSON reports** — threat level, key packets, IOCs, credentials, recommendations
-  **15 output languages** — `eng tr de ru fr es ar zh ja it pt ko nl pl sv`
-  **Color-coded terminal output** — key packets in red, sensitive values in yellow, protocols in cyan

---

## 📦 Installation

```bash
git clone https://github.com/qntsoftware/Pcap-Analyzer.git
cd Pcap-Analyzer
chmod +x install.sh
sudo ./install.sh
```

This installs to `/opt/pcapanalyzer`, creates a dedicated virtualenv, and exposes `pcapanalyzer` / `pcapmg` globally via `/usr/local/bin`.

<details>
<summary>📋 Requirements</summary>

- Kali Linux or any Debian-based distro (`apt`-based) with `tshark` installable
- Python 3.10+
- [Ollama](https://ollama.ai) — only if you plan to use local AI mode (`pcapmg -localai ...`)

</details>

<details>
<summary>🪟 WSL setup</summary>

`wsl_install.sh` mirrors `install.sh` for a WSL/Debian environment and additionally wires up `pcapbib`. `wsl_update.sh` is a dev-loop script that re-syncs `core/` and the CIPHER persona file and runs a quick smoke test.

> ⚠️ Both scripts currently hardcode a Windows source path (`/mnt/c/Users/<username>/...`). Parameterize this (e.g. via an environment variable or a CLI argument) before relying on them outside your own machine — and double-check it isn't something you want committed publicly as-is.

</details>

---

## 🚀 Three Tools, One Platform

### 1 · `pcapanalyzer` — Gemini-powered analysis

```bash
# One-time setup
pcapanalyzer -api YOUR_GEMINI_API_KEY

# Analyze
pcapanalyzer -path "capture.pcap" -des "Find the flag in the SSL/HTTP exchange" -lang tr
```

| Flag | Description |
|---|---|
| `-path` | Path to `.pcap` / `.pcapng` |
| `-f` | Wireshark display filter (e.g. `http`, `ssl`, `tcp.port==443`) |
| `-des` | Task description — drives both protocol auto-detection and the AI prompt |
| `-lang` | `eng tr de ru fr es ar zh ja it pt ko nl pl sv` (or `help` to list) |
| `-o` | Custom PDF output path |
| `--no-pdf` | Skip PDF generation |
| `--no-ai` | Switch to the deterministic [No-AI engine](#-no-ai-deep-heuristic-engine) |

### 2 · `pcapmg` — fully offline, local AI

```bash
ollama serve
ollama pull llama3          # or mistral, gemma2, qwen2.5...

pcapmg -localai llama3 -path "capture.pcap" -des "Audit network for intrusion" -lang eng
```

Same flag set as `pcapanalyzer`, plus `-localai <model>`. No API key, no outbound traffic — useful for air-gapped labs or sensitive captures.

---

## 🧮 No-AI Deep Heuristic Engine

Both `pcapanalyzer` and `pcapmg` support `--no-ai`: a fully deterministic analysis pass with no LLM call at all — useful for reproducible audits or when you simply don't want a capture leaving the machine.

```bash
pcapanalyzer -path traffic.pcap --no-ai --only-malware --ports --timing --json
```

**Filtering**
| Flag | Effect |
|---|---|
| `--only-risky` | Only packets on known risky ports |
| `--only-malware` | Only packets in the `MALWARE`/`C2` port category |
| `--only-external` | Only packets touching a non-private IP |
| `--min-size` / `--max-size` | Packet length bounds |
| `--proto <name>` | Filter by protocol/service name |
| `--src-ip` / `--dst-ip` | Substring match on address |
| `--port <n>` | Exact port match (src or dst) |
| `--min-ttl` / `--max-ttl` | TTL bounds (OS/hop-count triage) |
| `--top <n>` | Cap output to first N packets |

**Display & export**
| Flag | Effect |
|---|---|
| `--convs` | Top TCP conversation endpoints |
| `--dns` | DNS queries + tunnel-detection heuristics |
| `--ports` | Full port/service usage breakdown |
| `--hosts` | Top talkers / top destinations |
| `--timing` | Inter-arrival timing & C2 beaconing analysis |
| `--ics` | ICS/SCADA industrial protocol activity |
| `--crypto` | Cryptocurrency/blockchain traffic signatures |
| `--vpn` | VPN/tunnel detection (IPSec, OpenVPN, WireGuard) |
| `--compact` | One line per packet |
| `--json` [`--json-path`] | Structured JSON export |

---

## 🗂️ `pcapbib` — Binary & File Intelligence

A standalone tool for everything that isn't a live capture: hex dumps, raw binaries, Cisco/router configs, SIP logs, memory dumps. **20 independent analysis engines**, toggled individually or all at once with `--all`.

```bash
pcapbib -i dump.txt --hex --b64 --creds -lang tr              # hex dump + credential harvest
pcapbib -i cisco.cfg --cisco --hashes --ioc --pdf             # Type 7 decrypt + hash ID + PDF report
pcapbib -i challenge.bin --carve --flags --b64 --entropy       # CTF binary triage
pcapbib -i sip.log --creds --hashes --proto -lang ru           # SIP/VoIP auth audit
pcapbib -i memory.dmp --search "password" --ctx 4              # custom regex hunt with context
pcapbib -i sample.bin --all --ai-local llama3 --ai-task "Full security audit"
```

| Engine | What it does |
|---|---|
| `--hex` | Reconstruct network layers from a Wireshark hex dump |
| `--ascii` / `--strings` | Extract printable strings (`--min-str`, `--max-str`) |
| `--b64` | Detect & decode Base64 streams |
| `--creds` | Harvest usernames, passwords, tokens, API keys |
| `--hashes` | Identify MD5/SHA1/256/512, NTLM, bcrypt, Cisco hash formats |
| `--cisco` | Decrypt Cisco Type 7 reversible-XOR passwords |
| `--ioc` | Extract IPv4/IPv6/domains/URLs |
| `--carve` | Recover embedded PNG/JPEG/PDF/ZIP/ELF/PE from raw bytes |
| `--entropy` | Shannon entropy — flags packed/encrypted blobs |
| `--magic` | True file-type detection via magic-byte signatures |
| `--proto` | Protocol signature ID (FTP, HTTP, SIP, SMTP, SSH, Cisco, BGP...) |
| `--flags` | CTF flag-format hunting (`FLAG{...}`, `Root-Me{...}`, custom via `--flag-format`) |
| `--steg` | Steganography checks (PNG LSB, JPEG markers) |
| `--search` / `--search-hex` | Custom regex or raw hex-byte search, with `--ctx` context lines |
| `--all` | Every engine above, in one pass |

Output as colored terminal report, `--json`, or an executive `--pdf`. Optional AI interpretation layer via `--ai-api` (Gemini) or `--ai-local` (Ollama) + `--ai-task "<description>"`, which feeds the same CIPHER persona plus the engine's findings back into the model for a narrative read.

---

## 🖥️ Terminal Output & PDF Reports

| Marker | Meaning |
|---|---|
| 🔴 Red background | **Key packet** — contains the answer/flag |
| 🟡 Yellow text | Sensitive values (passwords, hashes, flags, certs) |
| 🔵 Cyan badge | Protocol identifier |

Every analysis (AI, No-AI, and `pcapbib`) can generate a report with cover metadata, a highlighted packet/finding table, executive summary, detailed analysis, security recommendations, and — for CTF tasks — the extracted flag.

---

## ⚙️ Configuration

`~/.pcapanalyzer/config.json`:
```json
{
  "gemini_api_key": "YOUR_KEY_HERE",
  "local_ai_model": "llama3"
}
```
Or override via environment: `export GEMINI_API_KEY="your_key"` (env takes priority over the config file).

---

## 🧩 Dependencies

| Dependency | Purpose |
|---|---|
| `tshark` | Deep packet parsing (Wireshark CLI) |
| `scapy` | Fallback packet parser |
| `google-generativeai` | Gemini API client |
| `reportlab` | PDF generation |
| `requests` | Ollama API communication |
| `ollama` | Local AI inference (optional) |

---

## 🧱 Architecture

```
pcap-analyzer/
├── core/
│   ├── cli.py            ← Entry points: pcapanalyzer_main / pcapmg_main
│   ├── bib.py             ← pcapbib — 20-engine binary/file intelligence tool
│   ├── parser.py          ← PCAP reader (tshark + scapy fallback), Packet dataclass
│   ├── ports.py           ← Full 0–65,535 port/service/category database
│   ├── analyzer.py        ← Gemini + Ollama AI bridge, response parsing/merging
│   ├── prompt_engine.py   ← Protocol auto-detection, smart prompt construction
│   ├── noai.py            ← Deterministic heuristic analysis engine
│   ├── renderer.py        ← Terminal color/output rendering
│   ├── reporter.py        ← PDF report generation (AI + No-AI + pcapbib)
│   ├── lang.py            ← 15-language localization layer
│   ├── config.py          ← API key / local model persistence
│   └── persona/
│       └── expert_analyst.md  ← CIPHER — the analyst persona injected into every AI prompt
├── install.sh             ← Kali Linux system installer
├── wsl_install.sh         ← WSL installer
├── wsl_update.sh          ← WSL dev-sync & smoke-test script
└── pyproject.toml         ← Package metadata (pcapanalyzer / pcapmg / pcapbib entry points)
```

---

## 🗺️ Roadmap

- [ ] Web-based report viewer
- [ ] STIX/IOC export for SIEM integration
- [ ] Multi-file batch analysis for `pcapbib`
- [ ] Plugin system for custom protocol decoders

> Have an idea? [Open an issue](https://github.com/qntsoftware/Pcap-Analyzer/issues).

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-thing`)
3. Commit your changes
4. Open a pull request

## 📜 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

---

<div align="center">

**If this tool saved you time in a CTF or an audit, a ⭐ genuinely helps the project reach more people.**

*PCAP ANALYZER v3.0 — VCAS.PRIVATE × QNTSOFTWARE*

</div>
