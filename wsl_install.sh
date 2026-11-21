#!/usr/bin/env bash

set -e

C_RESET='\033[0m'
C_CYAN='\033[96m'
C_GREEN='\033[92m'
C_YELLOW='\033[93m'
C_RED='\033[91m'
C_BOLD='\033[1m'
C_GREY='\033[90m'

WIN_SRC="/mnt/c/Users/efdee/OneDrive/Desktop/pcap analyzer"
DEST="/opt/pcapanalyzer"
BIN="/usr/local/bin"

log_info()  { echo -e "  ${C_CYAN}[*]${C_RESET} $1"; }
log_ok()    { echo -e "  ${C_GREEN}[✔]${C_RESET} $1"; }
log_warn()  { echo -e "  ${C_YELLOW}[!]${C_RESET} $1"; }
log_err()   { echo -e "  ${C_RED}[✘] $1${C_RESET}"; exit 1; }
log_step()  { echo -e "\n${C_CYAN}${C_BOLD}── $1 ──${C_RESET}"; }

echo -e "${C_CYAN}${C_BOLD}"
cat << 'BANNER'
 ██████╗  ██████╗ █████╗ ██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
 ██╔══██╗██╔════╝██╔══██╗██╔══██╗    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
 ██████╔╝██║     ███████║██████╔╝    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
 ██╔═══╝ ██║     ██╔══██║██╔═══╝     ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
 ██║     ╚██████╗██║  ██║██║         ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
 ╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝         ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
BANNER
echo -e "${C_RESET}"
echo -e "  ${C_GREY}VCAS.PRIVATE × QNTSOFTWARE — WSL Installer${C_RESET}\n"

if [[ $EUID -ne 0 ]]; then
    log_err "Root gerekli: sudo bash wsl_install.sh"
fi

log_step "PYTHON KONTROLÜ"
PYTHON=$(command -v python3 || true)
[[ -z "$PYTHON" ]] && log_err "python3 bulunamadı"
PY_VER=$($PYTHON --version 2>&1)
log_ok "$PY_VER"

log_step "TSHARK"
if command -v tshark &>/dev/null; then
    log_ok "tshark: $(tshark --version 2>&1 | head -1)"
else
    log_info "tshark kuruluyor..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark -qq
    log_ok "tshark kuruldu"
fi

log_step "DOSYALAR KOPYALANIYOR"
if [[ ! -d "$WIN_SRC" ]]; then
    log_err "Kaynak dizin bulunamadı: $WIN_SRC"
fi
[[ -d "$DEST" ]] && { log_warn "Önceki kurulum siliniyor..."; rm -rf "$DEST"; }
mkdir -p "$DEST"
cp -r "$WIN_SRC/." "$DEST/"
log_ok "Dosyalar → $DEST"

log_step "PYTHON ORTAMI"
python3 -m venv "$DEST/venv" 2>/dev/null || {
    apt-get install -y python3-venv -qq
    python3 -m venv "$DEST/venv"
}
log_ok "venv oluşturuldu"

log_info "pip güncelleniyor..."
"$DEST/venv/bin/pip" install --quiet --upgrade pip wheel

log_info "Paketler kuruluyor (google-generativeai, scapy, reportlab, requests)..."
"$DEST/venv/bin/pip" install --quiet \
    "google-generativeai>=0.8.0" \
    "scapy>=2.5.0" \
    "reportlab>=4.2.0" \
    "requests>=2.31.0"
log_ok "Python paketleri kuruldu"

log_step "LAUNCHER SCRIPTLER"

cat > "$DEST/run_pcapanalyzer.py" << 'PYEOF'
import sys
sys.path.insert(0, '/opt/pcapanalyzer')
from core.cli import pcapanalyzer_main
if __name__ == '__main__':
    pcapanalyzer_main()
PYEOF

cat > "$DEST/run_pcapmg.py" << 'PYEOF'
import sys
sys.path.insert(0, '/opt/pcapanalyzer')
from core.cli import pcapmg_main
if __name__ == '__main__':
    pcapmg_main()
PYEOF

cat > "$DEST/run_pcapbib.py" << 'PYEOF'
import sys
sys.path.insert(0, '/opt/pcapanalyzer')
from core.bib import pcapbib_main
if __name__ == '__main__':
    pcapbib_main()
PYEOF

cat > "$BIN/pcapanalyzer" << BINEOF
#!/usr/bin/env bash
exec /opt/pcapanalyzer/venv/bin/python /opt/pcapanalyzer/run_pcapanalyzer.py "\$@"
BINEOF

cat > "$BIN/pcapmg" << BINEOF
#!/usr/bin/env bash
exec /opt/pcapanalyzer/venv/bin/python /opt/pcapanalyzer/run_pcapmg.py "\$@"
BINEOF

cat > "$BIN/pcapbib" << BINEOF
#!/usr/bin/env bash
exec /opt/pcapanalyzer/venv/bin/python /opt/pcapanalyzer/run_pcapbib.py "\$@"
BINEOF

chmod +x "$BIN/pcapanalyzer" "$BIN/pcapmg" "$BIN/pcapbib"
chmod -R 755 "$DEST"
log_ok "Komutlar oluşturuldu: pcapanalyzer, pcapmg, pcapbib"

log_step "DOĞRULAMA"
pcapanalyzer --help > /dev/null 2>&1 && log_ok "pcapanalyzer → OK" || log_warn "pcapanalyzer test başarısız"
pcapmg --help > /dev/null 2>&1 && log_ok "pcapmg       → OK" || log_warn "pcapmg test başarısız"

echo ""
echo -e "${C_GREEN}${C_BOLD}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║   PCAP ANALYZER kurulumu başarıyla tamamlandı! ✔    ║"
echo "  ║   VCAS.PRIVATE × QNTSOFTWARE                        ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${C_RESET}"
echo -e "  ${C_CYAN}Hızlı Başlangıç:${C_RESET}"
echo -e "  ${C_GREY}API key kaydet :${C_RESET}  pcapanalyzer -api GEMINI_KEY"
echo -e "  ${C_GREY}PCAP analiz    :${C_RESET}  pcapanalyzer -path dosya.pcap -des 'Açıklama'"
echo -e "  ${C_GREY}Filtreli analiz:${C_RESET}  pcapanalyzer -path dosya.pcap -f 'http' -des 'HTTP analizi'"
echo -e "  ${C_GREY}Local AI       :${C_RESET}  pcapmg -localai llama3 -path dosya.pcap -des 'Analiz et'"
echo ""
