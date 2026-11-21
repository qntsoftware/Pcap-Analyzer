#!/usr/bin/env bash

set -euo pipefail

C_RESET='\033[0m'
C_CYAN='\033[96m'
C_GREEN='\033[92m'
C_YELLOW='\033[93m'
C_RED='\033[91m'
C_BOLD='\033[1m'
C_GREY='\033[90m'

TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/pcapanalyzer"
BIN_DIR="/usr/local/bin"
PYTHON_MIN="3.10"

echo -e "${C_CYAN}${C_BOLD}"
cat << 'EOF'
 ██████╗  ██████╗ █████╗ ██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
 ██╔══██╗██╔════╝██╔══██╗██╔══██╗    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
 ██████╔╝██║     ███████║██████╔╝    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
 ██╔═══╝ ██║     ██╔══██║██╔═══╝     ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
 ██║     ╚██████╗██║  ██║██║         ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
 ╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝         ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
EOF
echo -e "${C_RESET}"
echo -e "${C_GREY}  VCAS.PRIVATE × QNTSOFTWARE — Network Intelligence Platform${C_RESET}"
echo -e "${C_GREY}  ──────────────────────────────────────────────────────────${C_RESET}\n"

log_info()    { echo -e "  ${C_CYAN}[*]${C_RESET} $1"; }
log_ok()      { echo -e "  ${C_GREEN}[✔]${C_RESET} $1"; }
log_warn()    { echo -e "  ${C_YELLOW}[!]${C_RESET} $1"; }
log_error()   { echo -e "  ${C_RED}[✘] ERROR: $1${C_RESET}"; exit 1; }
log_section() { echo -e "\n  ${C_BOLD}${C_CYAN}── $1 ──${C_RESET}"; }

if [[ $EUID -ne 0 ]]; then
    log_error "Please run as root: sudo ./install.sh"
fi

if [[ ! -f /etc/os-release ]]; then
    log_warn "Cannot detect OS. Proceeding anyway."
else
    . /etc/os-release
    log_info "Detected OS: ${PRETTY_NAME}"
fi

log_section "PYTHON"
PYTHON_BIN=$(command -v python3 2>/dev/null || true)
if [[ -z "$PYTHON_BIN" ]]; then
    log_error "Python 3 not found. Install it first: apt-get install python3"
fi

PY_VER=$("$PYTHON_BIN" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
log_info "Python version: $PY_VER"

if python3 -c "import sys; exit(0 if sys.version_info >= (3,10) else 1)"; then
    log_ok "Python $PY_VER is compatible."
else
    log_error "Python 3.10+ required. Found $PY_VER"
fi

log_section "SYSTEM DEPENDENCIES"
log_info "Updating package list..."
apt-get update -qq

PKGS_TO_INSTALL=()
for pkg in tshark python3-pip python3-venv; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        PKGS_TO_INSTALL+=("$pkg")
    else
        log_ok "$pkg already installed"
    fi
done

if [[ ${#PKGS_TO_INSTALL[@]} -gt 0 ]]; then
    log_info "Installing: ${PKGS_TO_INSTALL[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${PKGS_TO_INSTALL[@]}" -qq
    log_ok "System packages installed."
fi

log_section "INSTALLATION"
log_info "Installing to: $INSTALL_DIR"

if [[ -d "$INSTALL_DIR" ]]; then
    log_warn "Previous installation found, removing..."
    rm -rf "$INSTALL_DIR"
fi

mkdir -p "$INSTALL_DIR"
cp -r "$TOOL_DIR/." "$INSTALL_DIR/"
log_ok "Files copied to $INSTALL_DIR"

log_section "PYTHON ENVIRONMENT"
log_info "Creating virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
VENV_PIP="$INSTALL_DIR/venv/bin/pip"
log_ok "Virtualenv created."

log_info "Installing Python packages..."
"$VENV_PIP" install --quiet --upgrade pip wheel

"$VENV_PIP" install --quiet \
    "google-generativeai>=0.8.0" \
    "scapy>=2.5.0" \
    "reportlab>=4.2.0" \
    "requests>=2.31.0" \
    "rich>=13.0.0"

log_ok "Python packages installed."


log_section "CREATING COMMANDS"

cat > "$BIN_DIR/pcapanalyzer" << LAUNCHER
#!/usr/bin/env bash
exec "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/run_pcapanalyzer.py" "\$@"
LAUNCHER

cat > "$BIN_DIR/pcapmg" << LAUNCHER
#!/usr/bin/env bash
exec "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/run_pcapmg.py" "\$@"
LAUNCHER

chmod +x "$BIN_DIR/pcapanalyzer" "$BIN_DIR/pcapmg"
log_ok "Commands created: pcapanalyzer, pcapmg"

cat > "$INSTALL_DIR/run_pcapanalyzer.py" << 'PYMOD'
import sys
sys.path.insert(0, "/opt/pcapanalyzer")
from core.cli import pcapanalyzer_main
if __name__ == "__main__":
    pcapanalyzer_main()
PYMOD

cat > "$INSTALL_DIR/run_pcapmg.py" << 'PYMOD'
import sys
sys.path.insert(0, "/opt/pcapanalyzer")
from core.cli import pcapmg_main
if __name__ == "__main__":
    pcapmg_main()
PYMOD

log_section "PERMISSIONS"
chown -R root:root "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

log_ok "Permissions set."

log_section "VERIFICATION"
if command -v pcapanalyzer &>/dev/null && command -v pcapmg &>/dev/null; then
    log_ok "pcapanalyzer → $(which pcapanalyzer)"
    log_ok "pcapmg       → $(which pcapmg)"
else
    log_warn "Commands not found in PATH. Try opening a new terminal."
fi

echo ""
echo -e "${C_GREEN}${C_BOLD}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║   PCAP ANALYZER installed successfully! ✔            ║"
echo "  ║   VCAS.PRIVATE × QNTSOFTWARE                        ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${C_RESET}"
echo -e "  ${C_CYAN}Quick Start:${C_RESET}"
echo -e "  ${C_GREY}1. Set API key :${C_RESET}  pcapanalyzer -api YOUR_GEMINI_API_KEY"
echo -e "  ${C_GREY}2. Analyze PCAP:${C_RESET}  pcapanalyzer -path capture.pcap -des \"Find the flag\""
echo -e "  ${C_GREY}3. Local AI    :${C_RESET}  pcapmg -localai llama3 -path capture.pcap -des \"Audit network\""
echo -e "  ${C_GREY}4. With filter :${C_RESET}  pcapanalyzer -path capture.pcap -f \"http\" -des \"Analyze HTTP\""
echo ""
echo -e "  ${C_GREY}Docs: /opt/pcapanalyzer/README.md${C_RESET}"
echo ""
