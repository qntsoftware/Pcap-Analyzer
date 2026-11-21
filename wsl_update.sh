#!/usr/bin/env bash
# WSL update & test script

set -e

DEST="/opt/pcapanalyzer"
BIN="/usr/local/bin"
WIN_SRC="/mnt/c/Users/efdee/OneDrive/Desktop/pcap analyzer"

echo "[1/5] Core dosyalar kopyalanıyor..."
cp -r "$WIN_SRC/core/." "$DEST/core/"
mkdir -p "$DEST/core/persona"
cp "$WIN_SRC/core/persona/expert_analyst.md" "$DEST/core/persona/"
echo "      OK"

echo "[2/5] pcapbib launcher oluşturuluyor..."
cat > "$DEST/run_pcapbib.py" << 'PYEOF'
import sys
sys.path.insert(0, '/opt/pcapanalyzer')
from core.bib import pcapbib_main
if __name__ == '__main__':
    pcapbib_main()
PYEOF

cat > "$BIN/pcapbib" << 'BINEOF'
#!/usr/bin/env bash
exec /opt/pcapanalyzer/venv/bin/python /opt/pcapanalyzer/run_pcapbib.py "$@"
BINEOF
chmod +x "$BIN/pcapbib" "$DEST/run_pcapbib.py"
echo "      OK"

echo "[3/5] Syntax & Multilingual test..."
"$DEST/venv/bin/python" -c "
import sys
sys.path.insert(0, '/opt/pcapanalyzer')
from core.bib import pcapbib_main
from core.prompt_engine import detect_protocol_from_description
from core.cli import pcapanalyzer_main, pcapmg_main
from core.lang import set_lang, L, get_ai_language_instruction
print('  pcapanalyzer : OK')
print('  pcapmg       : OK')
print('  pcapbib      : OK')
print('  prompt_engine: OK')
print('  lang module  : OK')
set_lang('tr')
print('  [TR] ', L('total_packets'))
set_lang('de')
print('  [DE] ', L('total_packets'))
set_lang('ru')
print('  [RU] ', L('total_packets'))
set_lang('eng')
print('  [ENG]', L('total_packets'))
"

echo "[4/5] Protokol tespit testi..."
"$DEST/venv/bin/python" << 'PYEOF'
import sys
sys.path.insert(0, '/opt/pcapanalyzer')
from core.prompt_engine import detect_protocol_from_description

tests = [
    "FTP auth ile alakali ctf testindeki cevabi ara",
    "SSL HTTP exchange CTF coz",
    "DNS tunel kontrolu yap",
    "SSH brute force tespiti",
    "SIP voip saldiri analizi",
    "SMB NTLM hash yakala",
    "Genel ag analizi",
]
for desc in tests:
    proto, filt = detect_protocol_from_description(desc)
    print(f"  '{desc[:40]}'")
    print(f"    => Protokol: {proto} | Filtre: {filt}")
PYEOF

echo "[5/5] pcapbib test..."
echo 'username admin password 7 10181A325528130F010D24' > /tmp/test_cisco.txt
echo 'username hub password 7 025017705B3907344E' >> /tmp/test_cisco.txt
echo 'enable secret 5 $1$p8Y6$MCdRLBzuGlfOs9S.hXOp0.' >> /tmp/test_cisco.txt
echo 'Authorization: Basic YWRtaW46YWRtaW4=' >> /tmp/test_cisco.txt
echo '172.25.105.3"172.25.105.40"555"asterisk"REGISTER"sip:172.25.105.40"4787f7ce""PLAIN"1234' >> /tmp/test_cisco.txt

pcapbib -i /tmp/test_cisco.txt --cisco --b64 --creds --hashes --ioc 2>&1

echo ""
echo "=============================="
echo "  KURULUM GUNCELLEMESI TAMAM"
echo "  Komutlar: pcapanalyzer / pcapmg / pcapbib"
echo "=============================="
