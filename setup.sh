#!/usr/bin/env bash
# Excalibull — instalador das ferramentas de recon (multi-OS)
# Rode UMA vez:  bash setup.sh
# Detecta o sistema operacional e instala Go + o toolchain de recon.
# Depois, recon.py / "code 0" usam todas automaticamente.
set -uo pipefail

echo "== Excalibull setup =="

# ---------------------------------------------------------------------------
# 1) Detectar SO e gerenciador de pacotes
# ---------------------------------------------------------------------------
OS="$(uname -s)"
PKG=""          # comando de install do gerenciador detectado
PKG_NAME=""     # nome amigável

detect_pkg() {
  case "$OS" in
    Darwin)
      if command -v brew >/dev/null 2>&1; then
        PKG="brew install"; PKG_NAME="Homebrew"
      else
        echo "[!] macOS sem Homebrew. Instale em https://brew.sh e rode de novo."; exit 1
      fi ;;
    Linux)
      if   command -v apt   >/dev/null 2>&1; then PKG="sudo apt install -y";           PKG_NAME="apt"
      elif command -v dnf   >/dev/null 2>&1; then PKG="sudo dnf install -y";           PKG_NAME="dnf"
      elif command -v pacman>/dev/null 2>&1; then PKG="sudo pacman -S --noconfirm";    PKG_NAME="pacman"
      elif command -v zypper>/dev/null 2>&1; then PKG="sudo zypper install -y";        PKG_NAME="zypper"
      elif command -v apk   >/dev/null 2>&1; then PKG="sudo apk add";                  PKG_NAME="apk"
      else echo "[!] Linux sem apt/dnf/pacman/zypper/apk. Instale Go manualmente: https://go.dev/dl/"; exit 1
      fi ;;
    *)
      echo "[!] SO não suportado automaticamente ($OS). Instale Go manualmente: https://go.dev/dl/"; exit 1 ;;
  esac
  echo "[*] SO: $OS · gerenciador: $PKG_NAME"
}

detect_pkg

# nome do pacote Go varia por gerenciador
go_pkg_name() {
  case "$PKG_NAME" in
    apt|zypper) echo "golang-go" ;;
    dnf|pacman|apk) echo "go" ;;
    Homebrew)   echo "go" ;;
    *)          echo "go" ;;
  esac
}

# ---------------------------------------------------------------------------
# 2) Go
# ---------------------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
  echo "[*] instalando Go via $PKG_NAME..."
  # shellcheck disable=SC2086
  $PKG "$(go_pkg_name)" || { echo "[!] falha ao instalar Go. Instale manualmente: https://go.dev/dl/"; exit 1; }
fi

# 3) PATH do go/bin
GOBIN="$(go env GOPATH 2>/dev/null)/bin"
export PATH="$PATH:$GOBIN"

# ---------------------------------------------------------------------------
# 4) ProjectDiscovery + tomnomnom/lc suite (cross-platform via go install)
# ---------------------------------------------------------------------------
echo "[*] instalando ferramentas Go (pode demorar)..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/jaeles-project/gospider@latest
go install -v github.com/tomnomnom/gf@latest

# 5) ffuf (content discovery) — brew tem pacote; no Linux via go install
if ! command -v ffuf >/dev/null 2>&1; then
  if [ "$PKG_NAME" = "Homebrew" ]; then brew install ffuf; else go install -v github.com/ffuf/ffuf/v2@latest; fi
fi

# 6) gf patterns (xss, ssrf, idor, redirect, ssti, sqli...)
if [ ! -d "$HOME/.gf" ]; then
  git clone -q https://github.com/1ndianl33t/Gf-Patterns "$HOME/.gf" 2>/dev/null \
    || { git clone -q https://github.com/tomnomnom/gf "$HOME/.gf-src" 2>/dev/null && mkdir -p "$HOME/.gf" && cp "$HOME/.gf-src"/examples/*.json "$HOME/.gf/" 2>/dev/null; }
  echo "[*] gf patterns em ~/.gf"
fi

# 7) templates do nuclei
command -v nuclei >/dev/null 2>&1 && nuclei -update-templates -silent 2>/dev/null || true

# 8) dependências Python
python3 -m pip install --quiet --user requests pyyaml 2>/dev/null || pip3 install --quiet requests pyyaml 2>/dev/null || true
# opcional: resolve_doh.py usa curl_cffi (impersona Chrome no DNS-over-HTTPS)
python3 -m pip install --quiet --user curl_cffi 2>/dev/null || true

# ---------------------------------------------------------------------------
# 8.5) Ferramentas de mineração web/mobile (jsrecon.py / apkrecon.py)
# ---------------------------------------------------------------------------
# jsrecon.py: stdlib puro (urllib/re) — nenhuma dependência a instalar.
# apkrecon.py: funciona só com stdlib + `strings`/`unzip`, MAS enriquece muito com
#   aapt/apktool/jadx (AndroidManifest binário → deep-links, componentes exported) e
#   adb (adb pull do APK de um device). apkeep = baixador de APK (APKPure/Play/F-Droid).
# Tudo best-effort: se faltar, o apkrecon degrada com aviso, não quebra.
echo "[*] ferramentas web/mobile (apkrecon): instalando aapt/apktool/jadx/adb (opcional)..."
pkg_try() {  # tenta cada nome candidato; nunca falha o script
  for name in "$@"; do
    # shellcheck disable=SC2086
    $PKG "$name" >/dev/null 2>&1 && return 0
  done
  return 1
}
# strings/unzip: base (binutils/unzip)
command -v strings >/dev/null 2>&1 || pkg_try binutils || true
command -v unzip   >/dev/null 2>&1 || pkg_try unzip || true
# adb (adb pull do APK instalado)
command -v adb >/dev/null 2>&1 || pkg_try android-tools-adb android-tools platform-tools android-platform-tools || true
# apktool + aapt (AndroidManifest binário → xmltree)
command -v apktool >/dev/null 2>&1 || pkg_try apktool android-apktool || true
command -v aapt    >/dev/null 2>&1 || command -v aapt2 >/dev/null 2>&1 || pkg_try aapt android-sdk-build-tools android-tools || true
# jadx (decompilação Java opcional p/ análise profunda)
command -v jadx >/dev/null 2>&1 || pkg_try jadx || true
# apkeep: baixador de APK que contorna mirrors (via cargo, se houver Rust)
if ! command -v apkeep >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1; then
  echo "[*] instalando apkeep via cargo (baixador de APK)..."; cargo install apkeep >/dev/null 2>&1 || true
fi

# 9) garantir go/bin no PATH do shell
case "${SHELL:-}" in
  *zsh) SHELL_RC="$HOME/.zshrc" ;;
  *)    SHELL_RC="$HOME/.bashrc" ;;
esac
if ! grep -qs 'go env GOPATH' "$SHELL_RC" 2>/dev/null; then
  echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> "$SHELL_RC"
  echo "[*] adicionado go/bin ao $SHELL_RC (abra um novo terminal ou: source $SHELL_RC)"
fi

# ---------------------------------------------------------------------------
# 10) Verificação
# ---------------------------------------------------------------------------
echo ""
echo "== Verificação =="
for t in subfinder httpx katana nuclei dnsx gau waybackurls amass gospider gf ffuf; do
  if command -v "$t" >/dev/null 2>&1; then printf "  \033[32mOK\033[0m   %s\n" "$t"; else printf "  \033[31mFALTA\033[0m %s\n" "$t"; fi
done
echo "  -- mineração web/mobile (jsrecon/apkrecon) --"
printf "  \033[32mOK\033[0m   jsrecon.py (stdlib puro)\n"
printf "  \033[32mOK\033[0m   apkrecon.py (stdlib + strings/unzip)\n"
for t in strings unzip adb apktool aapt jadx apkeep; do
  if command -v "$t" >/dev/null 2>&1; then printf "  \033[32mOK\033[0m   %s\n" "$t"; else printf "  \033[33mopt\033[0m  %s (opcional — apkrecon degrada sem ele)\n" "$t"; fi
done
echo ""
echo "Pronto. Próximos passos:"
echo "  python3 tools/brain.py init"
echo "  mineração de SPA:  python3 tools/jsrecon.py https://<host-autorizado> --context passkey"
echo "  mineração de APK:  python3 tools/apkrecon.py <app.apk|.xapk> --scope <dominios> --save <scratch>"
echo "  recon passivo agg: python3 tools/passive.py <dom1> <dom2> --diff-program <id> --data-dir <hive-data>"
echo "  recibos (1 cmd):   python3 tools/hive_scope_cache.py record-scope <program> --revision <sha256> --data-dir <hive-data>"
echo "  configure o MCP hive_mind e HIVE_DATA_DIR/HIVE_BIN no writer"
echo "  python3 tools/hive_workspace.py catalog"
echo "  antes de recon: hive_get_context + tools/hive_scope_cache.py record"
