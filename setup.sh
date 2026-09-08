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
echo ""
echo "Pronto. Próximos passos:"
echo "  python3 tools/brain.py init"
echo "  python3 tools/recon.py exemplo.com --all --out /tmp/teste"
