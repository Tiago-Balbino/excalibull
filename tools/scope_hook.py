#!/usr/bin/env python3
"""Hook PreToolUse (Bash|WebFetch) com autoridade de escopo exclusiva do Hive Mind.

Todo host HTTP(S) precisa de um recibo recente produzido a partir da resposta
estruturada de ``hive_get_context``. Escopo local em ``targets/`` nunca autoriza
tráfego. Ausência, expiração, ``unknown`` e ``out_of_scope`` falham fechados.

Chamado por .claude/settings.json PreToolUse.Bash e PreToolUse.WebFetch.
Stdin: JSON do evento de hook. Stdout: vazio (permite) ou {"decision":"block"}.
Exit code: sempre 0 (o bloqueio é sinalizado via stdout JSON).

Postura fail-closed: se o backend de autorização (``hive_scope_cache``) não puder
ser importado/consultado, ou se qualquer erro inesperado ocorrer com um comando
que toca hosts, o gate BLOQUEIA em vez de silenciar (um erro no gate nunca vira
bypass). Comandos sem host (ex.: ``ls``) seguem liberados mesmo em erro.
"""

from __future__ import annotations

import json
import ipaddress
import os
import re
import shlex
import sys
from pathlib import Path
from urllib.parse import urlsplit

HOOK_DIR = Path(__file__).resolve().parent
if str(HOOK_DIR) not in sys.path:
    sys.path.insert(0, str(HOOK_DIR))

# Import fail-closed: se o backend de autorização não carregar, NÃO deixamos o
# script morrer sem imprimir (isso liberaria tráfego). Guardamos o erro e, se
# houver host no comando, bloqueamos em main().
try:
    from hive_scope_cache import authorization_for  # noqa: E402
    _IMPORT_ERR: Exception | None = None
except Exception as exc:  # pragma: no cover - defensivo
    authorization_for = None  # type: ignore[assignment]
    _IMPORT_ERR = exc

_URL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)(?::\d+)?", re.IGNORECASE)
_HOST_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+[A-Za-z]{2,63}(?::\d+)?$|^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$"
)
# Sufixos de arquivo: um token com esses sufixos é caminho local, não host.
# (.sh/.app/.dev NÃO entram: são TLDs reais — o gate segue fail-closed p/ eles;
#  arquivos locais tipo setup.sh são cobertos por _looks_like_local_exec.)
_FILE_SUFFIXES = (".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".csv",
                  ".log", ".apk", ".xapk", ".apks", ".ipa", ".map")
# Sufixos de script/executável local: um token com esses sufixos QUE EXISTE no
# disco é um arquivo local (ex.: `bash setup.sh`), mesmo que a extensão também
# seja um TLD real (.sh). Estes são pulados sempre, inclusive quando o comando
# invoca uma ferramenta de rede.
_LOCAL_EXEC_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh", ".fish", ".pl", ".rb",
                        ".php", ".js", ".ts", ".lua", ".r", ".go")
# Comandos que fazem tráfego de rede. Quando um deles aparece no comando, um
# token que "parece host" NÃO pode ser dispensado só porque existe um arquivo
# local com o mesmo nome (fecha o bypass de colisão os.path.exists).
_FETCH_CMDS = {
    "curl", "wget", "http", "https", "httpie", "xh", "nc", "ncat", "netcat",
    "openssl", "ssh", "scp", "sftp", "ftp", "telnet", "nmap", "masscan",
    "httpx", "nuclei", "ffuf", "katana", "gau", "gauplus", "waybackurls",
    "dnsx", "subfinder", "amass", "gospider", "hakrawler", "wfuzz", "dirb",
    "dirsearch", "gobuster", "feroxbuster", "arjun", "dalfox", "socat",
}


def _is_local_path(token: str) -> bool:
    """True se o token existe como arquivo/dir local (logo, não é host remoto)."""
    if not token or len(token) > 4096:
        return False
    try:
        return os.path.exists(token)
    except (OSError, ValueError):
        return False


def _looks_like_local_exec(token: str) -> bool:
    """True se o token é um script/arquivo local existente com sufixo executável.

    Cobre `bash setup.sh`, `./run.zsh`, `source lib.sh` mesmo quando o comando
    invoca uma ferramenta de rede — .sh é TLD real, mas um .sh que existe no
    disco é um script, não um host.
    """
    low = token.lower()
    if low.endswith(_LOCAL_EXEC_SUFFIXES) and _is_local_path(token):
        return True
    return _is_local_path(token) and os.path.isdir(token)


def read_payload() -> dict | None:
    try:
        raw = sys.stdin.read()
    except Exception:
        return None
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def extract_hosts(command: str) -> list[str]:
    seen: set[str] = set()
    hosts: list[str] = []
    for match in _URL_RE.finditer(command):
        host = match.group(1).rstrip(".").lower()
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    # Um comando que invoca ferramenta de rede desabilita o atalho os.path.exists
    # para tokens que parecem host (fecha o bypass "arquivo local com nome de host").
    has_fetch_cmd = any(
        os.path.basename(tok).lower() in _FETCH_CMDS for tok in tokens
    )
    for i, raw in enumerate(tokens):
        token = raw.split("=", 1)[-1].strip("'\"[](),;`$")
        if "://" in token or "/" in token or token.lower().endswith(_FILE_SUFFIXES):
            continue
        if not _HOST_RE.fullmatch(token):
            continue
        base = token.rsplit(":", 1)[0]
        prev = tokens[i - 1] if i > 0 else ""
        # Falsos-positivos comuns que NÃO são host remoto:
        #  - módulo Python após -m (ex.: `python3 -m json.tool`)
        #  - script/arquivo local executável existente (ex.: `bash setup.sh`)
        #  - arquivo/dir local existente, DESDE QUE o comando não faça tráfego
        #    (quando há curl/wget/..., uma colisão de nome não concede bypass)
        if prev in ("-m", "--module"):
            continue
        if _looks_like_local_exec(base):
            continue
        if not has_fetch_cmd and _is_local_path(base):
            continue
        host = base.rstrip(".").lower()
        if host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


def extract_targets(command: str) -> list[str]:
    """Conserva origem e caminho para não perder exclusões por URL."""
    urls = list(dict.fromkeys(re.findall(r"https?://[^\s\"'<>`]+", command, re.IGNORECASE)))
    represented = {urlsplit(url).hostname for url in urls}
    return urls + [host for host in extract_hosts(command) if host not in represented]


def _is_loopback(host: str) -> bool:
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _block(reason: str) -> None:
    sys.stdout.write(json.dumps({"decision": "block", "reason": reason}))


def _hosts_from_payload(payload: dict) -> list[str]:
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input") or {}
    if tool == "WebFetch":
        url = tool_input.get("url", "") or ""
        return extract_targets(url)
    command = tool_input.get("command", "") or ""
    return extract_targets(command)


def main() -> int:
    payload = read_payload()
    if not payload:
        return 0
    if payload.get("tool_name") not in (None, "Bash", "WebFetch"):
        return 0

    try:
        hosts = _hosts_from_payload(payload)
    except Exception:
        # Não conseguimos analisar o comando com segurança → fail-closed.
        _block(
            "BLOQUEADO (Hive fail-closed): falha ao analisar o comando no scope_hook. "
            "Reformule o comando ou verifique o hook antes de emitir tráfego."
        )
        return 0

    if not hosts:
        return 0

    # Backend de autorização indisponível + há host → fail-closed.
    if authorization_for is None:
        _block(
            "BLOQUEADO (Hive fail-closed): backend de autorizacao (hive_scope_cache) "
            f"indisponivel ({type(_IMPORT_ERR).__name__}). Nenhum trafego autorizado "
            "ate o gate voltar. Verifique tools/hive_scope_cache.py."
        )
        return 0

    for host in hosts:
        if _is_loopback(urlsplit(host if "://" in host else "//" + host).hostname or ""):
            continue
        try:
            receipt = authorization_for(host)
        except Exception as exc:  # backend quebrou na consulta → fail-closed
            _block(
                f"BLOQUEADO (Hive fail-closed): erro ao consultar autorizacao de {host} "
                f"({type(exc).__name__}). Trafego negado ate o gate voltar."
            )
            return 0
        if not receipt or receipt.get("action_allowed") is not True:
            detail = "sem recibo vigente" if not receipt else f"status={receipt.get('status')}"
            reason = (
                f"BLOQUEADO (Hive fail-closed): {host} {detail}. "
                "Chame hive_get_context com program_id e asset exato; prossiga somente se "
                "scope.confirmed=true e action_allowed=true. Salve o JSON estruturado e rode "
                "`python3 tools/hive_scope_cache.py record <arquivo.json>`. "
                "Scope local em targets/ nao concede autorizacao."
            )
            _block(reason)
            return 0

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        # Um erro inesperado no gate nunca pode virar bypass silencioso.
        _block(
            "BLOQUEADO (Hive fail-closed): erro inesperado no scope_hook. "
            "Trafego negado por seguranca; verifique o hook."
        )
        sys.exit(0)
