#!/usr/bin/env python3
"""Hook PreToolUse (Bash) com autoridade de escopo exclusiva do Hive Mind.

Todo host HTTP(S) precisa de um recibo recente produzido a partir da resposta
estruturada de ``hive_get_context``. Escopo local em ``targets/`` nunca autoriza
tráfego. Ausência, expiração, ``unknown`` e ``out_of_scope`` falham fechados.

Chamado por .claude/settings.json PreToolUse.Bash.
Stdin: JSON do evento de hook. Stdout: vazio (permite) ou {"decision":"block"}.
Exit code: sempre 0 (o bloqueio é sinalizado via stdout JSON).
"""

from __future__ import annotations

import json
import ipaddress
import os
import re
import shlex
import sys
from pathlib import Path

HOOK_DIR = Path(__file__).resolve().parent
if str(HOOK_DIR) not in sys.path:
    sys.path.insert(0, str(HOOK_DIR))

from hive_scope_cache import authorization_for  # noqa: E402

_URL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)(?::\d+)?", re.IGNORECASE)
_HOST_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+[A-Za-z]{2,63}(?::\d+)?$|^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$"
)
# Sufixos de arquivo: um token com esses sufixos é caminho local, não host.
# (.sh/.app/.dev NÃO entram: são TLDs reais — o gate segue fail-closed p/ eles;
#  arquivos locais tipo setup.sh são cobertos por _is_local_path.)
_FILE_SUFFIXES = (".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".csv",
                  ".log", ".apk", ".xapk", ".apks", ".ipa", ".map")


def _is_local_path(token: str) -> bool:
    """True se o token existe como arquivo/dir local (logo, não é host remoto)."""
    if not token or len(token) > 4096:
        return False
    try:
        return os.path.exists(token)
    except (OSError, ValueError):
        return False


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
    for i, raw in enumerate(tokens):
        token = raw.split("=", 1)[-1].strip("'\"[](),;")
        if "://" in token or "/" in token or token.lower().endswith(_FILE_SUFFIXES):
            continue
        if not _HOST_RE.fullmatch(token):
            continue
        base = token.rsplit(":", 1)[0]
        prev = tokens[i - 1] if i > 0 else ""
        # Falsos-positivos comuns que NÃO são host remoto:
        #  - módulo Python após -m (ex.: `python3 -m json.tool`)
        #  - arquivo/dir local existente (ex.: `bash setup.sh`, `cat app.sh`)
        # Host remoto real nunca casa _is_local_path → gate segue fail-closed.
        if prev in ("-m", "--module") or _is_local_path(base):
            continue
        host = base.rstrip(".").lower()
        if host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


def _is_loopback(host: str) -> bool:
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> int:
    payload = read_payload()
    if not payload:
        return 0
    if payload.get("tool_name") not in (None, "Bash"):
        return 0

    command = (payload.get("tool_input") or {}).get("command", "") or ""
    hosts = extract_hosts(command)
    if not hosts:
        return 0

    for host in hosts:
        if _is_loopback(host):
            continue
        receipt = authorization_for(host)
        if not receipt or receipt.get("action_allowed") is not True:
            detail = "sem recibo vigente" if not receipt else f"status={receipt.get('status')}"
            reason = (
                f"BLOQUEADO (Hive fail-closed): {host} {detail}. "
                "Chame hive_get_context com program_id e asset exato; prossiga somente se "
                "scope.confirmed=true e action_allowed=true. Salve o JSON estruturado e rode "
                "`python3 tools/hive_scope_cache.py record <arquivo.json>`. "
                "Scope local em targets/ nao concede autorizacao."
            )
            sys.stdout.write(json.dumps({"decision": "block", "reason": reason}))
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
