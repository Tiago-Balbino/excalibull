#!/usr/bin/env python3
"""
scope_hook.py — hook PreToolUse (Bash) do Excalibull.

Bloqueia comandos que referenciam hosts FORA DE ESCOPO. Agrega o escopo de
todas as fichas de alvo (`targets/<alvo>/scope.md` / `scope.yaml` / `.scope.txt`)
mais qualquer arquivo de escopo na raiz do projeto, e reusa a lógica de matching
do scope_check.py (wildcard/exato/CIDR, não substring).

Comportamento: só BLOQUEIA host que casa uma regra OUT_OF_SCOPE explícita. Host
desconhecido passa (o hook é guarda contra OOS conhecido, não allowlist). Sem
nenhum escopo definido → não bloqueia nada.

Chamado por .claude/settings.json PreToolUse.Bash.
Stdin: JSON do evento de hook. Stdout: vazio (permite) ou {"decision":"block"}.
Exit code: sempre 0 (o bloqueio é sinalizado via stdout JSON).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HOOK_DIR = Path(__file__).resolve().parent
if str(HOOK_DIR) not in sys.path:
    sys.path.insert(0, str(HOOK_DIR))

from scope_check import (  # noqa: E402
    check_scope,
    find_scope_file,
    load_scope_md,
    load_scope_txt,
    load_scope_yaml,
)

PROJECT_ROOT = HOOK_DIR.parent
TARGETS_DIR = PROJECT_ROOT / "targets"

_URL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)(?::\d+)?", re.IGNORECASE)


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
    return hosts


def _load_one(path: Path) -> dict | None:
    try:
        suf = path.suffix.lower()
        if suf in (".yaml", ".yml"):
            return load_scope_yaml(path)
        if suf == ".md":
            return load_scope_md(path)
        return load_scope_txt(path)
    except Exception:
        return None


def load_aggregate_scope() -> dict | None:
    """Junta o escopo da raiz + de cada targets/<alvo>/scope.*.

    Retorna um dict {in_scope, out_of_scope, source} agregado, ou None se
    nenhum arquivo de escopo existir.
    """
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    sources: list[str] = []

    root = find_scope_file(PROJECT_ROOT)
    if root and not root.get("placeholder"):
        in_scope += root.get("in_scope", [])
        out_of_scope += root.get("out_of_scope", [])
        sources.append(root.get("source", "root"))

    if TARGETS_DIR.is_dir():
        for name in ("scope.md", "scope.yaml", "scope.yml", ".scope.txt", "scope.txt"):
            for path in sorted(TARGETS_DIR.glob(f"*/{name}")):
                if path.parent.name.startswith("_"):
                    continue  # pula _TEMPLATE e afins
                sc = _load_one(path)
                if not sc or sc.get("placeholder"):
                    continue
                in_scope += sc.get("in_scope", [])
                out_of_scope += sc.get("out_of_scope", [])
                sources.append(sc.get("source", str(path)))

    if not in_scope and not out_of_scope:
        return None
    return {
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "source": "; ".join(sources) if sources else "excalibull scope",
    }


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

    scope = load_aggregate_scope()
    if scope is None:
        return 0

    for host in hosts:
        verdict = check_scope(host, scope)
        if verdict.get("status") == "OUT_OF_SCOPE":
            rule = verdict.get("matched_rule") or host
            source = verdict.get("source", "scope file")
            reason = (
                f"BLOQUEADO: {host} está FORA DE ESCOPO "
                f"(regra: {rule}, fonte: {source}). "
                "Se for falso positivo, revise o scope.md do alvo — "
                "regras wildcard/exatas são avaliadas, não substrings."
            )
            sys.stdout.write(json.dumps({"decision": "block", "reason": reason}))
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
