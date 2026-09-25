#!/usr/bin/env python3
"""
validity_guard.py — hook PreToolUse (Write/Edit/MultiEdit) do Excalibull.

Bloqueia escrever um draft de report que contém sinal da lista never-submit SEM
um chain PERTO do sinal. Dispara quando o path parece report (reports/*, findings/*,
report-*, *-report.*, *draft*) e o conteúdo casa um sinal never-submit.

- DENY quando bate um sinal never-submit E não há linguagem de chain na vizinhança
  (janela de linhas) daquele sinal.
- ALLOW quando o sinal aparece junto de narrativa de chain.
- ALLOW pra arquivo que não é report.

Fonte da verdade da LISTA = rules/never-submit.md (parseada em runtime). O guard
só adiciona ALIASES de wording (EN/PT) pra melhorar recall; a parity é garantida
por tests/test_guards.py. Configurado em .claude/settings.json (PreToolUse
Write|Edit|MultiEdit).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NEVER_SUBMIT_MD = PROJECT_ROOT / "rules" / "never-submit.md"

# Fallback mínimo caso rules/never-submit.md não seja legível (fail-safe: ainda
# bloqueia os sinais mais comuns em vez de silenciar).
_FALLBACK_KILLLIST = [
    "Headers ausentes (CSP/HSTS/X-Frame-Options)",
    "SPF/DKIM/DMARC ausentes",
    "Introspection de GraphQL sozinha",
    "Disclosure de banner/versão sem exploit de CVE",
    "Clickjacking sem PoC de ação sensível",
    "Self-XSS",
    "Open redirect sozinho",
    "SSRF só-DNS (sem exfil de dado nem acesso interno)",
    "CORS wildcard sem PoC de exfil com credencial",
    "CSRF de logout",
    "Rate limit em formulário não-crítico",
    "Flags de cookie ausentes sozinhas",
]

# ALIASES de wording (EN/PT) → substring extra que também dispara. NÃO são a
# fonte da lista (essa é o .md); só cobrem como um draft pode estar escrito.
ALIASES: dict[str, str] = {
    "open-redirect": "open redirect sozinho está na never-submit",
    "redirect aberto": "open redirect sozinho está na never-submit",
    "redirecionamento aberto": "open redirect sozinho está na never-submit",
    "cors misconfig": "cors wildcard sem PoC de exfil está na never-submit",
    "graphql introspection": "introspection de GraphQL sozinha está na never-submit",
    "missing security header": "headers ausentes estão na never-submit",
    "missing csp": "CSP ausente sozinho está na never-submit",
    "csp ausente": "CSP ausente sozinho está na never-submit",
    "header ausente": "header de segurança ausente está na never-submit",
    "missing cookie flag": "flags de cookie ausentes estão na never-submit",
    "flag de cookie": "flags de cookie ausentes estão na never-submit",
    "logout csrf": "CSRF de logout sozinho é informativo",
    "missing dmarc": "SPF/DKIM/DMARC ausentes estão na never-submit",
    "missing spf": "SPF/DKIM/DMARC ausentes estão na never-submit",
    "missing dkim": "SPF/DKIM/DMARC ausentes estão na never-submit",
    "ssrf via dns": "SSRF só-DNS sozinho é informativo; pareie com exfil interno / metadata",
    "blind ssrf": "SSRF cego só com DNS é informativo; demonstre serviço interno / metadata",
    "version disclosure": "disclosure de versão sozinho está na never-submit",
    "disclosure de versão": "disclosure de versão sozinho está na never-submit",
    "user enumeration": "enumeração de user via delta sozinha costuma ser informativa",
    "enumeração de usuário": "enumeração de usuário via delta sozinha costuma ser informativa",
    "clickjack": "clickjacking sem PoC de ação sensível é informativo",
    "self xss": "self-XSS não reporta sozinho; chaineie com payoff real",
}

# Frases que indicam narrativa de chain → permitem o sinal QUANDO PERTO dele.
CHAIN_PRESENT_SIGNALS = [
    "chain:", "chain-candidate", "chained with", "chaineado", "chaineia",
    "encadeado", "encadeia", "→ ato", "-> ato", "leva a ato", "→ rce", "-> rce",
    "leva a rce", "→ admin", "-> admin", "tomada de conta", "account takeover",
    "ato:", "exfiltrate", "exfiltra", "exfil de", "cloud metadata",
    "metadata cloud", "169.254.169.254", "imds", "credentialed exfil",
    "cross-tenant", "cross tenant", "cookie tossing", "session theft",
    "roubo de sessão", "token theft", "roubo de token",
]

# Janela (em linhas) ao redor do sinal onde procurar linguagem de chain.
_CHAIN_WINDOW = 3


def _derive_phrase(bullet: str) -> str:
    """Deriva a substring de match a partir do texto cru do bullet do .md."""
    s = bullet.strip().lstrip("-* ").replace("`", "").lower()
    # corta qualificadores que não ajudam no match
    for cut in (" (", " sem ", " sozinh", " em mensagem", " em formulário",
                " em formulario", " em app"):
        idx = s.find(cut)
        if idx > 0:
            s = s[:idx]
    return s.strip(" .")


def load_killlist_signals() -> dict[str, str]:
    """Parseia a seção 'Lista de kill instantâneo' de never-submit.md → {substr: anchor}.

    A LISTA vem do .md (fonte única); anchor cita o bullet original.
    """
    bullets: list[str] = []
    try:
        text = NEVER_SUBMIT_MD.read_text(encoding="utf-8")
        in_section = False
        for line in text.splitlines():
            if line.startswith("## "):
                in_section = "kill instant" in line.lower()
                continue
            if in_section and line.lstrip().startswith("- "):
                bullets.append(line.strip())
    except Exception:
        bullets = list(_FALLBACK_KILLLIST)
    if not bullets:
        bullets = list(_FALLBACK_KILLLIST)

    signals: dict[str, str] = {}
    for bullet in bullets:
        phrase = _derive_phrase(bullet)
        if len(phrase) < 4:  # frases curtas demais geram falso-positivo
            continue
        clean_bullet = bullet.lstrip("-* ").replace("`", "").strip()
        signals[phrase] = (
            f"'{clean_bullet}' está na lista de kill de rules/never-submit.md — "
            f"só reporta com chain (rules/chain-table.md)."
        )
    # aliases de wording por cima (não sobrescrevem se já existir a frase base)
    for alias, anchor in ALIASES.items():
        signals.setdefault(alias, anchor + " (rules/never-submit.md).")
    return signals


_REPORT_MARKERS = ("/reports/", "/findings/", "/report-", "-report.",
                   "/draft", "draft-", "/finding.", "report.md", "finding.md")


def _looks_like_report(path: str) -> bool:
    p = path.lower()
    return any(m in p for m in _REPORT_MARKERS)


def _scan(content: str, signals: dict[str, str]) -> tuple[str | None, str | None]:
    """Retorna (sinal, anchor) do 1º sinal never-submit SEM chain na vizinhança."""
    lines = content.lower().splitlines() or [content.lower()]
    for idx, line in enumerate(lines):
        for signal, anchor in signals.items():
            if signal in line:
                lo = max(0, idx - _CHAIN_WINDOW)
                hi = idx + _CHAIN_WINDOW + 1
                window = "\n".join(lines[lo:hi])
                if any(tok in window for tok in CHAIN_PRESENT_SIGNALS):
                    continue  # ocorrência chaineada de perto → ok
                return signal, anchor
    return None, None


def _deny(signal: str, anchor: str, path: str) -> dict:
    msg = (
        f"validity_guard: bloqueado o write em {path}\n\n"
        f"Sinal never-submit detectado: '{signal}' (sem chain por perto)\n\n"
        f"{anchor}\n\n"
        f"Pra prosseguir:\n"
        f"  (a) adicione a narrativa de chain PERTO do sinal (mesma seção: alvo, "
        f"impacto, repro do comportamento chaineado), OU\n"
        f"  (b) rode o chain-walk (§12 / rules/chain-table.md) e volte com o chain "
        f"confirmado, OU\n"
        f"  (c) se já chaineou, deixe explícito no mesmo trecho ('chaineado com X', "
        f"'leva a ATO', 'exfil de ...')."
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": msg,
        }
    }


def main() -> None:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return
        data = json.loads(raw)
    except Exception:
        return

    tool = data.get("tool_name", "")
    if tool not in ("Write", "Edit", "MultiEdit"):
        return

    inp = data.get("tool_input", {}) or {}
    path = str(inp.get("file_path", ""))
    if not path or not _looks_like_report(path):
        return

    content = ""
    if tool == "Write":
        content = str(inp.get("content", ""))
    elif tool == "Edit":
        content = str(inp.get("new_string", ""))
    elif tool == "MultiEdit":
        for edit in inp.get("edits", []) or []:
            content += str(edit.get("new_string", "")) + "\n"

    if not content.strip():
        return

    signals = load_killlist_signals()
    signal, anchor = _scan(content, signals)
    if signal is None:
        return

    print(json.dumps(_deny(signal, anchor or "", path)))


if __name__ == "__main__":
    main()
