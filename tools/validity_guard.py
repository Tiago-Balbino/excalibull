#!/usr/bin/env python3
"""
validity_guard.py — hook PreToolUse (Write/Edit) do Excalibull.

Bloqueia escrever um draft de report que contém sinal da lista never-submit SEM
um chain. Dispara quando o path parece report (reports/*.md, findings/*.md,
targets/<alvo>/report-*.md, *draft*) e o conteúdo casa um sinal never-submit.

- DENY quando bate um sinal never-submit E não há linguagem de chain no corpo.
- ALLOW quando há narrativa de chain.
- ALLOW pra arquivo que não é report.

Sinais em PT e EN (termos técnicos costumam ficar em EN mesmo em PT).
Configurado em .claude/settings.json (PreToolUse Write|Edit).
"""

from __future__ import annotations

import json
import sys

# Substrings (lowercase) que indicam candidato a bloqueio. Alinhado com
# rules/never-submit.md. Mistura EN (termos técnicos) + PT.
NEVER_SUBMIT_SIGNALS: dict[str, str] = {
    "open redirect": "open-redirect → âncoras em rules/chain-table.md (redirect_uri OAuth / returnTo / SAML RelayState / login-CSRF / cookie tossing)",
    "open-redirect": "open-redirect → âncoras em rules/chain-table.md",
    "redirect aberto": "open-redirect → âncoras em rules/chain-table.md",
    "redirecionamento aberto": "open-redirect → âncoras em rules/chain-table.md",
    "cors wildcard": "cors → precisa de endpoint autenticado com credencial pra exfil (rules/chain-table.md → cors)",
    "cors misconfig": "cors → precisa de endpoint autenticado com credencial pra exfil",
    "graphql introspection": "introspection sozinha é informativa; pareie com bypass de auth em mutation / dado sensível",
    "introspection de graphql": "introspection sozinha é informativa; pareie com bypass de auth em mutation",
    "self-xss": "self-xss não reporta sozinho; chaineie via CSRF/entrega social com payoff real",
    "missing security header": "headers ausentes (CSP/HSTS/X-Frame-Options) sozinhos estão na never-submit",
    "missing csp": "CSP ausente sozinho está na never-submit; pareie com XSS",
    "csp ausente": "CSP ausente sozinho está na never-submit; pareie com XSS",
    "header ausente": "header de segurança ausente sozinho está na never-submit",
    "headers ausentes": "headers de segurança ausentes sozinhos estão na never-submit",
    "missing cookie flag": "flags de cookie ausentes sozinhas estão na never-submit",
    "flag de cookie": "flags de cookie ausentes sozinhas estão na never-submit",
    "logout csrf": "CSRF de logout sozinho é informativo",
    "csrf de logout": "CSRF de logout sozinho é informativo",
    "missing dmarc": "SPF/DKIM/DMARC ausentes sozinhos estão na never-submit",
    "missing spf": "SPF/DKIM/DMARC ausentes sozinhos estão na never-submit",
    "missing dkim": "SPF/DKIM/DMARC ausentes sozinhos estão na never-submit",
    "ssrf via dns": "SSRF só-DNS sozinho é informativo; pareie com exfil interno / metadata cloud",
    "ssrf só-dns": "SSRF só-DNS sozinho é informativo; pareie com exfil interno / metadata cloud",
    "blind ssrf": "SSRF cego só com prova de DNS é informativo; demonstre body de serviço interno ou metadata",
    "rate limit": "rate-limit em endpoint não-crítico está na never-submit",
    "clickjack": "clickjacking sem PoC de ação sensível é informativo",
    "version disclosure": "disclosure de banner/versão sozinho está na never-submit; pareie com exploit de CVE",
    "disclosure de versão": "disclosure de versão sozinho está na never-submit; pareie com exploit de CVE",
    "user enumeration": "enumeração de user via delta sozinha costuma ser informativa",
    "enumeração de usuário": "enumeração de usuário via delta sozinha costuma ser informativa",
}

# Frases que indicam que o draft JÁ tem narrativa de chain → permite.
CHAIN_PRESENT_SIGNALS = [
    "chain:", "chain-candidate", "chained with", "chaineado", "encadeado", "encadeia",
    "→ ato", "-> ato", "leva a ato", "→ rce", "-> rce", "leva a rce",
    "→ admin", "-> admin", "tomada de conta", "account takeover", "ato:",
    "exfiltrate", "exfiltra", "exfil de", "cloud metadata", "metadata cloud",
    "169.254.169.254", "imds", "credentialed exfil", "cross-tenant", "cross tenant",
    "cookie tossing", "session theft", "roubo de sessão", "token theft", "roubo de token",
]


def _looks_like_report(path: str) -> bool:
    p = path.lower()
    if not p.endswith((".md", ".markdown")):
        return False
    return (
        "/reports/" in p
        or "/findings/" in p
        or "/report-" in p
        or p.endswith("/finding.md")
        or p.endswith("/report.md")
        or "-report.md" in p
        or "/draft" in p
    )


def _scan(content: str) -> tuple[str | None, str | None]:
    body = content.lower()
    for marker in CHAIN_PRESENT_SIGNALS:
        if marker in body:
            return None, None
    for signal, anchor in NEVER_SUBMIT_SIGNALS.items():
        if signal in body:
            return signal, anchor
    return None, None


def _deny(signal: str, anchor: str, path: str) -> dict:
    msg = (
        f"validity_guard: bloqueado o write em {path}\n\n"
        f"Sinal never-submit detectado: '{signal}'\n\n"
        f"Esse padrão está em rules/never-submit.md e não passa na triagem. "
        f"Âncora de chain necessária:\n\n  {anchor}\n\n"
        f"Pra prosseguir:\n"
        f"  (a) adicione a narrativa de chain ao draft (alvo, impacto, repro do "
        f"comportamento chaineado), OU\n"
        f"  (b) rode o chain-walk (§12 / rules/chain-table.md) primeiro e volte com o "
        f"chain confirmado, OU\n"
        f"  (c) se já chaineou e o guard não viu, inclua 'chaineado com X', 'leva a ATO', "
        f"ou outra frase de chain no draft."
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

    signal, anchor = _scan(content)
    if signal is None:
        return

    print(json.dumps(_deny(signal, anchor or "", path)))


if __name__ == "__main__":
    main()
