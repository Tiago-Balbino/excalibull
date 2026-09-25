#!/usr/bin/env python3
"""exhaustion.py — matriz de mutação por lead (operacionaliza THE-MIND §5).

Rastreia a cobertura de ataque de um lead: quais células da matriz de mutação
(posição × método × encoding × bypass) já foram tentadas, para que ninguém marque
uma classe "exaurida" com meia dúzia de payloads. NÃO emite tráfego — só gera o
checklist e guarda o estado; cada célula é testada pelo agente/humano sob o gate
de recibo (scope_hook).

Estado: brain/exhaustion/<slug>.json (WAL local, atômico+locked via file_safety).
Fecho legítimo de um lead: cobertura >= threshold OU veredito FP (contra-prova).

Uso:
  python3 tools/exhaustion.py open  <target> <lead> --class idor --endpoint /api/x [--param id]
  python3 tools/exhaustion.py mark  <target> <lead> <cell-id> pass|fail|blocked|na [--note ..]
  python3 tools/exhaustion.py next  <target> <lead> [-n 5]
  python3 tools/exhaustion.py status <target> [lead]
  python3 tools/exhaustion.py fp    <target> <lead> --reason "3 re-enquadramentos + matriz cheia"
  python3 tools/exhaustion.py can-exhaust <target> <lead>     # exit 0 se pode; 1 se não
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from brain import get_brain_dir, slugify  # noqa: E402
from file_safety import atomic_write_text, load_json_or_quarantine, locked_file  # noqa: E402

import json  # noqa: E402

SCHEMA_VERSION = 1
DEFAULT_THRESHOLD = 0.8
_VALID_MARKS = {"untested", "pass", "fail", "blocked", "na"}
_TRIED = {"pass", "fail", "blocked"}  # contam como tentativa real (na = fora do denominador)


# --- Templates de matriz por classe (curados, alto-valor primeiro; §5/waf/payloads) ---
# Cada célula: (id, descrição do que tentar). Ordem = prioridade p/ `next`.
_TEMPLATES: dict[str, list[tuple[str, str]]] = {
    "idor": [
        ("path-get-baseline", "id no PATH, GET — baseline (objeto próprio)"),
        ("path-2accounts", "id de OUTRA conta no PATH + leitura-de-volta independente (§4)"),
        ("verb-put", "mesmo id, método PUT (escrita cross-account?)"),
        ("verb-patch", "mesmo id, método PATCH"),
        ("verb-delete", "mesmo id, método DELETE"),
        ("verb-post", "mesmo id, método POST"),
        ("pos-query", "id movido pra QUERY string"),
        ("pos-body", "id movido/duplicado no BODY (mass-assignment)"),
        ("pos-header", "id em HEADER (X-User-Id/X-Account-Id) forjado"),
        ("sibling-export", "endpoint irmão /export com o id"),
        ("sibling-share", "endpoint irmão /share|/invite com o id"),
        ("sibling-delete", "endpoint irmão /delete|/remove com o id"),
        ("idfmt-sequential", "id sequencial → enumerar vizinhos"),
        ("idfmt-uuid", "UUID/opaco → vazou em outro endpoint? previsível?"),
        ("wrap-array", "id como array/JSON ([id] , {\"id\":..}) — parser confusion"),
        ("dup-param", "id duplicado (?id=meu&id=alvo) — last/first wins"),
        ("content-type-swap", "trocar Content-Type (json↔form↔xml) no mesmo id"),
    ],
    "bac": [
        ("verb-swap", "trocar verbo (GET→POST/PUT/DELETE) na rota barrada"),
        ("options-head", "OPTIONS/HEAD — lê a política sem executar (🟢)"),
        ("path-case", "case da rota (/Admin /ADMIN) / trailing slash"),
        ("path-encode", "%2e %2f %252e no path (path normalization)"),
        ("hdr-original-url", "X-Original-URL / X-Rewrite-URL apontando pra rota interna"),
        ("hdr-forwarded", "X-Forwarded-For / X-Forwarded-Host / X-Real-IP"),
        ("hdr-referer", "forjar Referer exigido pelo controle"),
        ("hdr-role", "header de role/tenant forjado (X-Tenant, X-Role)"),
        ("method-override", "X-HTTP-Method-Override / _method=PUT"),
        ("guess-admin", "rotas admin adivinháveis (/admin /internal /debug)"),
        ("param-scope", "param de escopo (org/tenant/team id) trocado"),
        ("unauth-baseline", "repetir sem sessão/token (fail-open?) + leitura-de-volta"),
    ],
    "xss": [
        ("tier1-alert", "alert(1) — tier 1 (mais bloqueado; negativo NÃO prova nada §8)"),
        ("tier2-print", "print()/confirm()/prompt() — tier 2"),
        ("tier3-console", "console.log/document.title — tier 3 (execução silenciosa)"),
        ("tier4-fetch-oob", "fetch/img OOB p/ webhook — tier 4 (exec sem UI)"),
        ("ctx-html", "contexto HTML body: <svg onload> / <img onerror>"),
        ("ctx-attr", "contexto atributo: \" onfocus=.. autofocus"),
        ("ctx-jsstring", "contexto JS string: '-x-'/\\'-x//"),
        ("ctx-url", "contexto URL/href: javascript: / data:text/html"),
        ("enc-html", "encoding HTML entity/hex/dec do payload"),
        ("enc-unicode", "unicode/overlong/fullwidth (Nível 1 waf)"),
        ("waf-alt-tags", "tags alternativas (Nível 2)"),
        ("waf-alt-handlers", "event handlers alternativos (Nível 3)"),
        ("waf-no-keyword", "JS sem keywords / Function-constructor (Nível 4)"),
        ("waf-parser-diff", "mXSS / namespace confusion (Nível 5)"),
        ("sink-framework", "sink específico do framework (React/Angular/Vue/jQuery)"),
        ("csp-bypass", "CSP: JSONP em CDN whitelisted / base-tag / srcdoc"),
        ("dom-postmessage", "postMessage listener → sink (DOM XSS)"),
    ],
    "ssrf": [
        ("loopback", "127.0.0.1 / localhost / [::1] / 0.0.0.0"),
        ("metadata-aws", "169.254.169.254 metadata (+ header token IMDSv2)"),
        ("metadata-gcp", "metadata.google.internal (Metadata-Flavor)"),
        ("ip-decimal", "IP em decimal/octal/hex (2130706433)"),
        ("dns-rebind", "domínio próprio com rebind / A→interno"),
        ("scheme-gopher", "esquema gopher:// (protocolo smuggling)"),
        ("scheme-file", "file:// / dict:// / ftp://"),
        ("enc-url", "url-encode/double-encode do host interno"),
        ("redirect-follow", "endpoint que segue redirect → 30x p/ interno"),
        ("blind-oob", "OOB DNS/HTTP p/ confirmar (não é só-DNS §11)"),
        ("internal-body", "provar body de serviço interno (não só DNS)"),
    ],
    "logic": [
        ("val-negative", "valor negativo (preço/qty/refund) + leitura-de-volta"),
        ("val-zero", "zero / vazio"),
        ("val-huge", "valor gigante / overflow inteiro"),
        ("val-decimal", "casas decimais / arredondamento (0.001)"),
        ("val-type", "type confusion (string↔número↔bool)"),
        ("val-currency", "moeda/unidade trocada"),
        ("step-skip", "pular etapa (assume passo N-1 aconteceu)"),
        ("step-repeat", "repetir/reenviar (double-spend, race §6)"),
        ("role-elevate", "role/plan/tier elevado no body (mass-assign)"),
        ("coupon-reuse", "reuso/empilhamento de cupom/desconto"),
    ],
    "redirect": [
        ("reflect", "o destino reflete? (🟢 só observa)"),
        ("oauth-code", "redirect_uri no fluxo OAuth → roubo de code (chain)"),
        ("returnto-js", "returnTo/next que vira sink JS"),
        ("saml-relaystate", "SAML RelayState"),
        ("login-csrf", "login-CSRF + redirect"),
        ("bypass-host", "bypass de validação de host (@, //, \\, .attacker)"),
    ],
}

# Fallback genérico (§5 puro) — produto curado posição × método × encoding.
_GENERIC = [
    ("pos-query", "vetor na QUERY"),
    ("pos-path", "vetor no PATH"),
    ("pos-body", "vetor no BODY"),
    ("pos-header", "vetor em HEADER"),
    ("method-alt", "trocar método (GET/POST/PUT/PATCH/DELETE)"),
    ("enc-raw", "payload raw"),
    ("enc-url", "url-encode"),
    ("enc-double", "double-url-encode"),
    ("enc-unicode", "unicode/overlong"),
    ("enc-stacked", "encoding empilhado"),
    ("parser-diff", "diferencial de parser (content-type/charset)"),
]


def template_for(vuln_class: str) -> list[tuple[str, str]]:
    return _TEMPLATES.get((vuln_class or "").strip().lower(), _GENERIC)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _state_path(target: str) -> Path:
    d = get_brain_dir() / "exhaustion"
    return d / f"{slugify(target)}.json"


def _load(target: str) -> dict:
    st = load_json_or_quarantine(_state_path(target), dict)
    st.setdefault("schema_version", SCHEMA_VERSION)
    st.setdefault("leads", {})
    return st


def _save(target: str, state: dict) -> None:
    atomic_write_text(_state_path(target), json.dumps(state, ensure_ascii=False, indent=2))


def coverage(lead: dict) -> tuple[int, int, float]:
    """(tentadas, aplicáveis, pct). `na` sai do denominador."""
    cells = lead.get("cells", {})
    applicable = [c for c in cells.values() if c.get("status") != "na"]
    tried = [c for c in applicable if c.get("status") in _TRIED]
    denom = len(applicable)
    pct = (len(tried) / denom) if denom else 0.0
    return len(tried), denom, pct


def is_complete(lead: dict, threshold: float = DEFAULT_THRESHOLD) -> bool:
    if lead.get("fp"):
        return True
    _, _, pct = coverage(lead)
    return pct >= threshold


def missing_cells(lead: dict) -> list[tuple[str, str]]:
    return [(cid, c["desc"]) for cid, c in lead.get("cells", {}).items()
            if c.get("status") == "untested"]


# ---- operações ----
def op_open(target: str, lead: str, vuln_class: str, endpoint: str, param: str,
            threshold: float) -> dict:
    state = _load(target)
    cells = {cid: {"desc": desc, "status": "untested", "note": "", "ts": None}
             for cid, desc in template_for(vuln_class)}
    with locked_file(_state_path(target)):
        state = _load(target)
        state["leads"][lead] = {
            "class": vuln_class, "endpoint": endpoint, "param": param,
            "opened_at": _now(), "threshold": threshold, "fp": None, "cells": cells,
        }
        _save(target, state)
    return state["leads"][lead]


def op_mark(target: str, lead: str, cell_id: str, status: str, note: str) -> None:
    if status not in _VALID_MARKS:
        raise ValueError(f"status inválido: {status} (use {sorted(_VALID_MARKS)})")
    with locked_file(_state_path(target)):
        state = _load(target)
        ld = state["leads"].get(lead)
        if not ld:
            raise ValueError(f"lead '{lead}' não existe em {target} (rode `open` primeiro)")
        if cell_id not in ld["cells"]:
            raise ValueError(f"célula '{cell_id}' não existe nesse lead (veja `status`)")
        ld["cells"][cell_id].update(status=status, note=note, ts=_now())
        _save(target, state)


def op_fp(target: str, lead: str, reason: str) -> None:
    with locked_file(_state_path(target)):
        state = _load(target)
        ld = state["leads"].get(lead)
        if not ld:
            raise ValueError(f"lead '{lead}' não existe em {target}")
        ld["fp"] = {"reason": reason, "ts": _now()}
        _save(target, state)


def evaluate_exhaust(target: str, text: str, threshold: float = DEFAULT_THRESHOLD) -> tuple[bool, str]:
    """Usado pelo giveup_guard (MODO ESTRITO).

    Só libera se o texto do `record` referenciar um lead cuja matriz está completa
    (>= threshold) ou fechada como FP. Sem matriz referenciada → nega.
    """
    state = _load(target)
    leads = state.get("leads", {})
    if not leads:
        return False, (f"nenhuma matriz de exaustão aberta para '{target}'. "
                       f"Abra: python3 tools/exhaustion.py open {target} <lead> --class <c> --endpoint <e>")
    referenced = [lid for lid in leads if lid and lid in text]
    if not referenced:
        return False, ("o record não referencia nenhum lead com matriz. Cite o <lead-id> no "
                       f"texto (leads abertos: {', '.join(sorted(leads))}).")
    incomplete = []
    for lid in referenced:
        ld = leads[lid]
        if not is_complete(ld, ld.get("threshold", threshold)):
            tried, denom, pct = coverage(ld)
            miss = ", ".join(cid for cid, _ in missing_cells(ld)[:8]) or "—"
            incomplete.append(f"{lid}: {pct*100:.0f}% ({tried}/{denom}) — faltam: {miss}")
    if incomplete:
        return False, ("matriz(es) incompleta(s): " + " | ".join(incomplete)
                       + f". Cubra >= {int(threshold*100)}% (exhaustion next) ou feche como FP "
                       "(exhaustion fp) antes de declarar exhausted.")
    return True, "ok: matriz(es) referenciada(s) completa(s)/FP"


# ---- CLI ----
def _print_cells(lead: str, ld: dict) -> None:
    tried, denom, pct = coverage(ld)
    fp = " [FP fechado]" if ld.get("fp") else ""
    print(f"● {lead}  ({ld.get('class')} · {ld.get('endpoint')}"
          + (f" · {ld['param']}" if ld.get("param") else "") + ")"
          + f"  cobertura {pct*100:.0f}% ({tried}/{denom}){fp}")
    for cid, c in ld["cells"].items():
        icon = {"untested": "[ ]", "pass": "[P]", "fail": "[F]",
                "blocked": "[B]", "na": "[-]"}.get(c["status"], "[?]")
        note = f"  ({c['note']})" if c.get("note") else ""
        print(f"   {icon} {cid:22} {c['desc']}{note}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Matriz de exaustão (THE-MIND §5)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    o = sub.add_parser("open"); o.add_argument("target"); o.add_argument("lead")
    o.add_argument("--class", dest="vuln_class", required=True)
    o.add_argument("--endpoint", default=""); o.add_argument("--param", default="")
    o.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)

    m = sub.add_parser("mark"); m.add_argument("target"); m.add_argument("lead")
    m.add_argument("cell"); m.add_argument("status", choices=sorted(_VALID_MARKS))
    m.add_argument("--note", default="")

    n = sub.add_parser("next"); n.add_argument("target"); n.add_argument("lead")
    n.add_argument("-n", type=int, default=5)

    s = sub.add_parser("status"); s.add_argument("target"); s.add_argument("lead", nargs="?")

    f = sub.add_parser("fp"); f.add_argument("target"); f.add_argument("lead")
    f.add_argument("--reason", required=True)

    ce = sub.add_parser("can-exhaust"); ce.add_argument("target"); ce.add_argument("lead")

    a = ap.parse_args(argv)

    if a.cmd == "open":
        ld = op_open(a.target, a.lead, a.vuln_class, a.endpoint, a.param, a.threshold)
        print(f"[+] matriz aberta: {a.target}/{a.lead} ({len(ld['cells'])} células). Teste e marque com `mark`.")
        _print_cells(a.lead, ld)
        return 0
    if a.cmd == "mark":
        try:
            op_mark(a.target, a.lead, a.cell, a.status, a.note)
        except ValueError as e:
            print(f"ERRO: {e}", file=sys.stderr); return 2
        _print_cells(a.lead, _load(a.target)["leads"][a.lead]); return 0
    if a.cmd == "next":
        ld = _load(a.target)["leads"].get(a.lead)
        if not ld:
            print(f"lead '{a.lead}' não existe.", file=sys.stderr); return 2
        miss = missing_cells(ld)[:a.n]
        if not miss:
            print("(nada pendente — matriz coberta ou tudo marcado)"); return 0
        print(f"Próximas células de {a.target}/{a.lead}:")
        for cid, desc in miss:
            print(f"   · {cid:22} {desc}")
        return 0
    if a.cmd == "status":
        leads = _load(a.target)["leads"]
        if not leads:
            print(f"(sem matrizes para {a.target})"); return 0
        for lid in ([a.lead] if a.lead else sorted(leads)):
            if lid in leads:
                _print_cells(lid, leads[lid]); print()
        return 0
    if a.cmd == "fp":
        try:
            op_fp(a.target, a.lead, a.reason)
        except ValueError as e:
            print(f"ERRO: {e}", file=sys.stderr); return 2
        print(f"[+] {a.target}/{a.lead} fechado como FALSO POSITIVO: {a.reason}"); return 0
    if a.cmd == "can-exhaust":
        ld = _load(a.target)["leads"].get(a.lead)
        if not ld:
            print(f"não pode: lead '{a.lead}' sem matriz", file=sys.stderr); return 1
        if is_complete(ld, ld.get("threshold", DEFAULT_THRESHOLD)):
            print("pode exhausted"); return 0
        _, _, pct = coverage(ld)
        print(f"não pode: cobertura {pct*100:.0f}% < threshold", file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
