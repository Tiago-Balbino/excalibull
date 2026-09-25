#!/usr/bin/env python3
"""hypotheses.py — motor de hipóteses do Excalibull (automatiza o `code 6`).

Varre um CORPUS de recon (endpoints, JS, params, headers, notas) contra os sinais
`S-*`/`C-*` de `memory/signals.md` e emite leads `[UNTESTED]` rankeados, prontos
pra colar numa nota do Hive. Detecta também as composições `C-*` quando os sinais
`S-*` que as alimentam disparam juntos.

Fonte da verdade dos sinais = memory/signals.md (o mesmo arquivo que o operador
mantém à mão). Nada aqui toca o alvo — é análise passiva de texto já coletado.

Uso:
  python3 tools/hypotheses.py --corpus targets/nba/            # arquivo ou dir
  python3 tools/hypotheses.py --program nba --data-dir /.../hive-data
  saquear.py ... | python3 tools/hypotheses.py -               # corpus via stdin
  python3 tools/hypotheses.py --corpus recon.txt --json        # saída JSON
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SIGNALS = PROJECT_ROOT / "memory" / "signals.md"

_BACKTICK = re.compile(r"`([^`]+)`")
_ID_RE = re.compile(r"([SC]-[A-Z0-9\-]+?)\s+—")
_REF_ID_RE = re.compile(r"[SC]-[A-Z0-9]+(?:-[A-Z0-9]+)*")

# Prioridade por classe (menor = mais alto). Chains vêm antes de tudo (§10:
# BAC/IDOR/lógica primeiro; redirect/headers sozinhos são fracos).
_CLASS_WEIGHT = {"IDOR": 1, "BAC": 1, "LOGIC": 2, "HMAC": 3, "HDR": 4,
                 "REDIR": 5, "OSINT": 6}


def _field(block: str, label: str) -> str:
    """Extrai o texto de uma linha '- **Label:** ...' do bloco."""
    m = re.search(rf"-\s*\*\*{label}:\*\*\s*(.+)", block)
    return m.group(1).strip() if m else ""


def _compile_signal(raw: str) -> "re.Pattern | None":
    """Compila um trecho de sinal (backtick) como regex; se inválido, literal."""
    try:
        return re.compile(raw, re.IGNORECASE)
    except re.error:
        try:
            return re.compile(re.escape(raw), re.IGNORECASE)
        except re.error:
            return None


def parse_signals(text: str) -> list[dict]:
    """Parseia signals.md → lista de entradas {id, kind, patterns, feeds, lead, probe, matchers}."""
    entries: list[dict] = []
    for block in re.split(r"^### ", text, flags=re.M)[1:]:
        head = block.splitlines()[0]
        m = _ID_RE.match(head)
        if not m:
            continue
        sid = m.group(1)
        kind = "chain" if sid.startswith("C-") else "signal"
        sinal_line = _field(block, "Sinal")
        matchers = []
        if kind == "signal":
            for raw in _BACKTICK.findall(sinal_line):
                pat = _compile_signal(raw)
                if pat is not None:
                    matchers.append((raw, pat))
        feeds = []
        if kind == "chain":
            sinais_line = _field(block, "Sinais")
            feeds = [x for x in _REF_ID_RE.findall(sinais_line) if x != sid]
        entries.append({
            "id": sid,
            "kind": kind,
            "title": head.split("—", 1)[-1].strip(),
            "pattern": _field(block, "Pattern"),
            "lead": _field(block, "Hipótese") or _field(block, "Chain"),
            "probe": _field(block, "Probe"),
            "fp": _field(block, "FP"),
            "matchers": matchers,
            "feeds": feeds,
        })
    return entries


def load_corpus(args) -> str:
    """Monta o texto do corpus a partir de stdin / arquivo / dir / Hive."""
    parts: list[str] = []
    if args.corpus == "-":
        parts.append(sys.stdin.read())
    elif args.corpus:
        p = Path(args.corpus)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.suffix.lower() in (".md", ".txt", ".json", ".js", ".log"):
                    parts.append(_safe_read(f))
        elif p.is_file():
            parts.append(_safe_read(p))
    if args.program and args.data_dir:
        base = Path(args.data_dir).expanduser() / "programs" / args.program
        if base.is_dir():
            for f in sorted(base.rglob("*")):
                if f.suffix.lower() in (".md", ".json"):
                    parts.append(_safe_read(f))
    return "\n".join(parts)


def _safe_read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _weight(sid: str) -> int:
    if sid.startswith("C-"):
        return -1  # chains primeiro
    bits = sid.split("-")
    return _CLASS_WEIGHT.get(bits[1] if len(bits) > 1 else "", 7)


def evaluate(entries: list[dict], corpus: str, max_evidence: int = 6) -> list[dict]:
    """Roda os sinais contra o corpus e resolve as chains. Retorna leads rankeados."""
    fired: dict[str, dict] = {}
    for e in entries:
        if e["kind"] != "signal" or not e["matchers"]:
            continue
        evidence: list[str] = []
        for _raw, pat in e["matchers"]:
            for m in pat.finditer(corpus):
                tok = m.group(0).strip()
                if tok and tok not in evidence:
                    evidence.append(tok)
                if len(evidence) >= max_evidence:
                    break
            if len(evidence) >= max_evidence:
                break
        if evidence:
            fired[e["id"]] = {**e, "evidence": evidence}

    leads = list(fired.values())
    # chains: disparam quando TODOS os sinais alimentadores dispararam
    for e in entries:
        if e["kind"] != "chain" or not e["feeds"]:
            continue
        if all(f in fired for f in e["feeds"]):
            leads.append({**e, "evidence": [f"{f}✓" for f in e["feeds"]]})

    leads.sort(key=lambda x: (_weight(x["id"]), x["id"]))
    return leads


def render_text(leads: list[dict], label: str) -> str:
    if not leads:
        return f"== MOTOR DE HIPÓTESES — {label} ==\n(nenhum sinal disparou no corpus)"
    out = [f"== MOTOR DE HIPÓTESES — {label} ==",
           f"{len(leads)} lead(s) [UNTESTED], mais promissores primeiro:\n"]
    for x in leads:
        tag = "chain" if x["kind"] == "chain" else (x["pattern"] or "").replace("**", "")
        out.append(f"[UNTESTED] {x['id']} ({tag}) — {x['title']}")
        if x.get("lead"):
            out.append(f"    hipótese: {x['lead']}")
        out.append(f"    evidência: {', '.join(x['evidence'])}")
        if x.get("probe"):
            out.append(f"    probe: {x['probe']}")
        out.append("")
    out.append("Regra: cada lead é hipótese, não veredito. Confirme com o probe 🟢 antes do 🔴; "
               "registre o beco-sem-saída no brain se morrer (§12 / THE-MIND).")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Motor de hipóteses (code 6) do Excalibull")
    ap.add_argument("corpus", nargs="?", default="",
                    help="arquivo/dir de recon, ou '-' p/ stdin")
    ap.add_argument("--corpus", dest="corpus_opt", default="",
                    help="idem posicional (arquivo/dir/'-')")
    ap.add_argument("--program", default="", help="program_id p/ ler o corpus do Hive")
    ap.add_argument("--data-dir", default=os.environ.get("HIVE_DATA_DIR", ""))
    ap.add_argument("--signals", default=str(DEFAULT_SIGNALS))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    a.corpus = a.corpus_opt or a.corpus

    try:
        sig_text = Path(a.signals).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"ERRO: nao consegui ler {a.signals}: {exc}", file=sys.stderr)
        return 2
    entries = parse_signals(sig_text)

    corpus = load_corpus(a)
    if not corpus.strip():
        print("ERRO: corpus vazio — passe --corpus <arquivo|dir>, --program+--data-dir, ou stdin.",
              file=sys.stderr)
        return 2

    leads = evaluate(entries, corpus)
    label = a.program or a.corpus or "stdin"
    if a.json:
        print(json.dumps([{k: v for k, v in x.items() if k != "matchers"} for x in leads],
                         ensure_ascii=False, indent=2))
    else:
        print(render_text(leads, label))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
