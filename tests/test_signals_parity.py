#!/usr/bin/env python3
"""Linter de sincronia signals.md ↔ arsenal.md (#17).

Disciplina (declarada nos dois arquivos): toda entrada do arsenal com "Sinais"
espelha uma linha S-*/C-* em signals.md. Este teste falha se surgir NOVO drift
(uma técnica do arsenal com Sinais sem sinal correspondente). Gaps já conhecidos
ficam pinados em KNOWN_GAPS até serem preenchidos.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARSENAL = (ROOT / "memory" / "arsenal.md").read_text(encoding="utf-8")
SIGNALS = (ROOT / "memory" / "signals.md").read_text(encoding="utf-8")

# Técnicas do arsenal com Sinais que ainda NÃO têm sinal em signals.md.
# Decisão do operador (2026-09-25): NÃO gerar manualmente — o `modo dojo` aprende
# de write-ups/casos reais e gera os `S-*`. Este pin fica até o dojo preencher.
KNOWN_GAPS = {"l1evm"}

_STOP = {"por", "via", "que", "com", "sem", "the", "and", "de", "da", "do", "no",
         "na", "prioridade", "bypass", "parece", "bug", "auth", "flow", "passivo"}


def _tokens(text: str) -> set[str]:
    toks = re.split(r"[^a-z0-9]+", text.lower())
    return {t for t in toks if len(t) >= 3 and t not in _STOP}


def _arsenal_sections_with_signals() -> dict[str, set[str]]:
    out = {}
    for block in re.split(r"^## ", ARSENAL, flags=re.M)[1:]:
        header = block.splitlines()[0]
        if "**Sinais:**" in block:
            out[header] = _tokens(header)
    return out


def _signals_arsenal_fieldsets() -> list[set[str]]:
    """Um token-set por campo **Arsenal:** de signals.md (não a união).

    Match por SUBSET evita falso-positivo de token genérico (ex.: 'valor'
    aparecendo tanto em Lógica quanto em L1/EVM).
    """
    sets = []
    for m in re.findall(r"\*\*Arsenal:\*\*([^·\n]*)", SIGNALS):
        toks = _tokens(m)
        if toks:  # ignora '(feeder)'/'(header injection)' vazios após stopwords
            sets.append(toks)
    return sets


def _gap_key(header: str) -> str:
    """Chave curta e estável p/ o allowlist (primeiro token significativo)."""
    t = _tokens(header)
    if "evm" in t or "l1" in header.lower():
        return "l1evm"
    return sorted(t)[0] if t else header[:8].lower()


def test_no_new_signal_arsenal_drift():
    fieldsets = _signals_arsenal_fieldsets()
    drift = {}
    for header, htoks in _arsenal_sections_with_signals().items():
        # representado se ALGUM campo Arsenal de um sinal é subconjunto do título
        if not any(fs <= htoks for fs in fieldsets):
            drift[_gap_key(header)] = header
    unexpected = {k: v for k, v in drift.items() if k not in KNOWN_GAPS}
    assert not unexpected, (
        "Nova técnica do arsenal com **Sinais:** sem S-*/C- em signals.md: "
        + "; ".join(unexpected.values())
        + " — adicione a linha S-* correspondente (disciplina de sincronia)."
    )
