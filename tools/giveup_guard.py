#!/usr/bin/env python3
"""giveup_guard.py — hook PreToolUse (Bash) do Excalibull. MODO ESTRITO.

Impede o Claude de declarar um lead como `exhausted`/`da-killed` cedo demais.
Dispara quando o comando é `brain.py record <target> exhausted|da-killed …` e
consulta a matriz de exaustão (tools/exhaustion.py):

  - só LIBERA se o texto do record referenciar um lead cuja matriz está completa
    (cobertura >= threshold) OU fechada como FP (contra-prova);
  - BLOQUEIA se a matriz referenciada está incompleta (lista o que falta);
  - BLOQUEIA se nenhuma matriz do lead foi aberta/citada (modo estrito).

É o enforcement de "continuar atacando" do THE-MIND §5/§3.1. NÃO afeta nenhum
outro comando Bash. Fail-closed: erro ao avaliar uma declaração de exaustão →
bloqueia (nunca deixa passar uma desistência sem checagem).

Stdin: JSON do evento. Stdout: vazio (permite) ou {"decision":"block"}.
Exit code: sempre 0.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

_GIVEUP_STATUSES = {"exhausted", "da-killed"}


def _read_payload() -> dict | None:
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


def detect_giveup_record(command: str) -> tuple[str, str] | None:
    """Se o comando é `brain.py record <target> exhausted|da-killed …`, devolve
    (target, texto-technique+details). Senão None."""
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    for i, t in enumerate(toks):
        if t == "record" and any(os.path.basename(x) == "brain.py" for x in toks[:i]):
            after = toks[i + 1:]
            if len(after) >= 2 and after[1] in _GIVEUP_STATUSES:
                target = after[0]
                text = " ".join(after[2:])
                return target, text
    return None


def _block(reason: str) -> None:
    sys.stdout.write(json.dumps({"decision": "block", "reason": reason}))


def main() -> None:
    payload = _read_payload()
    if not payload:
        return
    if payload.get("tool_name") not in (None, "Bash"):
        return
    command = (payload.get("tool_input") or {}).get("command", "") or ""

    parsed = detect_giveup_record(command)
    if not parsed:
        return  # não é uma declaração de exaustão → não interfere
    target, text = parsed

    try:
        import exhaustion
        ok, msg = exhaustion.evaluate_exhaust(target, text)
    except Exception as exc:  # fail-closed: não deixa passar desistência sem checar
        _block(
            "🚫 giveup_guard: erro ao avaliar a matriz de exaustão "
            f"({type(exc).__name__}: {exc}). Declaração de 'exhausted' negada por seguança — "
            "verifique tools/exhaustion.py."
        )
        return

    if not ok:
        _block(
            f"🚫 giveup_guard (§5 — continuar atacando): NÃO pode declarar '{target}' exhausted.\n"
            f"{msg}\n"
            "Fluxo: `python3 tools/exhaustion.py open " + target + " <lead> --class <c> --endpoint <e>` "
            "→ `mark` as células (`next` sugere) → cobrir >=80% OU `fp` (contra-prova) → "
            "então `brain.py record " + target + " exhausted \"<lead-id>: …\"`."
        )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Erro inesperado ANTES de identificar uma desistência → não trava Bash comum.
        pass
    sys.exit(0)
