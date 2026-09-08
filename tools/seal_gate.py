#!/usr/bin/env python3
"""
seal_gate.py — Gate verificável do "Selo de saída" do modo hunter (Excalibull).

O sword fechava a caçada com um Selo manual (flush pra ficha). Aqui o Selo só
fecha quando este gate passa — ele checa que o retrato do alvo está 100% atual
antes de `modo hunter off`:

  1. targets/<slug>/README.md         — a ficha existe e não é só o template.
  2. targets/<slug>/a-cacada-ate-aqui.md — log de sessão com bloco datado de HOJE
     e uma linha "Próximo passo".
  3. brain/targets/<slug>.md          — o brain tem registros da sessão do alvo.

Uso:
    python3 tools/seal_gate.py <slug>

Exit 0 = Selo pode fechar. Exit 1 = falta item (lista o que falta). Exit 2 = alvo inexistente.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from brain import get_brain_dir, slugify  # noqa: E402

PROJECT_ROOT = _TOOLS.parent
TARGETS_DIR = PROJECT_ROOT / "targets"


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def check_seal(target: str) -> tuple[bool, list[str]]:
    """Retorna (ok, problemas). ok=True se o Selo pode fechar."""
    problems: list[str] = []
    tdir = TARGETS_DIR / target
    if not tdir.is_dir():
        return False, [f"targets/{target}/ não existe (rode `code 7 find {target}` ou `code 3`)."]

    # 1) ficha
    readme = tdir / "README.md"
    if not readme.exists():
        problems.append(f"targets/{target}/README.md ausente (a ficha).")
    else:
        txt = readme.read_text(encoding="utf-8", errors="ignore")
        if "Copie a pasta" in txt or len(txt.strip()) < 200:
            problems.append(f"targets/{target}/README.md parece o template vazio — preencha a ficha.")

    # 2) log de sessão datado + próximo passo
    log = tdir / "a-cacada-ate-aqui.md"
    if not log.exists():
        problems.append(
            f"targets/{target}/a-cacada-ate-aqui.md ausente — adicione um bloco datado da sessão."
        )
    else:
        ltxt = log.read_text(encoding="utf-8", errors="ignore")
        if _today() not in ltxt:
            problems.append(
                f"a-cacada-ate-aqui.md sem bloco de hoje ({_today()}) — registre o que rodou nesta sessão."
            )
        low = ltxt.lower()
        if "próximo passo" not in low and "proximo passo" not in low:
            problems.append("a-cacada-ate-aqui.md sem linha 'Próximo passo:' — diga onde retomar.")

    # 3) brain com registros do alvo
    brain_file = get_brain_dir() / "targets" / f"{slugify(target)}.md"
    if not brain_file.exists():
        problems.append(
            f"brain sem registros para '{target}' — rode `brain.py record`/`endpoint` nos leads da sessão."
        )

    return (len(problems) == 0), problems


def main(argv: list[str]) -> int:
    if not argv:
        print("uso: python3 tools/seal_gate.py <slug>", file=sys.stderr)
        return 2
    target = argv[0]
    if not (TARGETS_DIR / target).is_dir():
        print(f"⚠  alvo '{target}' não está em targets/ — nada pra selar.", file=sys.stderr)
        return 2

    ok, problems = check_seal(target)
    if ok:
        print(f"✅ Selo de saída OK para '{target}': ficha + log + brain atualizados.")
        return 0

    print(f"🚫 Selo de saída INCOMPLETO para '{target}'. Falta:")
    for p in problems:
        print(f"   - {p}")
    print("\nResolva os itens acima antes de confirmar 'modo hunter off'.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
