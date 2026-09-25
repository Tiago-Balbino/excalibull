#!/usr/bin/env python3
"""
seal_gate.py — Gate verificável do "Selo de saída" do modo hunter (Excalibull).

O Selo fecha apenas quando o estado local foi convertido em handoff no
workspace canonico do Hive Mind:

  1. targets/<slug>/a-cacada-ate-aqui.md — scratch com bloco datado de HOJE
     e uma linha "Próximo passo".
  2. brain/targets/<slug>.md          — write-ahead log local com registros.
  3. $HIVE_DATA_DIR/programs/<slug>/{notes,evidence}/ contém um handoff
     Excalibull de HOJE. Ingestão e read-back ainda devem ser confirmados via MCP.

Uso:
    python3 tools/seal_gate.py <slug>

Exit 0 = Selo pode fechar. Exit 1 = falta item (lista o que falta). Exit 2 = alvo inexistente.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from brain import get_brain_dir, slugify  # noqa: E402
from hive_workspace import resolve_data_dir  # noqa: E402

PROJECT_ROOT = _TOOLS.parent
TARGETS_DIR = PROJECT_ROOT / "targets"


def _today_candidates() -> list[str]:
    """Datas 'de hoje' aceitas: local E UTC (distintas).

    hive_workspace.py carimba o handoff em UTC; o operador pode estar num fuso
    atrás/à frente. Perto da meia-noite as duas datas divergem — aceitar ambas
    evita reprovar o selo por diferença de fuso.
    """
    local = datetime.now().strftime("%Y-%m-%d")
    utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return [local] if local == utc else [local, utc]


def _today() -> str:
    """Rótulo humano de 'hoje' (local) para mensagens."""
    return datetime.now().strftime("%Y-%m-%d")


def check_seal(target: str) -> tuple[bool, list[str]]:
    """Retorna (ok, problemas). ok=True se o Selo pode fechar."""
    problems: list[str] = []
    tdir = TARGETS_DIR / target
    if not tdir.is_dir():
        return False, [f"targets/{target}/ não existe (crie o scratch com `code 3 {target}`)."]

    # 1) log de sessão datado + próximo passo
    log = tdir / "a-cacada-ate-aqui.md"
    if not log.exists():
        problems.append(
            f"targets/{target}/a-cacada-ate-aqui.md ausente — adicione um bloco datado da sessão."
        )
    else:
        ltxt = log.read_text(encoding="utf-8", errors="ignore")
        if not any(day in ltxt for day in _today_candidates()):
            problems.append(
                f"a-cacada-ate-aqui.md sem bloco de hoje ({_today()}) — registre o que rodou nesta sessão."
            )
        low = ltxt.lower()
        if "próximo passo" not in low and "proximo passo" not in low:
            problems.append("a-cacada-ate-aqui.md sem linha 'Próximo passo:' — diga onde retomar.")

    # 2) brain com registros do alvo
    brain_file = get_brain_dir() / "targets" / f"{slugify(target)}.md"
    if not brain_file.exists():
        problems.append(
            f"brain sem registros para '{target}' — rode `brain.py record`/`endpoint` nos leads da sessão."
        )

    # 3) handoff no workspace canonico do Hive
    try:
        hive_data_dir = resolve_data_dir()
    except ValueError:
        problems.append("HIVE_DATA_DIR ausente — nao e possivel provar que o handoff foi escrito no Hive.")
    else:
        program_dir = hive_data_dir / "programs" / target
        candidates: list[Path] = []
        for folder in ("notes", "evidence"):
            base = program_dir / folder
            if base.is_dir():
                for day in _today_candidates():
                    candidates.extend(base.glob(f"*-excalibull-*-{day}.md"))
        if not candidates:
            problems.append(
                "handoff Hive de hoje ausente — use `tools/hive_workspace.py note` e depois "
                "`ingest_workspace` + `get_sync_status` + read-back."
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
        print(f"✅ Selo local OK para '{target}': scratch + brain + handoff Hive presentes.")
        print("   Confirme ingest_workspace, get_sync_status idle e read-back antes de declarar hunter OFF.")
        return 0

    print(f"🚫 Selo de saída INCOMPLETO para '{target}'. Falta:")
    for p in problems:
        print(f"   - {p}")
    print("\nResolva os itens acima antes de confirmar 'modo hunter off'.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
