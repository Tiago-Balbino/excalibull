#!/usr/bin/env python3
"""Selo por sessão: manifesto esperado, handoff, ingestão e read-back.

O padrão exige publicação confirmada. --handoff-only permite encerrar a
execução local com publicação pendente explícita, preservando WAL/outbox.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

from brain import get_brain_dir
from hive_documents import identifier
from hive_outbox import Outbox
from hive_publication import publication_problems

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TARGETS_DIR = PROJECT_ROOT / "targets"


def check_seal(target, *, session=None, data_dir=None, publication=True):
    problems = []
    identifier(target)
    scratch = TARGETS_DIR / target / "a-cacada-ate-aqui.md"
    wal = get_brain_dir() / "targets" / f"{target}.md"
    if not scratch.is_file():
        problems.append("scratch da sessão ausente: a-cacada-ate-aqui.md")
    elif not any(label in scratch.read_text().lower() for label in ("próximo passo", "proximo passo")):
        problems.append("scratch sem linha 'Próximo passo'")
    if not wal.is_file() or not wal.read_text().strip():
        problems.append("WAL do programa ausente/vazio")
    try:
        queue = Outbox(data_dir)
        session = queue.session(target, session)
        state = queue.load(session, target)
        entries = queue.current(state)
        handoff = state.get("handoff") or {}
        if not entries or handoff.get("id") not in state["expected"] or state["expected"].get(handoff.get("id")) != handoff.get("revision") or handoff.get("expected") != state["expected"]:
            problems.append("handoff atual não vinculado à sessão; prepare note <program> handoff")
        else:
            for path, key in ((scratch, "scratch_sha256"), (wal, "wal_sha256")):
                if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != handoff.get(key):
                    problems.append("scratch/WAL mudou após o handoff; prepare a revisão atual")
        for entry in entries:
            queue.bytes_for(state, entry)
        if publication:
            problems.extend(publication_problems(queue, state))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        problems.append(str(exc))
    return not problems, problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program", type=identifier)
    parser.add_argument("--session")
    parser.add_argument("--data-dir")
    parser.add_argument("--handoff-only", action="store_true")
    args = parser.parse_args(argv)
    ok, problems = check_seal(args.program, session=args.session, data_dir=args.data_dir,
                              publication=not args.handoff_only)
    if not ok:
        print(f"Selo incompleto para {args.program}:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    if args.handoff_only:
        print(f"Handoff local pronto para {args.program}; PUBLICAÇÃO PENDENTE. Preserve WAL/outbox.")
    else:
        print(f"Selo confirmado para {args.program}: contribuições esperadas ingeridas e recuperadas no Hive.")
        print("Verificação por trechos identificados; o contrato atual não comprova o hash integral remoto.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
