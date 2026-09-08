#!/usr/bin/env python3
"""kb_sync.py — code 7: sincroniza targets/ do excalibull com o board knowledge-targets.

O knowledge-targets é a FONTE DA VERDADE (board canônico, por plataforma).
excalibull/targets/ é a cópia de trabalho (vazia por padrão).

Uso:
    python3 tools/kb_sync.py find <slug>    # code 7 find — puxa do board pra targets/
    python3 tools/kb_sync.py send <slug>    # code 7 send — devolve targets/ pro board (+ ranking)
    python3 tools/kb_sync.py                 # code 7      — diffa board vs targets/

O caminho do board vem de $KNOWLEDGE_TARGETS_DIR (default: ../knowledge-targets,
irmão do excalibull em ~/projetos/pessoal/).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

PLATFORMS = ("intigriti", "bugcrowd", "hackerone", "outros")
EXCLUDES = (".git", ".DS_Store", "__pycache__")

_TOOLS = Path(__file__).resolve().parent
EXCALIBULL = _TOOLS.parent
TARGETS_DIR = EXCALIBULL / "targets"


def kb_dir() -> Path:
    env = os.environ.get("KNOWLEDGE_TARGETS_DIR")
    if env:
        return Path(env).expanduser().resolve()
    # default: sibling do excalibull
    return (EXCALIBULL.parent / "knowledge-targets").resolve()


def _read_platform_from_yaml(target_yml: Path) -> str:
    """Lê `plataforma:` do target.yml sem exigir pyyaml (parse de 1 linha)."""
    if not target_yml.exists():
        return ""
    for line in target_yml.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith("plataforma:"):
            val = s.split(":", 1)[1].strip().strip('"').strip("'")
            # tira comentário inline
            val = val.split("#", 1)[0].strip()
            return val
    return ""


def find_in_board(kb: Path, slug: str) -> Path | None:
    """Localiza <plataforma>/<slug> no board (procura em todas as plataformas)."""
    for plat in PLATFORMS:
        cand = kb / plat / slug
        if cand.is_dir():
            return cand
    return None


def _copy_tree(src: Path, dst: Path) -> None:
    """Copia src/ → dst/ preservando tudo. Usa rsync se houver; senão shutil."""
    dst.mkdir(parents=True, exist_ok=True)
    if shutil.which("rsync"):
        cmd = ["rsync", "-a"]
        for ex in EXCLUDES:
            cmd.append(f"--exclude={ex}")
        cmd += [f"{src}/", f"{dst}/"]
        subprocess.run(cmd, check=True)
    else:
        def ignore(_d, names):
            return [n for n in names if n in EXCLUDES]
        shutil.copytree(src, dst, dirs_exist_ok=True, ignore=ignore)


def cmd_find(slug: str) -> int:
    kb = kb_dir()
    if not kb.is_dir():
        print(f"ERRO: board não encontrado em {kb}. Defina $KNOWLEDGE_TARGETS_DIR.", file=sys.stderr)
        return 2
    src = find_in_board(kb, slug)
    if src is None:
        print(f"ERRO: alvo '{slug}' não existe no board {kb}.", file=sys.stderr)
        print("      Alvos disponíveis:", ", ".join(sorted(list_board(kb).keys())) or "(nenhum)")
        return 1
    plat = src.parent.name
    dst = TARGETS_DIR / slug
    _copy_tree(src, dst)
    print(f"✅ find: {plat}/{slug}  →  targets/{slug}/")
    print(f"   fonte: {src}")
    return 0


def cmd_send(slug: str) -> int:
    kb = kb_dir()
    if not kb.is_dir():
        print(f"ERRO: board não encontrado em {kb}. Defina $KNOWLEDGE_TARGETS_DIR.", file=sys.stderr)
        return 2
    src = TARGETS_DIR / slug
    if not src.is_dir():
        print(f"ERRO: targets/{slug}/ não existe no excalibull.", file=sys.stderr)
        return 1

    # descobre a plataforma: 1) target.yml local; 2) onde já existe no board
    plat = _read_platform_from_yaml(src / "target.yml")
    if plat not in PLATFORMS:
        existing = find_in_board(kb, slug)
        plat = existing.parent.name if existing else ""
    if plat not in PLATFORMS:
        print(
            f"ERRO: não sei a plataforma de '{slug}'. Preencha `plataforma:` em "
            f"targets/{slug}/target.yml (uma de: {', '.join(PLATFORMS)}).",
            file=sys.stderr,
        )
        return 1

    dst = kb / plat / slug
    _copy_tree(src, dst)
    print(f"✅ send: targets/{slug}/  →  {plat}/{slug}/")

    # regenera o ranking do board (best-effort)
    gen = kb / "_scripts" / "gen_ranking.py"
    if gen.exists():
        r = subprocess.run([sys.executable, str(gen)], cwd=str(kb))
        if r.returncode != 0:
            print("aviso: gen_ranking.py falhou (pyyaml instalado?). RANKING.md não atualizado.", file=sys.stderr)
    return 0


def list_board(kb: Path) -> dict[str, str]:
    """{slug: plataforma} de tudo no board."""
    out: dict[str, str] = {}
    for plat in PLATFORMS:
        base = kb / plat
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            if d.is_dir() and (d / "target.yml").exists():
                out[d.name] = plat
    return out


def cmd_diff() -> int:
    kb = kb_dir()
    if not kb.is_dir():
        print(f"ERRO: board não encontrado em {kb}. Defina $KNOWLEDGE_TARGETS_DIR.", file=sys.stderr)
        return 2
    board = list_board(kb)
    local = {d.name for d in TARGETS_DIR.iterdir() if d.is_dir() and not d.name.startswith("_")} if TARGETS_DIR.is_dir() else set()

    print(f"🗂️  Board: {kb}")
    print(f"📁 Cópia de trabalho: {TARGETS_DIR}\n")
    print(f"{'alvo':<28} {'plataforma':<12} {'no board':<9} {'local'}")
    print("-" * 62)
    for slug in sorted(set(board) | local):
        plat = board.get(slug, "—")
        in_board = "sim" if slug in board else "não"
        in_local = "sim" if slug in local else "—"
        print(f"{slug:<28} {plat:<12} {in_board:<9} {in_local}")
    only_local = local - set(board)
    if only_local:
        print(f"\n⚠  Só local (nunca enviado ao board): {', '.join(sorted(only_local))}")
        print("   Use: python3 tools/kb_sync.py send <slug>")
    return 0


def main(argv: list[str]) -> int:
    if not argv:
        return cmd_diff()
    action = argv[0]
    if action == "find":
        if len(argv) < 2:
            print("uso: kb_sync.py find <slug>", file=sys.stderr)
            return 2
        return cmd_find(argv[1])
    if action == "send":
        if len(argv) < 2:
            print("uso: kb_sync.py send <slug>", file=sys.stderr)
            return 2
        return cmd_send(argv[1])
    print(f"ação desconhecida: {action}. Use find | send | (vazio para diff).", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
