#!/usr/bin/env python3
"""writeup_search.py — busca full-text sobre um corpus local de write-ups.

Substrato dependency-light (SQLite FTS5, stdlib puro — sem FAISS/embeddings) que
o `modo dojo` vai consumir depois pra aprender padrões e destilar sinais. Aqui só
INDEXA e BUSCA texto; a geração de `S-*` (dojo) é decisão futura do operador.

Uso:
  python3 tools/writeup_search.py index <dir|arquivo> [--db .hive/writeups.db]
  python3 tools/writeup_search.py search "idor oauth redirect" [--limit 10]
  python3 tools/writeup_search.py stats

Nunca versione o .db (fica em .hive/, gitignored). O índice é reconstruível das
fontes — não é fonte canônica.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = PROJECT_ROOT / ".hive" / "writeups.db"
_EXTS = {".md", ".markdown", ".txt"}


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db_path))
    con.execute("CREATE VIRTUAL TABLE IF NOT EXISTS writeups "
                "USING fts5(path UNINDEXED, title, body, tokenize='porter unicode61')")
    return con


def _title_of(text: str, fallback: str) -> str:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            return s.lstrip("# ").strip()
        if s:
            return s[:80]
    return fallback


def index_path(target: Path, db_path: Path) -> int:
    con = _connect(db_path)
    files = [target] if target.is_file() else [
        f for f in sorted(target.rglob("*")) if f.suffix.lower() in _EXTS
    ]
    n = 0
    with con:
        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(f)
            con.execute("DELETE FROM writeups WHERE path = ?", (rel,))  # re-index limpo
            con.execute("INSERT INTO writeups (path, title, body) VALUES (?, ?, ?)",
                        (rel, _title_of(text, f.name), text))
            n += 1
    con.close()
    return n


def search(query: str, db_path: Path, limit: int = 10) -> list[dict]:
    if not db_path.exists():
        return []
    con = _connect(db_path)
    try:
        rows = con.execute(
            "SELECT path, title, snippet(writeups, 2, '»', '«', '…', 12) AS snip, rank "
            "FROM writeups WHERE writeups MATCH ? ORDER BY rank LIMIT ?",
            (query, limit),
        ).fetchall()
    except sqlite3.OperationalError as exc:
        print(f"ERRO: query FTS inválida: {exc}", file=sys.stderr)
        return []
    finally:
        con.close()
    return [{"path": p, "title": t, "snippet": s} for (p, t, s, _r) in rows]


def stats(db_path: Path) -> int:
    if not db_path.exists():
        return 0
    con = _connect(db_path)
    n = con.execute("SELECT count(*) FROM writeups").fetchone()[0]
    con.close()
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Busca full-text de write-ups (SQLite FTS5)")
    ap.add_argument("cmd", choices=["index", "search", "stats"])
    ap.add_argument("arg", nargs="?", default="", help="dir/arquivo (index) ou query (search)")
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--limit", type=int, default=10)
    a = ap.parse_args(argv)
    db_path = Path(a.db)

    if a.cmd == "index":
        if not a.arg:
            ap.error("index precisa de um dir/arquivo")
        n = index_path(Path(a.arg), db_path)
        print(f"[+] indexados {n} write-up(s) em {db_path}")
        return 0
    if a.cmd == "search":
        if not a.arg:
            ap.error("search precisa de uma query")
        hits = search(a.arg, db_path, a.limit)
        if not hits:
            print("(sem resultados)")
            return 0
        for h in hits:
            print(f"● {h['title']}\n    {h['path']}\n    …{h['snippet']}…\n")
        return 0
    print(f"{stats(db_path)} write-up(s) indexados em {db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
