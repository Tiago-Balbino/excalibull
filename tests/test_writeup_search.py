#!/usr/bin/env python3
"""Testes do writeup_search (SQLite FTS5, stdlib) — substrato do futuro dojo."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import writeup_search as ws  # noqa: E402


def _seed(tmp_path):
    (tmp_path / "a.md").write_text(
        "# IDOR em /api/orders\nAchado: id sequencial permitia ler pedido de outra conta (BOLA)."
    )
    (tmp_path / "b.md").write_text(
        "# Open redirect vira ATO\nredirect_uri controlável no fluxo OAuth → roubo de code."
    )
    (tmp_path / "ignore.png").write_text("binário-nao-indexa")


def test_index_and_search(tmp_path):
    _seed(tmp_path)
    db = tmp_path / "w.db"
    n = ws.index_path(tmp_path, db)
    assert n == 2  # só os .md, não o .png
    hits = ws.search("idor", db)
    assert any("IDOR" in h["title"] for h in hits)
    hits2 = ws.search("oauth redirect", db)
    assert any("redirect" in h["title"].lower() for h in hits2)


def test_search_missing_db_returns_empty(tmp_path):
    assert ws.search("qualquer", tmp_path / "nao-existe.db") == []


def test_reindex_is_idempotent(tmp_path):
    _seed(tmp_path)
    db = tmp_path / "w.db"
    ws.index_path(tmp_path, db)
    ws.index_path(tmp_path, db)  # segunda vez não duplica
    assert ws.stats(db) == 2


def test_bad_query_does_not_crash(tmp_path):
    _seed(tmp_path)
    db = tmp_path / "w.db"
    ws.index_path(tmp_path, db)
    assert ws.search('"unterminated', db) == []  # FTS error → lista vazia
