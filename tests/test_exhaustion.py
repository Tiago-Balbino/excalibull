#!/usr/bin/env python3
"""Testes da matriz de exaustão (tools/exhaustion.py)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import exhaustion as ex  # noqa: E402


def _brain(tmp_path, monkeypatch):
    monkeypatch.setenv("EXCALIBULL_BRAIN_DIR", str(tmp_path))


def test_template_per_class_and_fallback():
    assert len(ex.template_for("idor")) >= 12
    assert ex.template_for("classe-inexistente") == ex._GENERIC


def test_open_creates_matrix(tmp_path, monkeypatch):
    _brain(tmp_path, monkeypatch)
    ld = ex.op_open("nba", "idor-orders", "idor", "/api/orders", "id", ex.DEFAULT_THRESHOLD)
    assert ld["class"] == "idor"
    assert len(ld["cells"]) == len(ex.template_for("idor"))
    assert all(c["status"] == "untested" for c in ld["cells"].values())


def test_mark_updates_coverage(tmp_path, monkeypatch):
    _brain(tmp_path, monkeypatch)
    ex.op_open("nba", "l1", "idor", "/x", "id", ex.DEFAULT_THRESHOLD)
    ex.op_mark("nba", "l1", "path-get-baseline", "pass", "")
    ld = ex._load("nba")["leads"]["l1"]
    tried, denom, pct = ex.coverage(ld)
    assert tried == 1 and pct > 0


def test_na_leaves_denominator(tmp_path, monkeypatch):
    _brain(tmp_path, monkeypatch)
    ex.op_open("nba", "l1", "idor", "/x", "id", ex.DEFAULT_THRESHOLD)
    ld = ex._load("nba")["leads"]["l1"]
    total = len(ld["cells"])
    ex.op_mark("nba", "l1", list(ld["cells"])[0], "na", "")
    ld = ex._load("nba")["leads"]["l1"]
    _, denom, _ = ex.coverage(ld)
    assert denom == total - 1  # na saiu do denominador


def test_incomplete_then_complete_by_coverage(tmp_path, monkeypatch):
    _brain(tmp_path, monkeypatch)
    ex.op_open("nba", "l1", "generic", "/x", "", 0.8)
    ld = ex._load("nba")["leads"]["l1"]
    assert not ex.is_complete(ld, 0.8)
    cells = list(ld["cells"])
    for cid in cells[:-1]:  # marca todas menos 1 → >= 80%
        ex.op_mark("nba", "l1", cid, "pass", "")
    ld = ex._load("nba")["leads"]["l1"]
    assert ex.is_complete(ld, 0.8)


def test_fp_closes_matrix(tmp_path, monkeypatch):
    _brain(tmp_path, monkeypatch)
    ex.op_open("nba", "l1", "idor", "/x", "id", ex.DEFAULT_THRESHOLD)
    ex.op_fp("nba", "l1", "3 re-enquadramentos + matriz cheia = FP legítimo")
    assert ex.is_complete(ex._load("nba")["leads"]["l1"])


def test_evaluate_exhaust_gates(tmp_path, monkeypatch):
    _brain(tmp_path, monkeypatch)
    # sem matriz → nega
    ok, _ = ex.evaluate_exhaust("nba", "idor-orders: done")
    assert ok is False
    # matriz aberta incompleta, referenciada → nega
    ex.op_open("nba", "idor-orders", "idor", "/api/orders", "id", ex.DEFAULT_THRESHOLD)
    ok, msg = ex.evaluate_exhaust("nba", "idor-orders: tentei tudo")
    assert ok is False and "incompleta" in msg
    # não referencia nenhum lead → nega
    ok, _ = ex.evaluate_exhaust("nba", "sem citar lead")
    assert ok is False
    # fecha como FP → libera quando referenciado
    ex.op_fp("nba", "idor-orders", "FP")
    ok, _ = ex.evaluate_exhaust("nba", "idor-orders: FP confirmado")
    assert ok is True
