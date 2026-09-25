#!/usr/bin/env python3
"""Testes do giveup_guard (modo estrito) — força 'continuar atacando' (§5)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import exhaustion as ex  # noqa: E402


def run_guard(command: str, brain_dir: Path) -> str:
    env = {**os.environ, "EXCALIBULL_BRAIN_DIR": str(brain_dir)}
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "giveup_guard.py")],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}),
        capture_output=True, text=True, env=env, cwd=str(ROOT),
    )
    return proc.stdout


def is_block(out: str) -> bool:
    return '"decision": "block"' in out or '"decision":"block"' in out


def test_ignores_non_record_command(tmp_path):
    assert run_guard("ls -la", tmp_path).strip() == ""


def test_ignores_non_giveup_status(tmp_path):
    out = run_guard("python3 tools/brain.py record nba confirmed idor 'achado'", tmp_path)
    assert out.strip() == ""


def test_blocks_exhausted_without_matrix(tmp_path):
    out = run_guard("python3 tools/brain.py record nba exhausted 'idor-orders: tentei' 'x'", tmp_path)
    assert is_block(out)


def test_blocks_exhausted_with_incomplete_matrix(tmp_path, monkeypatch):
    monkeypatch.setenv("EXCALIBULL_BRAIN_DIR", str(tmp_path))
    ex.op_open("nba", "idor-orders", "idor", "/api/orders", "id", ex.DEFAULT_THRESHOLD)
    out = run_guard("python3 tools/brain.py record nba exhausted 'idor-orders: tentei' 'x'", tmp_path)
    assert is_block(out)


def test_allows_exhausted_when_matrix_fp(tmp_path, monkeypatch):
    monkeypatch.setenv("EXCALIBULL_BRAIN_DIR", str(tmp_path))
    ex.op_open("nba", "idor-orders", "idor", "/api/orders", "id", ex.DEFAULT_THRESHOLD)
    ex.op_fp("nba", "idor-orders", "3 re-enquadramentos = FP")
    out = run_guard("python3 tools/brain.py record nba exhausted 'idor-orders: FP confirmado' 'x'", tmp_path)
    assert out.strip() == ""


def test_allows_exhausted_when_coverage_met(tmp_path, monkeypatch):
    monkeypatch.setenv("EXCALIBULL_BRAIN_DIR", str(tmp_path))
    ex.op_open("nba", "gen", "generic", "/x", "", 0.8)
    ld = ex._load("nba")["leads"]["gen"]
    for cid in list(ld["cells"])[:-1]:  # >= 80%
        ex.op_mark("nba", "gen", cid, "pass", "")
    out = run_guard("python3 tools/brain.py record nba exhausted 'gen: matriz cheia' 'x'", tmp_path)
    assert out.strip() == ""
