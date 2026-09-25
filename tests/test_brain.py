#!/usr/bin/env python3
"""Testes do WAL local (tools/brain.py): escrita serializada + circuit breaker."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import brain  # noqa: E402


def test_record_result_and_endpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("EXCALIBULL_BRAIN_DIR", str(tmp_path))
    brain.init_brain(tmp_path)
    brain.record_result(tmp_path, "acme", "confirmed", "idor", "leu conta alheia")
    brain.record_result(tmp_path, "acme", "potential", "race", "double-spend?")
    brain.record_endpoint(tmp_path, "acme", "/api/v2/x", "tested", "idor", "A/B ok")
    txt = brain.get_target_file(tmp_path, "acme").read_text()
    assert "idor" in txt
    assert "Tested Endpoints" in txt
    assert "last_updated:" in txt


def test_circuit_breaker_trips_and_resets(tmp_path, monkeypatch):
    monkeypatch.setenv("EXCALIBULL_BRAIN_DIR", str(tmp_path))
    brain.init_brain(tmp_path)
    for _ in range(5):
        brain.record_circuit(tmp_path, "h.example", success=False)
    assert brain.check_circuit(tmp_path, "h.example") is False  # OPEN após 5 falhas
    brain.record_circuit(tmp_path, "h.example", success=True)
    assert brain.check_circuit(tmp_path, "h.example") is True   # success reseta


def test_circuit_breaker_functions_defined_at_module_top():
    # regressão: antes ficavam depois do __main__ (sumiam quando rodado como script)
    assert callable(brain.check_circuit)
    assert callable(brain.record_circuit)
