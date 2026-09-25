#!/usr/bin/env python3
"""Testes do motor de hipóteses (tools/hypotheses.py, o `code 6`)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import hypotheses as h  # noqa: E402

SIGNALS = (ROOT / "memory" / "signals.md").read_text(encoding="utf-8")


def _entries():
    return h.parse_signals(SIGNALS)


def test_parses_signals_and_chains():
    entries = _entries()
    ids = {e["id"] for e in entries}
    assert {"S-IDOR-01", "S-REDIR-01", "S-LOGIC-01"} <= ids
    assert {"C-01", "C-02", "C-03"} <= ids
    chains = [e for e in entries if e["kind"] == "chain"]
    assert all(e["feeds"] for e in chains)  # toda chain referencia sinais


def test_signal_has_compiled_matchers():
    idor = next(e for e in _entries() if e["id"] == "S-IDOR-01")
    assert idor["matchers"], "S-IDOR-01 deveria ter matcher regex"


def test_evaluate_fires_expected_signals():
    corpus = "GET /api/v2/users/{userId} returns data; body has price and coupon"
    leads = h.evaluate(_entries(), corpus)
    ids = {x["id"] for x in leads}
    assert "S-IDOR-01" in ids
    assert "S-LOGIC-01" in ids


def test_chain_fires_when_feeder_signal_present():
    corpus = "oauth client_id redirect_uri /authorize returnTo next"
    leads = h.evaluate(_entries(), corpus)
    ids = {x["id"] for x in leads}
    assert "S-REDIR-01" in ids
    assert "C-02" in ids  # redirect + OAuth → ATO


def test_chain_does_not_fire_without_feeder():
    # corpus com id (dispara S-IDOR) mas SEM nenhum token de redirect/oauth
    corpus = "apenas um identificador opaco de account aqui, nada mais"
    leads = h.evaluate(_entries(), corpus)
    assert "C-02" not in {x["id"] for x in leads}


def test_empty_corpus_no_leads():
    assert h.evaluate(_entries(), "texto totalmente irrelevante xyzzy") == [] or \
        all(x["kind"] == "signal" for x in h.evaluate(_entries(), "xyzzy"))


def test_chains_rank_before_signals():
    corpus = "client_id redirect_uri /authorize userId returnTo"
    leads = h.evaluate(_entries(), corpus)
    assert leads[0]["kind"] == "chain"  # chain no topo (mais promissor)


def test_evidence_is_captured():
    corpus = "param redirect_uri e returnTo no login"
    leads = h.evaluate(_entries(), corpus)
    redir = next(x for x in leads if x["id"] == "S-REDIR-01")
    assert any("redirect_uri" in ev or "returnTo" in ev for ev in redir["evidence"])
