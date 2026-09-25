#!/usr/bin/env python3
"""Testes dos simuladores de mecanismo (tools/mechanisms.py)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import mechanisms as m  # noqa: E402


def _ids(items):
    return [x["attack"] for x in items]


def test_jwt_rs_and_kid_and_jku():
    got = _ids(m.simulate_jwt({"alg": "RS256", "has_kid": True, "jku": True, "claims": ["role"]}))
    assert "alg-confusion-rs-to-hs" in got
    assert "alg-none" in got
    assert "kid-injection" in got
    assert "jku-x5u-ssrf" in got
    assert "claim-tamper" in got


def test_jwt_hs_weak_secret():
    assert "weak-hmac-secret" in _ids(m.simulate_jwt({"alg": "HS256"}))


def test_oauth_prefix_has_redirect_bypass_with_chain():
    res = m.simulate_oauth({"flow": "code", "redirect_uri_validation": "prefix", "pkce": False, "state": False})
    ids = _ids(res)
    assert "redirect_uri-bypass" in ids and "pkce-downgrade" in ids and "state-csrf-fixation" in ids
    assert any(x["attack"] == "redirect_uri-bypass" and x.get("chain") for x in res)


def test_oauth_implicit_token_leak():
    assert "implicit-token-leak" in _ids(m.simulate_oauth({"flow": "implicit"}))


def test_hmac_raw_vs_canonical():
    raw = _ids(m.simulate_hmac({"signs": "raw", "nonce": "global"}))
    assert "dup-key-smuggling" in raw and "sign-A-send-B" in raw
    canon = _ids(m.simulate_hmac({"signs": "canonical"}))
    assert "numeric-divergence-only" in canon and "dup-key-smuggling" not in canon


def test_state_money_prioritizes_repeat():
    res = m.simulate_state({"steps": ["cart", "checkout", "pay"]})
    repeat = next(x for x in res if x["attack"] == "step-repeat")
    assert repeat["priority"] == 1  # double-spend em fluxo de $


def test_dispatch_and_unknown():
    assert m.simulate("oauth", {"flow": "code"})
    assert m.simulate("nada", {}) == []
    assert set(m.SUPPORTED) >= {"jwt", "oauth", "hmac", "state"}


def test_results_are_ranked():
    res = m.simulate_jwt({"alg": "RS256", "jku": True})
    prios = [x["priority"] for x in res]
    assert prios == sorted(prios)
