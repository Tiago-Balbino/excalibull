#!/usr/bin/env python3
"""Testes das primitivas compartilhadas de extração (tools/extract.py)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import extract  # noqa: E402


def test_mask_str_and_bytes():
    assert extract.mask("sk_live_abcdefghijklmnop").startswith("sk_liv")
    assert "…" in extract.mask(b"AKIA0000000000000000")
    assert extract.mask("short") == "shor…"


def test_in_scope():
    scopes = ["example.com"]
    assert extract.in_scope("api.example.com", scopes) is True
    assert extract.in_scope("example.com", scopes) is True
    assert extract.in_scope("evil.com", scopes) is False
    assert extract.in_scope(b"API.EXAMPLE.COM", scopes) is True  # bytes + case


def test_split_scopes():
    assert extract.split_scopes("a.com, *.b.com , ") == ["a.com", "b.com"]


def test_text_patterns_api_and_url():
    P = extract.PATTERNS_TEXT
    js = 'fetch("/api/v2/users/me"); const u="https://cdn.example.com/x.js";'
    paths = [m.group(1) for m in P.api_path.finditer(js)]
    assert "/api/v2/users/me" in paths
    urls = P.url.findall(js)
    assert any("cdn.example.com" in u for u in urls)


def test_text_patterns_secret_and_gkey():
    P = extract.PATTERNS_TEXT
    blob = "key=AKIAABCDEFGHIJKLMNOP goog=AIza" + "a" * 35
    assert P.secret.search(blob) is not None
    assert P.gkey.search(blob) is not None


def test_bytes_patterns_match_same():
    Pb = extract.patterns(as_bytes=True)
    blob = b'"/api/wallet/balance" https://api.example.com/v1 AKIAABCDEFGHIJKLMNOP'
    assert Pb.api_path.search(blob) is not None
    assert Pb.url.search(blob) is not None
    assert Pb.secret.search(blob) is not None


def test_host_pattern_is_generic_not_hardcoded():
    # não deve estar preso a nenhum alvo específico
    assert "worldcoin" not in extract._HOST_SRC
    P = extract.PATTERNS_TEXT
    assert P.host.search("app.qualquer-alvo.io") is not None
