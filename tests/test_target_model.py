#!/usr/bin/env python3
"""Testes do Modelo de Alvo (tools/target_model.py)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import target_model as tm  # noqa: E402

JSRECON = {
    "api_endpoints": ["/api/v2/orders/{id}", "/admin/config"],
    "hosts": ["app.example.com"],
    "graphql_ops": ["GetUser"],
    "fingerprints": [{"name": "Next.js", "playbook": "rotas /api/*"}],
}


def _brain(tmp_path, monkeypatch):
    monkeypatch.setenv("EXCALIBULL_BRAIN_DIR", str(tmp_path))


def test_import_jsrecon(tmp_path, monkeypatch):
    _brain(tmp_path, monkeypatch)
    st = tm.import_jsrecon("prog", JSRECON)
    kinds = [c["kind"] for c in st["components"].values()]
    assert kinds.count("endpoint") == 3  # 2 paths + 1 graphql op
    assert any(c["kind"] == "host" for c in st["components"].values())
    assert st["fingerprints"][0]["name"] == "Next.js"


def test_import_passive(tmp_path, monkeypatch):
    _brain(tmp_path, monkeypatch)
    st = tm.import_passive("prog", {"prod": ["a.example.com"], "delta_prod": ["b.example.com"]})
    hosts = {c["value"] for c in st["components"].values() if c["kind"] == "host"}
    assert {"a.example.com", "b.example.com"} <= hosts


def _seed(tmp_path, monkeypatch):
    _brain(tmp_path, monkeypatch)
    tm.import_jsrecon("prog", JSRECON)
    with tm.locked_file(tm._state_path("prog")):
        st = tm.load("prog")
        st["objects"].append({"name": "pedido", "owned_by": "user", "id_format": "seq",
                              "endpoint": "/api/v2/orders/{id}"})
        st["boundaries"].append({"from": "", "to": "/admin/config", "control": "authz", "trusts": []})
        st["auth_flows"].append({"id": "oauth-authz", "kind": "oauth",
                                 "spec": {"flow": "code", "redirect_uri_validation": "prefix"},
                                 "endpoint": "/authorize"})
        tm.save("prog", st)


def test_enumerate_produces_ranked_leads(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    leads = tm.enumerate_leads("prog")
    classes = {x["cls"] for x in leads}
    assert {"idor", "bac", "oauth", "graphql"} <= classes
    scores = [x["_score"] for x in leads]
    assert scores == sorted(scores)  # rankeado


def test_enumerate_class_filter(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    leads = tm.enumerate_leads("prog", only_class="idor")
    assert leads and all(x["cls"] == "idor" for x in leads)


def test_autonomous_learning_fp_lowers_achado_raises(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    tm.record_verdict("prog", "idor-pedido", "fp")
    tm.record_verdict("prog", "oauth-redirect_uri-bypass", "achado")
    st = tm.load("prog")
    assert st["weights"]["idor"] < 1.0     # FP rebaixou
    assert st["weights"]["oauth"] > 1.0     # achado subiu
    assert st["weights"]["bac"] > 1.0       # irmão promovido (§3 A→B)
    # e o ranking reflete: oauth (peso alto) vem antes de idor (peso baixo)
    leads = tm.enumerate_leads("prog")
    order = [x["cls"] for x in leads]
    assert order.index("oauth") < order.index("idor")


def test_untested_surface(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    rows = tm.untested_surface("prog")
    eps = {r["endpoint"] for r in rows}
    assert "/admin/config" in eps and "/api/v2/orders/{id}" in eps


def test_show_json_schema(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    st = tm.load("prog")
    for key in ("components", "auth_flows", "objects", "boundaries", "fingerprints", "verdicts", "weights"):
        assert key in st
