#!/usr/bin/env python3
"""Contrato JSON entre saquear.py e os sub-tools (passive/jsrecon --json).

Verifica offline (mock de rede) que:
  - jsrecon --json EMITE as chaves que o saquear CONSOME;
  - passive --json EMITE prod/delta_prod;
  - os helpers de consumo do saquear leem esse JSON corretamente.
"""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import jsrecon  # noqa: E402
import passive  # noqa: E402
import saquear  # noqa: E402


def _run_json(mod, argv, monkeypatch):
    monkeypatch.setattr(sys, "argv", argv)
    buf = io.StringIO()
    with redirect_stdout(buf):
        mod.main()
    return json.loads(buf.getvalue())


def test_jsrecon_json_emits_contract_keys(monkeypatch):
    html = ('<html><script>var u="/api/v2/users/me";</script>'
            '<!-- _next/static --></html>')

    def fake_fetch(url, timeout=15):
        return (html, 200) if url.endswith("example") or "://x.example" in url else ("", 0)

    monkeypatch.setattr(jsrecon, "fetch", fake_fetch)
    out = _run_json(jsrecon, ["jsrecon.py", "https://x.example", "--json", "--max-js", "1"], monkeypatch)
    for key in ("api_endpoints", "other_paths", "hosts", "fingerprints", "secrets_masked"):
        assert key in out, f"jsrecon --json faltou a chave {key}"
    assert "/api/v2/users/me" in out["api_endpoints"]
    assert any(fp["name"] == "Next.js" for fp in out["fingerprints"])


def test_passive_json_emits_prod_and_delta(monkeypatch):
    # patcha as TUPLAS de fontes (montadas no import) → hermético, sem rede
    monkeypatch.setattr(passive, "_HOST_SOURCES",
                        (("crt.sh", lambda d: ({f"app.{d}"}, "ok")),))
    monkeypatch.setattr(passive, "_URL_SOURCES", ())
    out = _run_json(passive, ["passive.py", "ex.com", "--json", "--cache-ttl", "0"], monkeypatch)
    assert "prod" in out and "delta_prod" in out
    assert "app.ex.com" in out["prod"]
    assert out["delta_prod"] is None  # sem --diff-program


def test_classify_env_labels_environments():
    cases = {
        "app.ex.com": "prod", "ex.com": "prod",
        "staging.ex.com": "staging", "stage-1.ex.com": "staging",
        "api-dev.ex.com": "dev", "devnet.ex.com": "dev",
        "qa.ex.com": "qa", "uat.ex.com": "uat", "sandbox.ex.com": "sandbox",
        "internal.ex.com": "internal", "sepolia.ex.com": "testnet",
        "x.testnet.ex.com": "testnet", "e2e.ex.com": "test",
    }
    for host, env in cases.items():
        assert passive.classify_env(host) == env, host


def test_passive_json_inventory_preserves_prod_and_nonprod(monkeypatch):
    # duas fontes, prod + não-prod; proveniência por ativo deve ser agregada
    monkeypatch.setattr(passive, "_HOST_SOURCES",
                        (("crt.sh", lambda d: ({f"app.{d}", f"staging.{d}"}, "ok")),
                         ("otx", lambda d: ({f"app.{d}", f"qa.{d}"}, "ok"))))
    monkeypatch.setattr(passive, "_URL_SOURCES", ())
    out = _run_json(passive, ["passive.py", "ex.com", "--json", "--cache-ttl", "0"], monkeypatch)
    assert "inventory" in out
    inv = {e["host"]: e for e in out["inventory"]}
    # prod E não-prod preservados no mesmo inventário (não só um contador lateral)
    assert set(inv) == {"app.ex.com", "staging.ex.com", "qa.ex.com"}
    assert inv["app.ex.com"]["environment"] == "prod" and inv["app.ex.com"]["prod"] is True
    assert inv["staging.ex.com"]["environment"] == "staging" and inv["staging.ex.com"]["prod"] is False
    assert inv["qa.ex.com"]["environment"] == "qa"
    # proveniência por ativo agregada entre fontes
    assert inv["app.ex.com"]["sources"] == ["crt.sh", "otx"]
    assert inv["qa.ex.com"]["sources"] == ["otx"]
    # escopo e autorização: nenhum ativo passivo é sondável sem contexto ao vivo
    for e in out["inventory"]:
        assert e["in_scope"] is True
        assert e["probe_authorization"] == "pending-per-asset"
        assert e["new"] is None  # sem --diff-program não há baseline


def test_passive_inventory_new_flag_tracks_local_baseline(monkeypatch, tmp_path):
    base = tmp_path / "programs" / "prog"
    base.mkdir(parents=True)
    (base / "known.md").write_text("conhecido: app.ex.com", encoding="utf-8")
    monkeypatch.setattr(passive, "_HOST_SOURCES",
                        (("crt.sh", lambda d: ({f"app.{d}", f"novo.{d}", f"dev.{d}"}, "ok")),))
    monkeypatch.setattr(passive, "_URL_SOURCES", ())
    from hive_workspace import _program, resolve_data_dir  # noqa: F401
    monkeypatch.setattr(passive, "_program", _program, raising=False)
    out = _run_json(passive, ["passive.py", "ex.com", "--json", "--cache-ttl", "0",
                              "--diff-program", "prog", "--data-dir", str(tmp_path)], monkeypatch)
    inv = {e["host"]: e for e in out["inventory"]}
    assert inv["app.ex.com"]["new"] is False      # já no baseline local
    assert inv["novo.ex.com"]["new"] is True       # ausente no staging
    assert inv["dev.ex.com"]["new"] is True and inv["dev.ex.com"]["environment"] == "dev"


def test_saquear_consumes_inventory_contract():
    pv = {"inventory": [
        {"host": "staging.ex.com", "environment": "staging", "prod": False,
         "sources": ["crt.sh"], "in_scope": True, "new": True,
         "probe_authorization": "pending-per-asset"},
        "lixo-nao-dict",
    ]}
    inv = saquear.inventory_from_passive(pv)
    assert [e["host"] for e in inv] == ["staging.ex.com"]  # itens inválidos descartados
    assert inv[0]["environment"] == "staging"
    assert saquear.inventory_from_passive({}) == []
    assert saquear.inventory_from_passive(None) == []


def test_saquear_consumes_emitted_contract(monkeypatch):
    # jsrecon emite → saquear consome
    js = {"api_endpoints": ["/api/v2/x", "no-slash"],
          "fingerprints": [{"name": "Hasura GraphQL", "playbook": "..."}]}
    assert saquear.endpoints_from_jsrecon("h.io", js) == ["h.io /api/v2/x"]
    assert [f["name"] for f in saquear.stacks_from_jsrecon(js)] == ["Hasura GraphQL"]
    pv = {"delta_prod": ["novo.ex.com"], "prod": ["novo.ex.com", "velho.ex.com"]}
    assert saquear.new_hosts_from_passive(pv) == ["novo.ex.com"]
    assert saquear.parse_json("lixo{{") is None
