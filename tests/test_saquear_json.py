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


def test_saquear_consumes_emitted_contract(monkeypatch):
    # jsrecon emite → saquear consome
    js = {"api_endpoints": ["/api/v2/x", "no-slash"],
          "fingerprints": [{"name": "Hasura GraphQL", "playbook": "..."}]}
    assert saquear.endpoints_from_jsrecon("h.io", js) == ["h.io /api/v2/x"]
    assert [f["name"] for f in saquear.stacks_from_jsrecon(js)] == ["Hasura GraphQL"]
    pv = {"delta_prod": ["novo.ex.com"], "prod": ["novo.ex.com", "velho.ex.com"]}
    assert saquear.new_hosts_from_passive(pv) == ["novo.ex.com"]
    assert saquear.parse_json("lixo{{") is None
