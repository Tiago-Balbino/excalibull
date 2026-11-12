"""Headers obrigatórios do programa (ex.: Deriv: X-HackerOne-Research) via EXCALIBULL_REQUIRED_HEADERS.

O recon é anônimo: o env injeta só headers de identificação, nunca credencial/transporte,
e só no http_get (alvo), não nas fontes passivas de terceiros.
"""
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import netcommon as nc  # noqa: E402


@pytest.fixture
def capture(monkeypatch):
    seen = {}

    def fake_open(req, timeout=None):
        seen["headers"] = {k.lower(): v for k, v in req.headers.items()}
        raise urllib.error.URLError("stop-after-capture")

    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    return seen


def test_required_header_injected_on_every_get(monkeypatch, capture):
    monkeypatch.setenv("EXCALIBULL_REQUIRED_HEADERS", '{"X-HackerOne-Research":"lab"}')
    nc.http_get("http://127.0.0.1:1/x", retries=0)
    assert capture["headers"].get("x-hackerone-research") == "lab"


def test_explicit_headers_do_not_drop_required(monkeypatch, capture):
    monkeypatch.setenv("EXCALIBULL_REQUIRED_HEADERS", '{"X-HackerOne-Research":"lab"}')
    nc.http_get("http://127.0.0.1:1/x", headers={"X-Extra": "1"}, retries=0)
    assert capture["headers"].get("x-hackerone-research") == "lab"
    assert capture["headers"].get("x-extra") == "1"


def test_absent_env_is_noop(monkeypatch, capture):
    monkeypatch.delenv("EXCALIBULL_REQUIRED_HEADERS", raising=False)
    assert nc.required_headers() == {}
    nc.http_get("http://127.0.0.1:1/x", retries=0)
    assert "x-hackerone-research" not in capture["headers"]


@pytest.mark.parametrize("bad", [
    '{"Authorization":"Bearer x"}',
    '{"Cookie":"a=b"}',
    '{"User-Agent":"spoof"}',
    '{"Host":"evil"}',
    '["not","an","object"]',
    '{"X Bad Name":"v"}',
    '{"X-H":"val\\u0001com-controle"}',
])
def test_rejects_credentials_transport_and_malformed(monkeypatch, bad):
    monkeypatch.setenv("EXCALIBULL_REQUIRED_HEADERS", bad)
    with pytest.raises(ValueError):
        nc.required_headers()
