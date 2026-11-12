"""Registro de perfis do Carrasco e oráculo unauthenticated-read (offline, sem alvo real)."""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import carrasco as c


@pytest.fixture
def plan(monkeypatch):
    p = json.loads((c.ROOT / "examples/carrasco/unauthenticated-read.json").read_text())
    monkeypatch.setenv("CARRASCO_ACCOUNT_A", json.dumps({"Authorization": "Bearer SECRET_OWNER"}))
    monkeypatch.setenv("CARRASCO_REQUIRED_HEADERS", json.dumps({"X-Researcher": "lab"}))
    monkeypatch.setattr(c.RateLimiter, "wait", lambda self: None)
    return p


class Gate:
    def __init__(self):
        self.calls = []

    def check(self, url, method="GET"):
        self.calls.append(url)
        return "approved-test-revision"


class Transport:
    def __init__(self, plan, anon=(200, 200), control=200, readback=200, anon_marker=True):
        marker = plan["owner"]["marker"]
        shown = marker if anon_marker else "generic-login-page"
        self.rows = [(control, marker), (anon[0], shown), (anon[1], shown), (readback, marker)]
        self.calls = []

    def get(self, url, headers, timeout, max_bytes):
        self.calls.append((url, headers))
        status, marker = self.rows[len(self.calls) - 1]
        return status, json.dumps({"content": marker, "other": "PRIVATE_DATA"}).encode()


def run(plan, **kwargs):
    transport, saved = Transport(plan, **kwargs), []
    state = c.execute(plan, Gate(), transport, lambda s: saved.append(copy.deepcopy(s)))
    return state, transport, saved


def test_registry_lists_all_profiles():
    assert set(c.PROFILES) == {"cross-account-read", "unauthenticated-read", "cross-account-write"}
    assert c.PROFILES["unauthenticated-read"].REQUESTS == 4
    assert c.PROFILES["cross-account-read"].REQUESTS == 6
    assert c.PROFILES["cross-account-write"].REQUESTS == 5
    assert c.PROFILES["cross-account-write"].ATTACK_REQUESTS == 3


def test_example_validates_and_records_profile(plan):
    assert c.validate(plan) is plan
    state = c.new_state(plan)
    assert state["profile"] == "unauthenticated-read"


def test_confirmed_four_steps_and_anonymous_carries_no_credential(plan):
    state, transport, saved = run(plan)
    assert state["status"] == "confirmed"
    assert len(transport.calls) == 4
    # passo 0 e 3 = dono autenticado; passos 1 e 2 = anônimo sem credencial
    assert transport.calls[0][1]["authorization"] == "Bearer SECRET_OWNER"
    assert transport.calls[3][1]["authorization"] == "Bearer SECRET_OWNER"
    for anon in (transport.calls[1][1], transport.calls[2][1]):
        assert "authorization" not in anon and "cookie" not in anon
        assert anon["x-researcher"] == "lab"  # header comum obrigatório mantido
    text = json.dumps(saved)
    for forbidden in ("SECRET_OWNER", "PRIVATE_DATA", plan["owner"]["marker"], "/api/documents/"):
        assert forbidden not in text
    assert state["human_review_required"] is True


@pytest.mark.parametrize("options,status,steps", [
    ({}, "confirmed", 4),
    ({"anon": (403, 404)}, "refuted", 4),
    ({"anon": (401, 401)}, "refuted", 4),
    ({"anon_marker": False}, "inconclusive", 4),      # 200 sem marcador não é achado
    ({"anon": (200, 403)}, "inconclusive", 4),        # resposta ambígua
    ({"control": 401}, "inconclusive", 1),            # controle do dono falhou: para cedo
    ({"readback": 401}, "inconclusive", 4),           # sessão do dono não confirmada no fim
])
def test_unauthenticated_verdicts(plan, options, status, steps):
    state, transport, _ = run(plan, **options)
    assert state["status"] == status
    assert len(transport.calls) == steps


def test_requests_budget_must_match_profile(plan):
    plan["limits"]["requests"] = 6  # válido no cross-account-read, inválido aqui
    with pytest.raises(ValueError):
        c.validate(plan)


def test_unknown_profile_is_rejected(plan):
    plan["profile"] = "cross-account-write"
    with pytest.raises(ValueError):
        c.validate(plan)


def test_cross_account_keys_rejected_for_this_profile(plan):
    plan["accounts"] = plan.pop("owner")  # chaves do perfil errado
    with pytest.raises(ValueError):
        c.validate(plan)


@pytest.mark.parametrize("url", ["http://app.example.invalid/x", "https://u:p@app.example.invalid/x",
                                 "https://app.example.invalid/x?t=1", "https://app.example.invalid/x#f"])
def test_owner_url_is_validated(plan, url):
    plan["owner"]["url"] = url
    with pytest.raises(ValueError):
        c.validate(plan)


def test_owner_marker_must_be_synthetic(plan):
    plan["owner"]["marker"] = "not-a-carrasco-marker"
    with pytest.raises(ValueError):
        c.validate(plan)


def test_missing_owner_credential_fails(plan, monkeypatch):
    monkeypatch.delenv("CARRASCO_ACCOUNT_A")
    with pytest.raises(ValueError):
        c.execute(plan, Gate(), Transport(plan), lambda s: None)


def test_scope_checked_before_each_request(plan):
    state, transport, _ = run(plan)
    gate = Gate()
    c.execute(plan, gate, Transport(plan), lambda s: None)
    assert len(gate.calls) == 4  # um gate do Mind por requisição


def test_stage_uses_single_owner_asset(plan, monkeypatch, tmp_path):
    monkeypatch.setenv("EXCALIBULL_OUTBOX_DIR", str(tmp_path))
    monkeypatch.setenv("HIVE_HANDLE", "lab")
    monkeypatch.setenv("HIVE_TEAM_TAG", "test")
    state, _, _ = run(plan)
    path = c.stage(plan, state)
    text = path.read_text()
    assert "asset_refs:" in text and "carrasco" in text
    assert "PRIVATE_DATA" not in text and "SECRET_OWNER" not in text
