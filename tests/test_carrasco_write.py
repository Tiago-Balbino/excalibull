"""Perfil cross-account-write: política de efeitos, leitura de volta e LIMPEZA obrigatória.

Transporte stateful em memória; nenhum alvo, serviço remoto ou tráfego real.
"""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import carrasco as c


@pytest.fixture
def wplan(monkeypatch):
    p = json.loads((c.ROOT / "examples/carrasco/cross-account-write.json").read_text())
    monkeypatch.setenv("CARRASCO_ACCOUNT_A", json.dumps({"Authorization": "Bearer SECRET_A"}))
    monkeypatch.setenv("CARRASCO_ACCOUNT_B", json.dumps({"Cookie": "session=SECRET_B"}))
    monkeypatch.setenv("CARRASCO_REQUIRED_HEADERS", json.dumps({"X-Researcher": "lab"}))
    monkeypatch.setattr(c.RateLimiter, "wait", lambda self: None)
    return p


class Gate:
    def check(self, url):
        return "approved-test-revision"


class WriteTransport:
    """Objeto em memória: a escrita do atacante só "pega" se aceita; o dono sempre restaura."""
    def __init__(self, wplan, *, attacker_write=200, control=200, readback=200, verify=200,
                 owner_write=200, verify_tampered=False):
        self.stored = wplan["target"]["marker"]
        self.get_status = [control, readback, verify]
        self.attacker_write, self.owner_write, self.verify_tampered = attacker_write, owner_write, verify_tampered
        self.gets = 0
        self.calls = []

    def get(self, url, headers, timeout, max_bytes):
        self.calls.append(("GET", headers))
        idx = self.gets
        self.gets += 1
        status = self.get_status[min(idx, len(self.get_status) - 1)]
        shown = "carrasco-tampered0000tamper" if (idx == 2 and self.verify_tampered) else self.stored
        return status, json.dumps({"content": shown, "other": "PRIVATE_DATA"}).encode()

    def send(self, url, headers, method, body, timeout, max_bytes):
        self.calls.append((method, headers))
        payload = json.loads(body)
        if "cookie" in headers:  # dono restaurando o próprio objeto
            self.stored = payload["content"]
            return self.owner_write, b"{}"
        if self.attacker_write in (200, 201, 202, 204):  # escrita cruzada aceita pelo servidor
            self.stored = payload["content"]
        return self.attacker_write, b"{}"


def wrun(wplan, **kwargs):
    transport, saved = WriteTransport(wplan, **kwargs), []
    state = c.execute(wplan, Gate(), transport, lambda s: saved.append(copy.deepcopy(s)))
    return state, transport, saved


def test_write_example_validates(wplan):
    assert c.validate(wplan) is wplan


def test_write_confirmed_restores_and_isolates_sessions(wplan):
    state, transport, saved = wrun(wplan)
    assert state["status"] == "confirmed"
    assert state["cleanup"] == "restored"
    assert state["attack_status"] == "confirmed"
    assert transport.stored == wplan["target"]["marker"]  # objeto volta ao original
    kinds = [k for k, _ in transport.calls]
    assert kinds == ["GET", "PATCH", "GET", "PATCH", "GET"]
    # escrita do atacante leva credencial de A, nunca o cookie do dono
    assert transport.calls[1][1]["authorization"] == "Bearer SECRET_A"
    assert "cookie" not in transport.calls[1][1]
    # limpeza/verificação usam o dono (cookie), nunca a credencial do atacante
    for owner_step in (transport.calls[3][1], transport.calls[4][1]):
        assert owner_step["cookie"] == "session=SECRET_B" and "authorization" not in owner_step
    text = json.dumps(saved)
    for forbidden in ("SECRET_A", "SECRET_B", "PRIVATE_DATA",
                      wplan["target"]["marker"], wplan["write"]["marker"]):
        assert forbidden not in text


def test_write_refuted_when_denied_object_intact(wplan):
    state, transport, _ = wrun(wplan, attacker_write=403)
    assert state["status"] == "refuted"
    assert state["cleanup"] == "restored"
    assert transport.stored == wplan["target"]["marker"]


def test_write_control_failure_does_not_write_or_clean(wplan):
    state, transport, _ = wrun(wplan, control=401)
    assert state["status"] == "inconclusive"
    assert "cleanup" not in state  # nenhuma escrita tentada → nada a restaurar
    assert [k for k, _ in transport.calls] == ["GET"]


def test_write_cleanup_runs_even_when_attack_blocked_midway(wplan):
    # readback devolve 429 (Blocked) depois que o atacante já escreveu
    state, transport, _ = wrun(wplan, readback=429)
    assert state["status"] == "blocked"
    assert state["cleanup"] == "restored"
    assert transport.stored == wplan["target"]["marker"]  # restaurado apesar do bloqueio
    assert [k for k, _ in transport.calls] == ["GET", "PATCH", "GET", "PATCH", "GET"]


def test_write_cleanup_failure_is_failed_and_flags_manual_restoration(wplan):
    state, _, _ = wrun(wplan, verify_tampered=True)
    assert state["status"] == "failed"
    assert state["reason"] == "cleanup_unverified"
    assert state["manual_restoration_required"] is True


def test_write_cleanup_rejected_is_failed(wplan):
    state, _, _ = wrun(wplan, owner_write=500)
    assert state["status"] == "failed"
    assert state["manual_restoration_required"] is True


def test_write_requires_effects_policy(wplan):
    del wplan["policy"]["effects"]
    with pytest.raises(ValueError):
        c.validate(wplan)


@pytest.mark.parametrize("flag", ["reversible", "idempotent_write", "own_objects_only", "no_third_party_data"])
def test_write_effects_flags_must_be_true(wplan, flag):
    wplan["policy"]["effects"][flag] = False
    with pytest.raises(ValueError):
        c.validate(wplan)


def test_write_marker_must_differ_from_original(wplan):
    wplan["write"]["marker"] = wplan["target"]["marker"]
    wplan["write"]["body"]["content"] = wplan["target"]["marker"]
    with pytest.raises(ValueError):
        c.validate(wplan)


def test_write_body_must_place_marker_at_pointer(wplan):
    wplan["write"]["body"] = {"content": "carrasco-elsewhere000000different"}  # não bate com write.marker
    with pytest.raises(ValueError):
        c.validate(wplan)


def test_cleanup_body_must_restore_original_marker(wplan):
    wplan["cleanup"]["body"] = {"content": "carrasco-wrongrestore0000wrong00"}
    with pytest.raises(ValueError):
        c.validate(wplan)


@pytest.mark.parametrize("method", ["GET", "DELETE", "POST", "post"])
def test_write_method_restricted_to_patch_put(wplan, method):
    wplan["write"]["method"] = method
    with pytest.raises(ValueError):
        c.validate(wplan)


def test_attacker_and_owner_need_distinct_envs(wplan):
    wplan["attacker"]["headers_env"] = wplan["target"]["headers_env"]
    with pytest.raises(ValueError):
        c.validate(wplan)


def test_write_transport_rejects_non_patch_put():
    with pytest.raises(ValueError):
        c.Transport().send("https://app.example.invalid/a", {}, "DELETE", b"{}", 2, 10)
