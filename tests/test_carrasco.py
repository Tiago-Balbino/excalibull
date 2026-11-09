"""Experimentos offline: decisões, gate, limites, privacidade e HTTP real em loopback."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import carrasco as c


@pytest.fixture
def plan(monkeypatch):
    p = json.loads((c.ROOT / "examples/carrasco/cross-account-read.json").read_text())
    monkeypatch.setenv("CARRASCO_ACCOUNT_A", json.dumps({"Authorization": "Bearer SECRET_A"}))
    monkeypatch.setenv("CARRASCO_ACCOUNT_B", json.dumps({"Cookie": "session=SECRET_B"}))
    monkeypatch.setenv("CARRASCO_REQUIRED_HEADERS", json.dumps({"X-Researcher": "lab"}))
    monkeypatch.setattr(c.RateLimiter, "wait", lambda self: None)
    return p


class Gate:
    def __init__(self, fail_at=None):
        self.calls = []
        self.fail_at = fail_at

    def check(self, url):
        self.calls.append(url)
        if len(self.calls) == self.fail_at:
            raise c.Blocked("denied")
        return "approved-test-revision"


class Transport:
    def __init__(self, plan, crosses=(200, 200), anonymous=403, control=200, readback=200):
        a, b = [plan["accounts"][k]["marker"] for k in ("a", "b")]
        self.rows = [(control, a), (200, b), (anonymous, "none"), (crosses[0], b), (crosses[1], b), (readback, b)]
        self.calls = []

    def get(self, url, headers, timeout, max_bytes):
        self.calls.append((url, headers))
        status, marker = self.rows[len(self.calls) - 1]
        return status, json.dumps({"content": marker, "other": "PRIVATE_DATA"}).encode()


def run(plan, **kwargs):
    transport, gate, saved = Transport(plan, **kwargs), Gate(), []
    state = c.execute(plan, gate, transport, lambda s: saved.append(copy.deepcopy(s)))
    return state, transport, gate, saved


def test_confirmed_requires_six_steps_and_no_secrets(plan):
    state, transport, gate, saved = run(plan)
    assert state["status"] == "confirmed"
    assert len(transport.calls) == len(gate.calls) == 6
    assert "authorization" not in transport.calls[2][1] and "cookie" not in transport.calls[2][1]
    assert transport.calls[3][1]["authorization"] == "Bearer SECRET_A"
    assert transport.calls[5][1]["cookie"] == "session=SECRET_B"
    text = json.dumps(saved)
    for forbidden in ("SECRET_A", "SECRET_B", "PRIVATE_DATA", plan["accounts"]["b"]["marker"], "/api/documents/"):
        assert forbidden not in text
    assert saved[1]["observations"][0]["state"] == "attempted"
    assert state["human_review_required"] is True


@pytest.mark.parametrize("options,status,steps", [
    ({"crosses": (403, 404)}, "refuted", 6),
    ({"crosses": (200, 403)}, "inconclusive", 6),
    ({"crosses": (401, 401)}, "inconclusive", 6),
    ({"anonymous": 200}, "inconclusive", 3),
    ({"control": 401}, "inconclusive", 1),
    ({"readback": 401}, "inconclusive", 6),
    ({"crosses": (429, 200)}, "blocked", 4),
])
def test_verdicts(plan, options, status, steps):
    state, transport, _, _ = run(plan, **options)
    assert state["status"] == status
    assert len(transport.calls) == steps


def test_200_without_marker_is_not_finding(plan):
    transport = Transport(plan)
    transport.rows[3] = transport.rows[4] = (200, "generic login page")
    state = c.execute(plan, Gate(), transport, lambda s: None)
    assert state["status"] == "inconclusive"


def test_scope_checked_before_every_request_and_failure_stops(plan):
    transport = Transport(plan)
    gate = Gate(fail_at=4)
    state = c.execute(plan, gate, transport, lambda s: None)
    assert state["status"] == "blocked"
    assert len(gate.calls) == 4 and len(transport.calls) == 3


def test_mind_gate_requires_exact_approved_revision(plan):
    class Client:
        def context(self, program, asset, question):
            assert program == plan["program_id"]
            assert asset == {"type": "url_prefix", "value": plan["accounts"]["a"]["url"]}
            return {"scope": {"confirmed": True, "status": "authorized", "action_allowed": True,
                              "scope_revision": "different-revision"}}
    with pytest.raises(c.Blocked):
        c.MindGate(Client(), plan).check(plan["accounts"]["a"]["url"])


@pytest.mark.parametrize("field,value", [("confirmed", False), ("status", "unknown"), ("action_allowed", False)])
def test_mind_gate_flags(plan, field, value):
    class Client:
        def context(self, *args):
            scope = {"confirmed": True, "status": "authorized", "action_allowed": True,
                     "scope_revision": plan["policy"]["scope_revision"]}
            scope[field] = value
            return {"scope": scope}
    with pytest.raises(c.Blocked):
        c.MindGate(Client(), plan).check(plan["accounts"]["a"]["url"])


@pytest.mark.parametrize("url", ["http://example.invalid/a", "https://user:pass@example.invalid/a",
                                      "https://app.example.invalid/a?token=x", "https://app.example.invalid/a#x"])
def test_invalid_urls(plan, url):
    plan["accounts"]["a"]["url"] = url
    with pytest.raises(ValueError):
        c.validate(plan)


@pytest.mark.parametrize("policy", ["reviewed", "automation_allowed", "owned_test_accounts", "private_objects"])
def test_missing_policy_review_blocks(plan, policy):
    plan["policy"][policy] = False
    with pytest.raises(ValueError):
        c.validate(plan)


def test_env_credentials_are_required_and_distinct(plan, monkeypatch):
    monkeypatch.delenv("CARRASCO_ACCOUNT_A")
    with pytest.raises(ValueError):
        c.execute(plan, Gate(), Transport(plan), lambda s: None)


def test_shared_headers_cannot_contain_credentials(plan, monkeypatch):
    monkeypatch.setenv("CARRASCO_REQUIRED_HEADERS", '{"Cookie":"SECRET"}')
    with pytest.raises(ValueError):
        c.execute(plan, Gate(), Transport(plan), lambda s: None)


def test_scope_outage_is_blocked(plan):
    gate = Gate()
    def fail(url):
        raise c.HiveError("unavailable")
    gate.check = fail
    transport = Transport(plan)
    state = c.execute(plan, gate, transport, lambda s: None)
    assert state["status"] == "blocked" and not transport.calls


def test_network_error_preserves_attempt(plan):
    transport = Transport(plan)
    def fail(*args):
        raise TimeoutError("SECRET")
    transport.get = fail
    state = c.execute(plan, Gate(), transport, lambda s: None)
    assert state["status"] == "inconclusive"
    assert state["observations"][0]["state"] == "attempted"
    assert "SECRET" not in json.dumps(state)


def test_stage_reuses_outbox_and_has_assets(plan, monkeypatch, tmp_path):
    monkeypatch.setenv("EXCALIBULL_OUTBOX_DIR", str(tmp_path))
    monkeypatch.setenv("HIVE_HANDLE", "lab")
    monkeypatch.setenv("HIVE_TEAM_TAG", "test")
    state, _, _, _ = run(plan)
    path = c.stage(plan, state)
    text = path.read_text()
    assert "asset_refs:" in text and "result:" in text and "carrasco" in text
    assert "PRIVATE_DATA" not in text and "SECRET" not in text
    assert state["publication"] == "pending"


def test_validate_cli_sends_no_traffic(plan, tmp_path, capsys):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    assert c.main(["validate", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["traffic_sent"] is False


def test_submit_spawns_only_known_worker_and_persists_snapshot(plan, monkeypatch, tmp_path):
    monkeypatch.setattr(c, "JOBS", tmp_path / "jobs")
    monkeypatch.setenv("HIVE_HANDLE", "lab")
    monkeypatch.setenv("HIVE_TEAM_TAG", "test")
    calls = []
    def spawn(argv, **kwargs):
        calls.append((argv, kwargs))
        return type("Process", (), {"pid": 12345})()
    monkeypatch.setattr(c.subprocess, "Popen", spawn)
    job = c.submit(plan)
    assert calls[0][0][:3] == [sys.executable, str(Path(c.__file__).resolve()), "run"]
    assert calls[0][1]["start_new_session"] is True
    assert "shell" not in calls[0][1]
    assert json.loads((c.job_directory(job) / "plan.json").read_text()) == plan
    assert c.job_status(job)["status"] == "queued"
    assert c.wait_job(job, 0.01)["finished"] is False
    assert len(calls) == 1  # Aguardar não reenvia o experimento.
    assert "SECRET" not in (c.job_directory(job) / "plan.json").read_text()


def test_wait_distinguishes_staging_in_progress_from_finished(plan, monkeypatch, tmp_path):
    monkeypatch.setattr(c, "JOBS", tmp_path)
    job = "a" * 32
    directory = c.job_directory(job)
    directory.mkdir()
    state = c.new_state(plan)
    state.update(status="confirmed", publication="preparing")
    c.private_write(directory / "result.json", json.dumps(state))
    assert c.job_status(job)["finished"] is False
    state["publication"] = "staged"
    c.private_write(directory / "result.json", json.dumps(state))
    assert c.wait_job(job, 1)["finished"] is True


def test_background_worker_mind_outage_persists_blocked_and_stages(plan, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(c, "JOBS", tmp_path / "jobs")
    monkeypatch.setenv("HIVE_HANDLE", "lab")
    monkeypatch.setenv("HIVE_TEAM_TAG", "test")
    monkeypatch.setenv("EXCALIBULL_OUTBOX_DIR", str(tmp_path / "outbox"))
    def unavailable():
        raise c.HiveError("SECRET_TOKEN")
    monkeypatch.setattr(c, "HiveClient", unavailable)
    job = "b" * 32
    directory = c.job_directory(job)
    directory.mkdir(parents=True)
    path = directory / "plan.json"
    path.write_text(json.dumps(plan))
    assert c.main(["run", str(path), "--job", job]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "blocked" and output["publication"] == "staged"
    state = json.loads((directory / "result.json").read_text())
    assert not state["observations"] and "SECRET_TOKEN" not in json.dumps(state)
    assert c.job_status(job)["finished"] is True
    assert c.main(["run", str(path), "--job", job]) == 2
    assert json.loads((directory / "result.json").read_text()) == state


def test_stage_recovery_checks_plan_hash_and_sends_no_traffic(plan, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HIVE_HANDLE", "lab")
    monkeypatch.setenv("HIVE_TEAM_TAG", "test")
    monkeypatch.setenv("EXCALIBULL_OUTBOX_DIR", str(tmp_path / "outbox"))
    state, _, _, _ = run(plan)
    path, result = tmp_path / "plan.json", tmp_path / "result.json"
    path.write_text(json.dumps(plan))
    result.write_text(json.dumps(state))
    assert c.main(["stage", str(path), str(result)]) == 0
    assert json.loads(result.read_text())["publication"] == "staged"
    plan["hypothesis"] = "changed"
    path.write_text(json.dumps(plan))
    assert c.main(["stage", str(path), str(result)]) == 2


@pytest.mark.parametrize("budget,value", [("requests", 7), ("rate", float("nan")), ("rate", 0), ("response_bytes", 2000000)])
def test_invalid_budgets(plan, budget, value):
    plan["limits"][budget] = value
    with pytest.raises(ValueError):
        c.validate(plan)


def test_nested_pointer_uses_exact_value():
    assert c.pointer_value(b'{"a/b":[{"~key":"yes"}]}', "/a~1b/0/~0key") == "yes"


def test_required_headers_cannot_be_overwritten(plan, monkeypatch):
    monkeypatch.setenv("CARRASCO_ACCOUNT_A", '{"Authorization":"Bearer TEST", "X-Researcher":"other"}')
    with pytest.raises(ValueError):
        c.execute(plan, Gate(), Transport(plan), lambda s: None)


def test_real_background_process_waits_and_stages_with_fake_mind(plan, tmp_path):
    # Processo real, launcher MCP sintético; nenhum alvo ou serviço remoto.
    checkout = tmp_path / "checkout"
    shutil.copytree(c.ROOT / "tools", checkout / "tools", ignore=shutil.ignore_patterns("__pycache__"))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    hive = bin_dir / "hive"
    hive.write_text("#!" + sys.executable + "\n" + '''import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg["method"]
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "lab", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": n} for n in ["hive_search", "hive_get_context"]]}
    else:
        args = msg["params"].get("arguments", {})
        data = {"items": []}
        if msg["params"]["name"] == "hive_get_context":
            data = {"program_id": args["program_id"], "asset": args["asset"],
                    "scope": {"status": "out_of_scope", "confirmed": False, "action_allowed": False, "scope_revision": "lab"}}
        result = {"structuredContent": data}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
''')
    hive.chmod(0o700)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    env = {**os.environ, "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
           "HIVE_HANDLE": "lab", "HIVE_TEAM_TAG": "test", "EXCALIBULL_OUTBOX_DIR": str(tmp_path / "outbox")}
    cli = [sys.executable, str(checkout / "tools" / "carrasco.py")]
    submitted = subprocess.run([*cli, "submit", str(path)], env=env, capture_output=True, text=True, timeout=10, check=True)
    job = json.loads(submitted.stdout)["job_id"]
    waited = subprocess.run([*cli, "wait", job, "--seconds", "10"], env=env, capture_output=True, text=True, timeout=15, check=True)
    result = json.loads(waited.stdout)
    assert result["finished"] is True and result["status"] == "blocked"
    assert result["publication"] == "staged"
    state = json.loads(Path(result["result"]).read_text())
    assert state["observations"] == []
    assert list((tmp_path / "outbox" / "programs").rglob("*.md"))


def test_transport_never_follows_redirect_or_saves_cookies():
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.path)
            self.send_response(302 if self.path == "/redirect" else 200)
            self.send_header("Location", "/other")
            self.send_header("Set-Cookie", "session=DO_NOT_REUSE")
            self.end_headers()
            self.wfile.write(b"{}")
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = c.Transport()
        base = "http://127.0.0.1:" + str(server.server_port)
        assert transport.get(base + "/redirect", {"Authorization": "Bearer TEST"}, 2, 100)[0] == 302
        assert calls == ["/redirect"]
        with pytest.raises(ValueError):
            transport.get(base + "/large", {}, 2, 1)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
