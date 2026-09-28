"""Integração offline: instância/destinos, casa nova, recon e monitor de números."""
import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import active_recon
import cors_headers_scan
import hive_instance
import hive_workspace
import saquear
import session_monitor


@pytest.fixture
def writer(tmp_path, monkeypatch):
    root = tmp_path / "hive"
    data = tmp_path / "data"
    (root / "config").mkdir(parents=True)
    (root / "bin").mkdir()
    (root / "config/hive.toml").write_text(f'HIVE_DATA_DIR = {json.dumps(str(data))}\nHIVE_ROLE = "writer"\nSECRET = "NEVER-EXPORT"\n')
    (root / "bin/hive-teste").write_text("launcher")
    monkeypatch.setenv("HIVE_INSTANCE_DIR", str(root))
    monkeypatch.setenv("EXCALIBULL_BRAIN_DIR", str(tmp_path / "brain"))
    monkeypatch.delenv("HIVE_DATA_DIR", raising=False)
    monkeypatch.delenv("HIVE_BIN", raising=False)
    return root, data


def test_workspace_exports_only_metadata_and_rejects_divergence(writer, tmp_path):
    root, data = writer
    info = hive_instance.workspace()
    assert info["data_dir"] == str(data)
    assert info["instance_root"] == str(root)
    assert "NEVER-EXPORT" not in json.dumps(info)
    assert "SECRET" not in info
    with pytest.raises(ValueError, match="diverge"):
        hive_instance.workspace(str(tmp_path / "different"), writer=True)
    (root / "config/hive.toml").write_text(f'HIVE_DATA_DIR = {json.dumps(str(data))}\nHIVE_ROLE = "reader"\n')
    assert hive_instance.workspace()["role"] == "reader"
    with pytest.raises(ValueError, match="reader"):
        hive_instance.workspace(writer=True)


def test_ingest_uses_same_instance_launcher_and_blocks_wrong_binary(writer, monkeypatch):
    root, data = writer
    calls = []
    monkeypatch.setattr(hive_workspace.subprocess, "run", lambda cmd, **kwargs: calls.append((cmd, kwargs)) or SimpleNamespace(returncode=0))
    args = argparse.Namespace(data_dir=None, instance=None, hive_bin=None)
    assert hive_workspace.cmd_ingest(args) == 0
    assert calls == [([str(root / "bin/hive-teste"), "ingest"], {"cwd": str(root), "check": False})]
    args.hive_bin = "/different/hive"
    with pytest.raises(ValueError, match="diverge"):
        hive_workspace.cmd_ingest(args)
    assert len(calls) == 1


def test_casa_nova_normalizes_id_and_never_overwrites_or_approves_scope(writer, tmp_path, capsys):
    root, data = writer
    body = tmp_path / "body.md"
    body.write_text("Fonte: informações fornecidas pelo operador.\nAtivo observado: app.example.\n")
    argv = ["create-program", "--name", "Alvo Ágil", "--platform", "hackerone", "--handle", "alice", "--input", str(body)]
    assert hive_workspace.main(argv) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["program_id"] == "alvo-agil"
    folder = data / "programs/alvo-agil"
    profile = Path(result["files"][0])
    original = profile.read_text()
    assert "Alvo Ágil" in original and "hackerone" in original
    assert not (folder / "scope.json").exists() and not (folder / "rules.md").exists()
    assert hive_workspace.main(argv) == 2
    assert profile.read_text() == original
    body.write_text("Authorization: Bearer SECRET")
    argv[2] = "Another"
    assert hive_workspace.main(argv) == 2
    assert not (data / "programs/another").exists()


def test_active_recon_gates_every_child_and_reports_limit(monkeypatch):
    calls = []
    monkeypatch.setattr(active_recon, "authorized", lambda url, program: "/denied" not in url)
    def fake_get(url, **kwargs):
        kwargs["authorize"](url)
        calls.append(url)
        return ('<a href="/yes">yes</a><a href="/denied">deny</a><a href="https://outside.example/">outside</a>' if url.endswith("/") else "", 200)
    monkeypatch.setattr(active_recon, "http_get", fake_get)
    data = active_recon.crawl("example", "https://app.example/", max_pages=10)
    assert "https://app.example/denied" not in calls
    assert "https://outside.example/" not in calls
    assert data["coverage"]["status"] == "partial"
    assert data["coverage"]["blocked"] == ["app.example/denied"]
    limited = active_recon.crawl("example", "https://app.example/", max_pages=1)
    assert limited["coverage"]["pages_pending"] == 2


def test_cors_checks_redirect_and_marks_unexecuted_probes(monkeypatch):
    monkeypatch.setattr(cors_headers_scan, "_PROGRAM", "example")
    monkeypatch.setattr(cors_headers_scan, "authorized", lambda url, program: "outside" not in url)
    monkeypatch.setattr(cors_headers_scan._LIMITER, "wait", lambda: None)
    calls = []
    class Session:
        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            return SimpleNamespace(status_code=302, headers={"Location": "https://outside.example/"})
    with pytest.raises(PermissionError):
        cors_headers_scan.checked_get(Session(), "https://app.example/", timeout=1)
    assert len(calls) == 1 and calls[0][1]["allow_redirects"] is False
    results = cors_headers_scan.test_cors(Session(), "https://app.example/", 1, True)
    assert len(results) == 5 and all(r["incomplete"] for r in results)
    assert all(r["check"].startswith("cors-incomplete") for r in results)


def test_monitor_no_guessed_tokens_deduplicates_usage_and_marks_time(writer, tmp_path, capsys):
    assert session_monitor.main(["start", "example", "--mode", "hunter", "--posture", "lanca"]) == 0
    path, state = session_monitor.load_active()
    assert session_monitor.totals(state)["tokens"] is None
    assert session_monitor.main(["where", "--protocol", "one-piece"]) == 0
    assert session_monitor.record("hive", "hive_search", duration_ms=25, program="example")
    assert not session_monitor.record("tool", "wrong-program", duration_ms=99, program="other")
    values = {"input_tokens": 100, "output_tokens": 20, "cached_input_tokens": 50, "source": "executor", "secret": "NEVER-EXPORT"}
    assert session_monitor.record("usage", "model", values=values, event_id="batch:1")
    assert not session_monitor.record("usage", "model", values=values, event_id="batch:1")
    assert session_monitor.main(["finding", "bug-1", "--confirmed"]) == 0
    path, state = session_monitor.load_active()
    assert state["findings"][0]["confirmed"] is True
    assert state["findings"][0]["metrics_at_finding"]["elapsed_wall_seconds"] >= 0
    metrics = session_monitor.totals(state)
    assert metrics["tokens"]["total_tokens"] == 120
    assert metrics["tokens"]["cached_input_tokens"] == 50
    assert metrics["hive_calls"] == 1 and metrics["hive_duration_ms_reported"] == 25
    assert state["findings"][0]["context"]["protocol"] == "one-piece"
    assert "NEVER-EXPORT" not in path.read_text()
    assert session_monitor.main(["finding", "candidate-2"]) == 0
    assert session_monitor.main(["finding", "candidate-2", "--confirmed"]) == 0
    _, state = session_monitor.load_active()
    assert len(state["findings"]) == 2
    assert state["findings"][1]["confirmed_at"]
    with pytest.raises(ValueError):
        session_monitor.record("hive", "bad-duration", duration_ms=float("nan"))
    with pytest.raises(ValueError):
        session_monitor.usage({"input_tokens": -1, "output_tokens": 20})
    assert session_monitor.main(["stop"]) == 0
    assert session_monitor.load_active() == (None, None)
    note = next(writer[1].glob("programs/example/notes/*monitor*.md"))
    assert "pending-ingest-idle-readback" in note.read_text()


def test_monitor_missing_cache_is_unknown_and_keeps_observed_counts(writer):
    session_monitor.main(["start", "example"])
    session_monitor.record("usage", "model", values={"input_tokens": 100, "output_tokens": 20}, event_id="interval-1")
    _, state = session_monitor.load_active()
    assert session_monitor.totals(state)["tokens"]["cached_input_tokens"] is None
    session_monitor.record("usage", "model", values={"input_tokens": 80, "output_tokens": 10, "cached_input_tokens": 40}, event_id="interval-2")
    _, state = session_monitor.load_active()
    tokens = session_monitor.totals(state)["tokens"]
    assert tokens["total_tokens"] == 210
    assert tokens["cached_input_tokens"] is None
    assert tokens["cached_input_tokens_reported"] == 40
    assert tokens["cached_input_samples"] == 1


def test_saquear_preserves_partial_results_and_does_not_probe_discovered_hosts(writer, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(saquear, "authorized", lambda url, program: True)
    def fake_run(cmd, timeout=300):
        calls.append(cmd)
        if cmd[0] == "passive.py":
            return json.dumps({"delta_prod": ["new.example"], "sources": []}), "", 0
        if cmd[0] == "active_recon.py":
            return json.dumps({"records": [], "coverage": {"status": "partial"}}), "", 1
        if cmd[0] == "jsrecon.py":
            return "invalid-json", "", 2
        return "", "", 0
    monkeypatch.setattr(saquear, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["saquear", "example", "--domains", "example", "--hosts", "app.example", "--cors", "--scratch", str(tmp_path / "scratch")])
    assert saquear.main() == 1
    assert all("https://new.example/" not in cmd for cmd in calls)
    assert any(cmd[0] == "cors_headers_scan.py" for cmd in calls)
    report = json.loads((tmp_path / "scratch/saquear-coverage.json").read_text())
    assert report["status"] == "partial"
