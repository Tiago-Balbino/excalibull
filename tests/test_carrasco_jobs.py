"""Ciclo de vida dos jobs do Carrasco: cancelamento cooperativo, worker morto e listagem.

Tudo offline: transportes em memória, nenhum Mind real, nenhum tráfego.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import bgjobs
import carrasco as c
from test_carrasco import Gate, Transport, plan  # noqa: F401  (fixture reutilizada)
from test_carrasco_write import WriteTransport, wplan  # noqa: F401


def test_cancel_before_first_step_sends_no_traffic(plan):
    transport, gate = Transport(plan), Gate()
    state = c.execute(plan, gate, transport, lambda s: None, cancelled=lambda: True)
    assert state["status"] == "blocked" and state["reason"] == "cancelled_by_operator"
    assert transport.calls == [] and gate.calls == []


def test_cancel_mid_read_stops_before_next_attack_step(plan):
    transport = Transport(plan)
    state = c.execute(plan, Gate(), transport, lambda s: None, cancelled=lambda: len(transport.calls) >= 2)
    assert state["status"] == "blocked" and state["reason"] == "cancelled_by_operator"
    assert len(transport.calls) == 2  # Os controles rodaram; o acesso cruzado não.


def test_cancel_after_write_still_runs_mandatory_cleanup(wplan):
    transport = WriteTransport(wplan)
    # Cancelado logo após a escrita do atacante: a leitura de volta não roda,
    # mas a restauração obrigatória e a verificação rodam.
    state = c.execute(wplan, type("G", (), {"check": lambda self, url, method="GET": "approved-test-revision"})(),
                      transport, lambda s: None, cancelled=lambda: len(transport.calls) >= 2)
    assert state["reason"] == "cancelled_by_operator" and state["status"] == "blocked"
    assert state["attack_status"] == "interrupted"
    assert state["cleanup"] == "restored" and state["manual_restoration_required"] is False
    assert [m for m, _ in transport.calls] == ["GET", "PATCH", "PATCH", "GET"]
    assert transport.stored == wplan["target"]["marker"]


def queued_job(plan, directory, pid=None):
    directory.mkdir(parents=True)
    state = c.new_state(plan)
    state.update(status="running")
    c.private_write(directory / "result.json", json.dumps(state))
    if pid is not None:
        c.private_write(directory / "job.json", json.dumps({"job_id": directory.name, "pid": pid}))


def dead_pid():
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait()  # Coletado: o pid não existe mais (reuso imediato é improvável).
    return process.pid


def test_dead_worker_is_reported_stale_and_wait_returns_early(plan, monkeypatch, tmp_path):
    monkeypatch.setattr(c, "JOBS", tmp_path)
    job = "e" * 32
    queued_job(plan, tmp_path / job, pid=dead_pid())
    status = c.job_status(job)
    assert status["worker"] == "dead" and status["stale"] is True and status["finished"] is False
    assert c.wait_job(job, 30)["stale"] is True  # Não espera os 30 s.
    assert c.main(["status", job]) == 2


def test_live_worker_is_alive_and_not_stale(plan, monkeypatch, tmp_path):
    monkeypatch.setattr(c, "JOBS", tmp_path)
    job = "f" * 32
    queued_job(plan, tmp_path / job, pid=os.getpid())
    status = c.job_status(job)
    assert status["worker"] == "alive" and status["stale"] is False


def test_missing_job_metadata_is_unknown_not_dead(plan, monkeypatch, tmp_path):
    monkeypatch.setattr(c, "JOBS", tmp_path)
    job = "1" * 32
    queued_job(plan, tmp_path / job)
    assert c.job_status(job)["worker"] == "unknown"
    assert c.job_status(job)["stale"] is False


def test_cancel_command_writes_signal_once(plan, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(c, "JOBS", tmp_path)
    job = "2" * 32
    queued_job(plan, tmp_path / job, pid=os.getpid())
    assert c.main(["cancel", job]) == 1  # Pedido registrado; job ainda pendente.
    first = json.loads(capsys.readouterr().out)
    assert first["cancel_requested"] is True and first["cancel_already_requested"] is False
    c.main(["cancel", job])
    assert json.loads(capsys.readouterr().out)["cancel_already_requested"] is True
    assert bgjobs.cancel_requested(tmp_path / job)


def test_cancel_unknown_job_is_error(monkeypatch, tmp_path):
    monkeypatch.setattr(c, "JOBS", tmp_path)
    assert c.main(["cancel", "3" * 32]) == 2


def test_jobs_lists_newest_first_without_secrets(plan, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(c, "JOBS", tmp_path)
    for job in ("4" * 32, "5" * 32):
        queued_job(plan, tmp_path / job, pid=os.getpid())
    os.utime(tmp_path / ("4" * 32) / "result.json", (1, 1))
    (tmp_path / "not-a-job").mkdir()
    assert c.main(["jobs"]) == 0
    output = capsys.readouterr().out
    listing = json.loads(output)
    assert [row["job_id"] for row in listing["jobs"]] == ["5" * 32, "4" * 32]
    assert "SECRET" not in output and plan["accounts"]["b"]["url"] not in output


def test_invalid_job_ids_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        bgjobs.job_directory(tmp_path, "../escape")
