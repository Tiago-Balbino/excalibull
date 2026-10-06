"""Contratos de contribuição: retry, queda, autoria, isolamento e concorrência."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from hive_documents import document, render
from hive_outbox import Outbox, prepare


@pytest.fixture
def queue(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HANDLE", "alice")
    monkeypatch.setenv("HIVE_TEAM_TAG", "team-a")
    for key in ("EXCALIBULL_SESSION_ID", "EXCALIBULL_PLATFORM", "EXCALIBULL_TARGET_NAME"):
        monkeypatch.delenv(key, raising=False)
    return Outbox(tmp_path / "outbox")


def test_retry_survives_restart_without_new_revision_or_timestamp(queue):
    first = queue.enqueue("demo", "negative", "Descartado: sem impacto.", assets=["app.example"], result="discarded")
    session = queue.session("demo")
    second = Outbox(queue.root).enqueue("demo", "negative", "Descartado: sem impacto.", assets=["app.example"], result="discarded")
    assert first == second
    state = queue.load(session)
    assert state["expected"] == {first["id"]: 1}
    assert len(queue.current(state)) == 1
    assert "discarded" in queue.bytes_for(state, first).decode()


def test_change_preserves_previous_revision_and_resets_publication(queue):
    first = queue.enqueue("demo", "negative", "Inconclusivo.", result="inconclusive")
    session = queue.session("demo")
    with queue.edit(session) as state:
        state.update(ingestion_ok=True, verification={"at": "old"}, status="verified")
    second = queue.enqueue("demo", "negative", "Descartado.", result="discarded")
    assert second["id"] == first["id"] and second["revision"] == 2
    assert first["path"] != second["path"]
    state = queue.load(session)
    assert state["expected"] == {first["id"]: 2}
    assert not state["ingestion_ok"] and state["verification"] is None
    assert (queue.root / first["path"]).exists()


def test_authors_and_projects_do_not_overwrite(queue):
    one = queue.enqueue("demo", "surface", "Observação A", platform="hackerone", target_name="One")
    two = queue.enqueue("demo", "surface", "Observação B", platform="hackerone", target_name="Two")
    three = queue.enqueue("demo", "surface", "Observação C", handle="bob")
    assert len({one["id"], two["id"], three["id"]}) == 3
    assert len(queue.current(queue.load(queue.session("demo")))) == 3


def test_program_and_session_isolation(queue):
    queue.start("demo", "session-a")
    one = queue.enqueue("demo", "negative", "Observação")
    queue.start("demo", "session-b")
    two = queue.enqueue("demo", "negative", "Observação")
    assert one["id"] != two["id"]
    with pytest.raises(ValueError, match="outro programa"):
        queue.enqueue("other", "negative", "Observação", session="session-a")
    with pytest.raises(ValueError, match="reservado"):
        queue.start("demo", "active-demo")


def test_concurrent_implicit_start_and_contributions_keep_all_entries(queue):
    def enqueue(index):
        return Outbox(queue.root).enqueue("demo", f"item-{index}", f"Observação {index}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        entries = list(executor.map(enqueue, range(16)))
    manifests = list((queue.root / "sessions").glob("*.json"))
    assert len(manifests) == 2  # sessão + ponteiro do programa
    state = queue.load(queue.session("demo"))
    assert set(state["expected"]) == {e["id"] for e in entries}


def test_corrupt_manifest_is_never_silently_replaced(queue):
    sid = queue.start("demo")
    path = queue.manifest_path(sid)
    path.write_text("corrupt evidence")
    with pytest.raises(ValueError, match="corrompido"):
        queue.enqueue("demo", "item", "Observação")
    assert path.read_text() == "corrupt evidence"


def test_crash_after_document_write_is_recoverable(queue, monkeypatch):
    sid = queue.start("demo")
    original = queue._save
    monkeypatch.setattr(queue, "_save", lambda state: (_ for _ in ()).throw(OSError("simulated crash")))
    with pytest.raises(OSError):
        queue.enqueue("demo", "item", "Observação")
    orphan = next((queue.root / "programs/demo/notes").glob("*.md"))
    content = orphan.read_bytes()
    monkeypatch.setattr(queue, "_save", original)
    entry = queue.enqueue("demo", "item", "Observação")
    assert queue.bytes_for(queue.load(sid), entry) == content
    assert entry["revision"] == 1


def test_export_has_only_current_expected_documents_and_stays_pending(queue, tmp_path):
    old = queue.enqueue("demo", "item", "Primeira observação")
    latest = queue.enqueue("demo", "item", "Observação corrigida")
    (queue.root / "programs/demo/notes/archive.md").write_text("Arquivo fora da sessão")
    package = tmp_path / "session.tar.gz"
    result = queue.export("demo", package)
    assert result["publication"] == "pending-writer"
    assert queue.load(queue.session("demo"))["verification"] is None
    with tarfile.open(package) as archive:
        assert set(archive.getnames()) == {latest["path"], "manifest.json"}
        manifest = json.load(archive.extractfile("manifest.json"))
        assert manifest["expected"] == {old["id"]: 2}
        assert hashlib.sha256(archive.extractfile(latest["path"]).read()).hexdigest() == latest["sha256"]
    original = package.read_bytes()
    with pytest.raises(FileExistsError):
        queue.export("demo", package)
    assert package.read_bytes() == original


def test_tampered_document_or_symlink_cannot_be_exported(queue, tmp_path):
    entry = queue.enqueue("demo", "item", "Observação")
    path = queue.root / entry["path"]
    content = path.read_bytes()
    path.write_bytes(content + b"modified")
    with pytest.raises(ValueError, match="hash"):
        queue.export("demo", tmp_path / "changed.tar.gz")
    path.unlink()
    outside = tmp_path / "outside.md"
    outside.write_bytes(content)
    path.symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        queue.export("demo", tmp_path / "symlink.tar.gz")


def test_authorship_requires_configuration(queue, monkeypatch):
    monkeypatch.delenv("HIVE_HANDLE")
    monkeypatch.delenv("HIVE_TEAM_TAG")
    with pytest.raises(ValueError, match="autoria"):
        queue.enqueue("demo", "item", "Observação")
    assert not (queue.root / "programs").exists()


@pytest.mark.parametrize("asset", ["*.example.com", "ip:192.0.2.0/24", "https://user:secret@app.example/", "https://app.example/?token=value"])
def test_observed_assets_reject_scope_rules_and_credentials(queue, asset):
    with pytest.raises(ValueError):
        queue.enqueue("demo", "item", "Observação", assets=[asset])


def test_document_registration_is_paired_and_canonical(queue):
    with pytest.raises(ValueError, match="juntos"):
        queue.enqueue("demo", "item", "Observação", platform="hackerone")
    prepared = document("demo", "Observação", assets=["app.example", "ip:192.0.2.1", "https://APP.example:443/api"],
                        platform="hackerone", target_name="Example")
    assert prepared["metadata"]["observed_targets"] == ["host:app.example", "ip:192.0.2.1", "url_prefix:https://app.example/api"]
    text, marker, witness = render(prepared, "session-a", "id-a", 1)
    assert marker in text and witness == "Observação"


@pytest.mark.parametrize("body", ["Authorization: Bearer SECRET", "Set-Cookie: session=SECRET", "password=SECRET"])
def test_secret_values_never_enter_outbox(queue, body):
    with pytest.raises(ValueError, match="credencial"):
        queue.enqueue("demo", "item", body)
    assert not (queue.root / "programs").exists()


def test_many_assets_are_preserved_without_silent_truncation(queue):
    assets = [f"app-{i}.example" for i in range(80)]
    entry = queue.enqueue("demo", "item", "Observação", assets=assets, platform="hackerone", target_name="Example")
    text = queue.bytes_for(queue.load(queue.session("demo")), entry).decode()
    assert all(host in text for host in assets)


def test_private_modes_for_manifest_and_notes(queue):
    entry = queue.enqueue("demo", "item", "Observação")
    assert queue.root.stat().st_mode & 0o777 == 0o700
    assert queue.manifest_path(queue.session("demo")).stat().st_mode & 0o777 == 0o600
    assert (queue.root / entry["path"]).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('stamp', ['2026-10-06 12:00:00Z', '2026-10-06T12:00:00', 'today'])
def test_collection_timestamp_must_match_hive_rfc3339_contract(queue, stamp):
    with pytest.raises(ValueError, match='RFC 3339'):
        queue.enqueue('demo', 'item', 'Observação', collected_at=stamp)
