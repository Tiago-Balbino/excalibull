"""Publicação e Selo nunca avançam com lote parcial, idle isolado ou read-back antigo."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from hive_outbox import Outbox
import hive_publication as publication
import seal_gate


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HANDLE", "alice")
    monkeypatch.setenv("HIVE_TEAM_TAG", "team-a")
    for key in ("EXCALIBULL_SESSION_ID", "EXCALIBULL_PLATFORM", "EXCALIBULL_TARGET_NAME"):
        monkeypatch.delenv(key, raising=False)
    queue = Outbox(tmp_path / "outbox")
    entry = queue.enqueue("demo", "handoff", "# Handoff\n\nDescartado: sem impacto.", assets=["app.example"], result="discarded")
    sid = queue.session("demo")
    workspace = tmp_path / "writer"
    workspace.mkdir()
    config = tmp_path / "writer.toml"
    config.write_text("# synthetic configuration")
    targets = tmp_path / "targets"
    scratch = targets / "demo/a-cacada-ate-aqui.md"
    scratch.parent.mkdir(parents=True)
    scratch.write_text("Sessão sintética\nPróximo passo: retomar.")
    brain = tmp_path / "brain"
    wal = brain / "targets/demo.md"
    wal.parent.mkdir(parents=True)
    wal.write_text("Resultado negativo: sem impacto.")
    queue.bind_handoff("demo", queue.root / entry["path"], scratch, wal)
    monkeypatch.setattr(seal_gate, "TARGETS_DIR", targets)
    monkeypatch.setenv("EXCALIBULL_BRAIN_DIR", str(brain))
    monkeypatch.setenv("EXCALIBULL_OUTBOX_DIR", str(queue.root))
    return queue, sid, entry, workspace, config


def report(entries, *, outcome="created", published=True, ok=True):
    results = [{"path": e["path"], "outcome": outcome, "published": published} for e in entries]
    summary = {name: sum(r["outcome"] == name for r in results) for name in publication.OUTCOMES}
    summary.update(total=len(results), ingested=summary["created"] + summary["updated"], scan_complete=True, results=results)
    return {"schema_version": 1, "ok": ok, "exit_code": 0 if ok else 15, "summary": summary}


class Client:
    def __init__(self, queue, sid, ingestion=None, status="idle", search_change=None, **kwargs):
        self.entries = queue.current(queue.load(sid))
        self.tools = {"ingest_workspace", "hive_search", "get_sync_status"}
        self.ingestion = ingestion or report(self.entries)
        self.status = status
        self.search_change = search_change
        self.calls = []
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def ingest_report(self):
        return self.ingestion
    def call(self, name, arguments):
        self.calls.append((name, arguments))
        if name == "get_sync_status":
            return {"status": self.status, "queue_confirmed": self.status == "idle"}
        entry = next(e for e in self.entries if e["marker"] == arguments["query"])
        result = {"path": entry["path"], "text": entry["marker"] + "\n" + entry["witness"], "untrusted_content": True}
        if self.search_change:
            self.search_change(result)
        return {"results": [result], "truncated": False, "warnings": []}


def publish(session, *, ingestion=None, status="idle", search_change=None):
    queue, sid, entry, workspace, config = session
    client = Client(queue, sid, ingestion=ingestion, status=status, search_change=search_change)
    factory = lambda **kwargs: client
    assert publication.deliver(queue, sid, "demo", workspace)["ok"]
    ingested = publication.ingest(queue, sid, "demo", workspace, config, client_factory=factory)
    verified = publication.verify(queue, sid, "demo", client_factory=factory)
    return ingested, verified, client


def test_complete_session_seals_and_records_limited_proof(session):
    queue, sid, entry, workspace, config = session
    assert seal_gate.check_seal("demo", publication=False)[0]
    assert not seal_gate.check_seal("demo")[0]
    ingested, verified, client = publish(session)
    assert ingested["ok"] and verified["ok"]
    assert seal_gate.check_seal("demo")[0]
    state = Outbox(queue.root).load(sid)
    assert state["verification"]["scope"] == "retrieved-fragment"
    assert state["verification"]["expected"] == {entry["id"]: 1}
    assert client.calls[1][1]["program_id"] == "demo"


def test_handoff_only_cli_is_explicitly_pending(session, capsys):
    assert seal_gate.main(["demo"]) == 1
    assert seal_gate.main(["demo", "--handoff-only"]) == 0
    assert "PUBLICAÇÃO PENDENTE" in capsys.readouterr().out


def test_export_or_delivery_does_not_satisfy_publication(session, tmp_path):
    queue, sid, entry, workspace, config = session
    queue.export("demo", tmp_path / "package.tar.gz")
    assert not seal_gate.check_seal("demo")[0]
    assert publication.deliver(queue, sid, "demo", workspace)["ok"]
    assert not seal_gate.check_seal("demo")[0]
    before = (workspace / entry["path"]).read_bytes()
    assert publication.deliver(queue, sid, "demo", workspace)["ok"]
    assert (workspace / entry["path"]).read_bytes() == before


@pytest.mark.parametrize("outcome,published,ok", [
    ("failed", True, False), ("failed", False, False), ("skipped", False, True),
    ("missing", False, True), ("cancelled", False, False), ("created", False, True)])
def test_non_success_outcomes_cannot_seal(session, outcome, published, ok):
    queue, sid, entry, *_ = session
    ingestion = report([entry], outcome=outcome, published=published, ok=ok)
    ingestion["summary"]["results"][0]["reason_code"] = "foreign_writer" if outcome == "skipped" else "commit_failed"
    ingested, verified, _ = publish(session, ingestion=ingestion)
    assert not ingested["ok"] and not verified["ok"]
    assert not seal_gate.check_seal("demo")[0]
    if published:
        assert queue.current(queue.load(sid))[0]["state"] == "reconciliation-required"


def test_unchanged_requires_identity_read_back(session):
    queue, sid, entry, *_ = session
    ingested, verified, _ = publish(session, ingestion=report([entry], outcome="unchanged", published=False))
    assert ingested["ok"] and verified["ok"]


def test_partial_batch_requires_reconciliation_even_if_expected_file_succeeded(session):
    queue, sid, entry, *_ = session
    ingestion = report([entry], ok=False)
    ingested, verified, _ = publish(session, ingestion=ingestion)
    assert not ingested["ok"] and not verified["ok"]
    # Retomar a mesma identidade com relatório completo libera a confirmação.
    ingested, verified, _ = publish(session)
    assert ingested["ok"] and verified["ok"]
    assert queue.current(queue.load(sid))[0]["revision"] == 1


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(schema_version=2),
    lambda r: r["summary"].update(scan_complete=False),
    lambda r: r["summary"].update(created=3),
    lambda r: r["summary"]["results"][0].update(outcome="future-outcome"),
    lambda r: r["summary"]["results"].append(copy.deepcopy(r["summary"]["results"][0])),
    lambda r: r.update(_mcp_is_error=True),
])
def test_malformed_unknown_or_error_reports_fail_closed(session, mutation):
    queue, sid, entry, *_ = session
    ingestion = report([entry])
    mutation(ingestion)
    ingested, verified, _ = publish(session, ingestion=ingestion)
    assert not ingested["ok"] and not verified["ok"]


def test_missing_file_result_fails_closed(session):
    ingested, verified, _ = publish(session, ingestion=report([]))
    assert not ingested["ok"] and not verified["ok"]


@pytest.mark.parametrize("status", ["unknown", "busy", "indexing"])
def test_queue_unknown_or_busy_is_not_confirmation(session, status):
    ingested, verified, client = publish(session, status=status)
    assert ingested["ok"] and not verified["ok"]
    assert not any(name == "hive_search" for name, _ in client.calls)


@pytest.mark.parametrize("change", [
    lambda r: r.update(path="programs/other/notes/old.md"),
    lambda r: r.update(text="old revision"),
    lambda r: r.update(text=r["text"].split("\n")[0]),
])
def test_idle_with_divergent_path_marker_or_content_cannot_seal(session, change):
    ingested, verified, _ = publish(session, search_change=change)
    assert ingested["ok"] and not verified["ok"]
    assert not seal_gate.check_seal("demo")[0]


def test_authentication_error_invalidates_previous_readback(session):
    queue, sid, *_ = session
    assert publish(session)[1]["ok"]
    def unavailable(**kwargs):
        raise ValueError("synthetic expired authentication")
    assert not publication.verify(queue, sid, "demo", client_factory=unavailable)["ok"]
    assert queue.load(sid)["verification"] is None
    assert not seal_gate.check_seal("demo")[0]


def test_new_revision_or_contribution_invalidates_complete_seal(session):
    queue, sid, *_ = session
    assert publish(session)[1]["ok"]
    queue.enqueue("demo", "negative", "Novo resultado negativo", result="discarded")
    assert not seal_gate.check_seal("demo")[0]
    queue.enqueue("demo", "handoff", "# Handoff\n\nOutro resultado")
    assert not seal_gate.check_seal("demo", publication=False)[0]


def test_changed_scratch_and_stale_verification_block_seal(session):
    queue, sid, *_ = session
    assert publish(session)[1]["ok"]
    with queue.edit(sid) as state:
        state["verification"]["at"] = (datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat()
    assert not seal_gate.check_seal("demo")[0]
    scratch = seal_gate.TARGETS_DIR / "demo/a-cacada-ate-aqui.md"
    scratch.write_text("Mudou\nPróximo passo: retomar.")
    assert not seal_gate.check_seal("demo", publication=False)[0]


def test_writer_mismatch_and_unannounced_capability_do_not_publish(session):
    queue, sid, entry, workspace, config = session
    publication.deliver(queue, sid, "demo", workspace)
    original = (workspace / entry["path"]).read_bytes()
    (workspace / entry["path"]).write_text("preserve writer content")
    assert not publication.deliver(queue, sid, "demo", workspace)["ok"]
    assert (workspace / entry["path"]).read_text() == "preserve writer content"
    (workspace / entry["path"]).write_bytes(original)
    client = Client(queue, sid)
    client.tools.remove("ingest_workspace")
    assert not publication.ingest(queue, sid, "demo", workspace, config, client_factory=lambda **kwargs: client)["ok"]
    assert not seal_gate.check_seal("demo")[0]


def test_workspace_rejects_repository_outbox_and_symlink(session, tmp_path):
    queue, sid, entry, workspace, config = session
    with pytest.raises(ValueError):
        publication.deliver(queue, sid, "demo", queue.root)
    (workspace / ".git").mkdir()
    with pytest.raises(ValueError, match="repositório"):
        publication.deliver(queue, sid, "demo", workspace)
    linked = tmp_path / "linked"
    linked.symlink_to(workspace, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        publication.deliver(queue, sid, "demo", linked)


def test_readback_failure_after_one_file_resets_whole_set(session):
    queue, sid, *_ = session
    queue.enqueue("demo", "negative", "Descartado: segunda contribuição.", result="discarded")
    client = Client(queue, sid)
    original_call = client.call
    searches = []
    def call(name, arguments):
        if name == 'hive_search':
            searches.append(arguments)
            if len(searches) == 2:
                raise ValueError('synthetic authentication failure')
        return original_call(name, arguments)
    client.call = call
    workspace, config = session[3:]
    publication.deliver(queue, sid, "demo", workspace)
    assert publication.ingest(queue, sid, "demo", workspace, config, client_factory=lambda **kwargs: client)["ok"]
    assert not publication.verify(queue, sid, "demo", client_factory=lambda **kwargs: client)["ok"]
    assert len(searches) == 2
    assert all(e['verification'] is None for e in queue.current(queue.load(sid)))


def test_new_session_cannot_reuse_old_handoff(session):
    queue, sid, *_ = session
    assert publish(session)[1]["ok"]
    queue.start('demo', 'new-session')
    assert not seal_gate.check_seal('demo')[0]
    assert not seal_gate.check_seal('demo', publication=False)[0]


def test_changed_client_boundary_invalidates_seal(session, monkeypatch):
    assert publish(session)[1]["ok"]
    monkeypatch.setenv('HIVE_MIND_URL', 'https://other.example/mind')
    assert not seal_gate.check_seal('demo')[0]


def test_delivery_io_failure_keeps_retry_and_cannot_preserve_old_seal(session, monkeypatch):
    queue, sid, entry, workspace, *_ = session
    assert publish(session)[1]['ok']
    monkeypatch.setattr(publication, 'file_hash', lambda path: (_ for _ in ()).throw(OSError('synthetic disk failure')))
    assert not publication.deliver(queue, sid, 'demo', workspace)['ok']
    state = queue.load(sid)
    assert state['verification'] is None
    assert queue.current(state)[0]['attempts'][-1]['operation'] == 'delivery'
    assert not seal_gate.check_seal('demo')[0]


def test_full_flow_with_real_stdio_gateway_and_synthetic_mcp(session, tmp_path):
    from hive_gateway import HiveClient
    queue, sid, entry, workspace, config = session
    script = tmp_path / 'synthetic_writer.py'
    script.write_text('''import json,sys
from pathlib import Path
workspace=Path(''' + repr(str(workspace)) + ''')
for line in sys.stdin:
    request=json.loads(line)
    if 'id' not in request: continue
    method=request['method']
    if method=='initialize': result={'protocolVersion':'2024-11-05'}
    elif method=='tools/list': result={'tools':[{'name':n} for n in ['ingest_workspace','get_sync_status','hive_search']]}
    else:
        name=request['params']['name']; arguments=request['params']['arguments']
        files=list(workspace.glob('programs/*/notes/*.md'))
        if name=='ingest_workspace':
            results=[{'path':p.relative_to(workspace).as_posix(),'outcome':'created','published':True} for p in files]
            summary={'created':len(results),'updated':0,'unchanged':0,'skipped':0,'missing':0,'failed':0,'cancelled':0,'total':len(results),'ingested':len(results),'scan_complete':True,'results':results}
            result={'isError':False,'content':[{'type':'text','text':json.dumps({'schema_version':1,'ok':True,'exit_code':0,'summary':summary})}]}
        elif name=='get_sync_status': result={'content':[{'type':'text','text':'**Status:** `idle`'}]}
        else:
            matches=[{'path':p.relative_to(workspace).as_posix(),'text':p.read_text(),'untrusted_content':True} for p in files if p.parts[-3]==arguments['program_id'] and arguments['query'] in p.read_text()]
            result={'structuredContent':{'results':matches,'warnings':[],'truncated':False},'content':[{'type':'text','text':'summary'}]}
    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}),flush=True)
''')
    factory = lambda **kwargs: HiveClient(command=[sys.executable, str(script)], **{**kwargs, 'timeout': 2})
    assert publication.deliver(queue, sid, 'demo', workspace)['ok']
    assert publication.ingest(queue, sid, 'demo', workspace, config, client_factory=factory)['ok']
    assert publication.verify(queue, sid, 'demo', client_factory=factory)['ok']
    assert seal_gate.check_seal('demo')[0]
