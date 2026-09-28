"""Contratos offline: captura, privacidade, escopo, merge e revisitas reais no writer tmp."""
import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import browser_recon
import endpoints
import jsrecon
import netcommon
import perola_negra
import recon_records
import recon_snapshot


@pytest.fixture(autouse=True)
def selected_instance(tmp_path, monkeypatch):
    instance = tmp_path / "instance"
    (instance / "config").mkdir(parents=True)
    (instance / "config/hive.toml").write_text(f'HIVE_DATA_DIR = {json.dumps(str(tmp_path / "data"))}\nHIVE_ROLE = "writer"\n')
    monkeypatch.setenv("HIVE_INSTANCE_DIR", str(instance))
    monkeypatch.delenv("HIVE_DATA_DIR", raising=False)


def har(tmp_path):
    path = tmp_path / "private.har"
    path.write_text(json.dumps({"log": {"entries": [{
        "request": {"url": "https://app.example/api/v1/users/123?email=alice%40example.com&token=SECRET",
                    "method": "POST", "headers": [{"name": "Cookie", "value": "session=SECRET"}],
                    "postData": {"mimeType": "application/json", "text": json.dumps({
                        "operationName": "UpdateUser", "query": "mutation UpdateUser { user(email: \"alice@example.com\") { id } }",
                        "variables": {"email": "alice@example.com", "password": "SECRET", "count": 7}})}},
        "response": {"status": 200, "content": {"text": "SECRET_RESPONSE"}}}]}}))
    return path


def invoke(mod, args, monkeypatch):
    monkeypatch.setattr(sys, "argv", [mod.__name__ + ".py", *args])
    return mod.main()


def test_har_keeps_structure_and_omits_values(tmp_path):
    rows, coverage = browser_recon.read_har(har(tmp_path), "member", "profile")
    row = rows[0]
    assert row["method"] == "POST"
    assert row["path"] == "/api/v1/users/{redacted}"
    assert row["query_params"] == ["email", "token"]
    assert row["body_schema"]["variables"] == {"email": "string", "password": "string", "count": "number"}
    assert row["graphql_operations"] == ["UpdateUser"]
    assert row["access_context"] == {"role": "member", "flow": "profile", "credential_present": True}
    output = json.dumps(rows)
    for value in ("SECRET", "alice", "SECRET_RESPONSE", "session=", "123"):
        assert value not in output
    assert coverage["entries"] == 1


def test_normalize_rejects_free_headers_and_body_values():
    row = recon_records.normalize_record({"host": "app.example", "path": "/api/foo?password=secret",
        "method": "PATCH", "headers": {"Authorization": "SECRET"},
        "body_schema": {"password": "SECRET"}, "body": "SECRET", "query_params": ["email"]})
    assert row["body_schema"] == {"password": "redacted"}
    assert row["query_params"] == ["email", "password"]
    assert "SECRET" not in json.dumps(row)
    with pytest.raises(ValueError):
        recon_records.normalize_record({"host": "user@host.example", "path": "/"})


def test_corpus_preserves_methods_roles_params_and_existing_status(tmp_path, monkeypatch):
    data = tmp_path / "data"
    text = tmp_path / "legacy.txt"
    text.write_text("app.example GET /api/v1/items?cursor=secret\n")
    args = ["merge", "example", "--input", str(text), "--data-dir", str(data), "--status", "tested"]
    assert invoke(endpoints, args, monkeypatch) == 0
    records = [recon_records.request_record("https://app.example/api/v1/items?filter=secret", "GET", role=role, flow="listing")
               for role in ("member", "admin")]
    records.append(recon_records.request_record("https://app.example/api/v1/items", "POST"))
    path = tmp_path / "records.json"
    path.write_text(json.dumps({"program_id": "example", "records": records}))
    args = ["merge", "example", "--input", str(path), "--data-dir", str(data)]
    assert invoke(endpoints, args, monkeypatch) == 0
    assert invoke(endpoints, args, monkeypatch) == 0
    note = next(data.glob("programs/example/notes/*corpus.md"))
    corpus = endpoints.load_existing(note)
    get = corpus[("app.example", "GET", "/api/v1/items")]
    assert get["status"] == "tested"
    assert len(get["observations"]) == 3
    assert {ob["access_context"]["role"] for ob in get["observations"]} == {"unknown", "member", "admin"}
    assert ("app.example", "POST", "/api/v1/items") in corpus
    assert "secret" not in note.read_text()


def test_corrupt_corpus_and_wrong_program_do_not_overwrite(tmp_path, monkeypatch):
    data = tmp_path / "data"
    note = data / "programs/example/notes/moldret-excalibull-endpoints-corpus.md"
    note.parent.mkdir(parents=True)
    note.write_text("preserve this invalid corpus")
    path = tmp_path / "input.json"
    path.write_text(json.dumps({"program_id": "other", "records": []}))
    args = ["merge", "example", "--input", str(path), "--data-dir", str(data)]
    with pytest.raises(ValueError):
        invoke(endpoints, args, monkeypatch)
    path.write_text("app.example /api/foo\n")
    with pytest.raises(ValueError):
        invoke(endpoints, args, monkeypatch)
    assert note.read_text() == "preserve this invalid corpus"


def test_authorization_requires_current_program_and_flags(monkeypatch):
    receipt = {"program_id": "example", "confirmed": True, "status": "authorized", "action_allowed": True}
    monkeypatch.setattr(browser_recon, "authorization_for", lambda url: receipt)
    assert browser_recon.authorized("https://app.example/path", "example")
    assert not browser_recon.authorized("https://app.example/path", "other")
    receipt["confirmed"] = False
    assert not browser_recon.authorized("https://app.example/path", "example")


def test_jsrecon_checks_redirect_before_network(monkeypatch):
    checked = []
    def authorize(url):
        checked.append(url)
        if "outside" in url:
            raise PermissionError("denied")
    def fake_opener(handler):
        def open_request(req, timeout):
            handler.redirect_request(req, None, 302, "redirect", {}, "https://outside.example/")
            pytest.fail("redirect allowed")
        return types.SimpleNamespace(open=open_request)
    monkeypatch.setattr(netcommon.urllib.request, "build_opener", fake_opener)
    with pytest.raises(PermissionError):
        netcommon.http_get("https://app.example/", authorize=authorize)
    assert checked == ["https://app.example/", "https://outside.example/"]


def test_jsrecon_bundle_limit_is_reported(monkeypatch, capsys):
    html = '<script src="/a.js"></script><script src="/b.js"></script>'
    monkeypatch.setattr(jsrecon, "fetch", lambda url, timeout=15: (html if url.endswith("/") else '"/api/foo"', 200))
    invoke(jsrecon, ["https://app.example/", "--json", "--max-js", "1"], monkeypatch)
    data = json.loads(capsys.readouterr().out)
    assert data["coverage"]["status"] == "partial"
    assert data["coverage"]["bundles_pending"] == 1
    assert data["records"][0]["method"] == "?"
    assert data["content_hashes"]


def test_cdp_observes_without_navigating_and_filters_unapproved(monkeypatch):
    listeners = {}
    allowed = types.SimpleNamespace(url="https://app.example/api/foo", method="GET", post_data=None,
                                    all_headers=lambda: {"cookie": "SECRET"})
    denied = types.SimpleNamespace(url="https://outside.example/", method="GET", post_data=None)
    # Request objects in Playwright are hashable.
    class Request:
        url, method, post_data = allowed.url, allowed.method, allowed.post_data
        def all_headers(self):
            return {"cookie": "SECRET"}
    allowed = Request()
    class Page:
        def is_closed(self):
            return False
        def wait_for_timeout(self, ms):
            listeners["request"](allowed)
            listeners["request"](denied)
            listeners["response"](types.SimpleNamespace(request=allowed, status=200))
    ctx = types.SimpleNamespace(pages=[Page()], on=lambda event, fn: listeners.update({event: fn}),
                                remove_listener=lambda event, fn: listeners.pop(event))
    class PW:
        def __enter__(self):
            return types.SimpleNamespace(chromium=types.SimpleNamespace(connect_over_cdp=lambda url: types.SimpleNamespace(contexts=[ctx])))
        def __exit__(self, *args):
            pass
    module = types.ModuleType("playwright.sync_api")
    module.sync_playwright = PW
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.sync_api", module)
    monkeypatch.setattr(browser_recon, "authorized", lambda url, program: "app.example" in url)
    ticks = iter([0, 0, 0, 1])
    monkeypatch.setattr(browser_recon.time, "monotonic", lambda: next(ticks))
    rows, coverage = browser_recon.observe_cdp("http://127.0.0.1:9222", "example", .1, "member", "checkout")
    assert len(rows) == 1 and rows[0]["response_status"] == 200
    assert coverage["filtered_without_receipt"] == 1
    assert coverage["requests_pending"] == 0
    assert not listeners
    assert "SECRET" not in json.dumps(rows)


def test_perola_har_offline_produces_writer_and_no_traffic(tmp_path, monkeypatch):
    monkeypatch.setattr(perola_negra, "authorized", lambda *args: pytest.fail("offline import queried active gate"))
    args = ["example", "--har", str(har(tmp_path)), "--data-dir", str(tmp_path / "data"),
            "--scratch", str(tmp_path / "scratch"), "--role", "member", "--flow", "profile"]
    assert invoke(perola_negra, args, monkeypatch) == 0
    report = json.loads((tmp_path / "scratch/perola-negra-coverage.json").read_text())
    assert report["publication"] == "pending-ingest-idle-readback"
    assert report["revisits"] == []
    assert report["record_count"] == 1


def test_revisit_diff_failure_and_partial_preserve_baseline(tmp_path, monkeypatch):
    data_dir, scratch = tmp_path / "data", tmp_path / "scratch"
    args = ["example", "--hosts", "app.example", "--data-dir", str(data_dir), "--scratch", str(scratch)]
    monkeypatch.setattr(perola_negra, "authorized", lambda *args: True)
    real_run = perola_negra.run_tool
    payload = {"records": [recon_records.request_record("https://app.example/api/foo")],
               "graphql_ops": [], "fingerprints": [], "content_hashes": {"app.example/a.js": "hash-a"},
               "coverage": {"status": "collected"}}
    failed = [False]
    def fake_run(argv, timeout=300):
        if argv[0] == "jsrecon.py":
            return (2, "") if failed[0] else (0, json.dumps(payload))
        return real_run(argv, timeout)
    monkeypatch.setattr(perola_negra, "run_tool", fake_run)
    assert invoke(perola_negra, args, monkeypatch) == 0
    assert invoke(perola_negra, args, monkeypatch) == 0
    report_path = scratch / "perola-negra-coverage.json"
    assert json.loads(report_path.read_text())["revisits"][0]["status"] == "unchanged"
    payload["records"].append(recon_records.request_record("https://app.example/api/bar"))
    assert invoke(perola_negra, args, monkeypatch) == 0
    report = json.loads(report_path.read_text())
    assert report["revisits"][0]["added_endpoints"] == ["/api/bar"]
    snapshot_path = data_dir / "programs/example/notes/excalibull-perola-negra-snapshot.md"
    original = snapshot_path.read_text()
    payload["coverage"]["status"] = "partial"
    payload["records"] = []
    assert invoke(perola_negra, args, monkeypatch) == 1
    assert snapshot_path.read_text() == original
    failed[0] = True
    assert invoke(perola_negra, args, monkeypatch) == 1
    assert snapshot_path.read_text() == original
    monkeypatch.setattr(perola_negra, "authorized", lambda *args: False)
    assert invoke(perola_negra, args, monkeypatch) == 1
    assert json.loads(report_path.read_text())["revisits"][0]["status"] == "blocked-without-receipt"


def test_known_revisit_retains_entry_paths_and_explicit_selection(tmp_path):
    snapshot = {"app.example": {"https://app.example/portal": {}}, "old.example": {}}
    assert perola_negra.known_urls(tmp_path, snapshot) == ["https://app.example/portal", "https://old.example/"]
    assert perola_negra.select_urls([], "new.example", ["https://old.example/"], False) == ["https://new.example/"]
    assert perola_negra.select_urls([], "new.example", ["https://old.example/"], True) == ["https://new.example/", "https://old.example/"]
    with pytest.raises(ValueError):
        perola_negra.select_urls(["https://user:secret@app.example/"], "", [], False)
