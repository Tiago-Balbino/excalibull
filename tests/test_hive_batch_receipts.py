import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import pytest  # noqa: E402

import hive_batch_receipts as hb  # noqa: E402


class FakeClient:
    def __init__(self, deny=()):
        self.deny = set(deny)
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def context(self, program, asset, question):
        self.calls.append(asset["value"])
        allowed = asset["value"] not in self.deny
        return {"program_id": program, "asset": asset,
                "scope": {"status": "authorized" if allowed else "out_of_scope", "confirmed": True,
                          "action_allowed": allowed, "scope_revision": "r1"}}


def test_build_urls_hosts_paths_dedup():
    urls = hb.build_urls(hosts="a.example.com,b.example.com", paths="/,/robots.txt,/")
    assert urls == ["https://a.example.com/", "https://a.example.com/robots.txt",
                    "https://b.example.com/", "https://b.example.com/robots.txt"]


@pytest.mark.parametrize("bad", ["https://u:p@a.example.com/", "https://a.example.com/x?q=1",
                                 "ftp://a.example.com/", "https://a.example.com/#f"])
def test_build_urls_rejects(tmp_path, bad):
    f = tmp_path / "u.txt"
    f.write_text(bad + "\n")
    with pytest.raises(ValueError):
        hb.build_urls(urls_file=str(f))


def test_run_records_all_when_authorized():
    recorded = []
    client = FakeClient()
    allowed, report, state = hb.run("p", ["https://a.example.com/", "https://a.example.com/x"], "q",
                                    client_factory=lambda: client, recorder=recorded.append)
    assert state == "complete" and len(allowed) == 2 and len(recorded) == 2


def test_run_stops_on_first_denied_and_emits_no_pairs():
    recorded = []
    client = FakeClient(deny={"https://a.example.com/x"})
    urls = ["https://a.example.com/", "https://a.example.com/x", "https://a.example.com/y"]
    allowed, report, state = hb.run("p", urls, "q", client_factory=lambda: client, recorder=recorded.append)
    assert state == "stopped"
    assert client.calls == urls[:2]  # não continua após o negado
    assert report[-1]["verdict"] == "denied"


def test_curl_pairs_unique_names():
    pairs = hb.curl_pairs(["https://a.example.com/x.js", "https://a.example.com/x_js"])
    names = [p for p in pairs.split() if p.startswith("o_")]
    assert len(names) == len(set(names)) == 2
