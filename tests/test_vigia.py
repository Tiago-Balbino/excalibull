"""Vigia offline: classificação vivo/morto, gates do Mind, diff, limites, notas e sonda em loopback.

Nenhum alvo real: Mind, DNS e sonda são fakes; o Prober real só fala com 127.0.0.1.
"""
import copy
import json
import os
from pathlib import Path
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import vigia as v

REVISION = "approved-test-revision"


@pytest.fixture
def plan(monkeypatch):
    p = json.loads((v.ROOT / "examples/vigia/mission.json").read_text())
    p["policy"]["scope_revision"] = REVISION
    p["passive"]["enabled"] = False
    p["revisit_known"] = False
    p["hosts"] = []
    monkeypatch.setenv("VIGIA_REQUIRED_HEADERS", json.dumps({"X-Researcher": "lab"}))
    monkeypatch.setattr(v.RateLimiter, "wait", lambda self: None)
    return p


# Cenário: um host por comportamento.
DNS = {
    "alive.example.com": {"rcode": "NOERROR", "addresses": ["93.184.216.34"], "cnames": []},
    "noweb.example.com": {"rcode": "NOERROR", "addresses": ["93.184.216.35"], "cnames": []},
    "gone.example.com": {"rcode": "NXDOMAIN", "addresses": [], "cnames": []},
    "dangling.example.com": {"rcode": "NXDOMAIN", "addresses": [], "cnames": ["orphan.cloudapp.example.net"]},
    "internal.example.com": {"rcode": "NOERROR", "addresses": ["10.0.0.5"], "cnames": []},
    "servfail.example.com": {"rcode": "SERVFAIL", "addresses": [], "cnames": []},
    "tls.example.com": {"rcode": "NOERROR", "addresses": ["93.184.216.36"], "cnames": []},
}
PROBES = {
    ("alive.example.com", "https"): {"outcome": "http", "http_status": 200, "server": "nginx", "title": "App"},
    ("noweb.example.com", "https"): {"outcome": "refused"},
    ("noweb.example.com", "http"): {"outcome": "timeout"},
    ("tls.example.com", "https"): {"outcome": "tls_invalid", "tls_error": "certificate has expired"},
}


class Gate:
    def __init__(self, host_scope=None, url_scope=None):
        self.host_scope, self.url_scope = host_scope or {}, url_scope or {}
        self.calls = []

    def host(self, host):
        self.calls.append(("host", host))
        return self.host_scope.get(host, "authorized")

    def url(self, url):
        self.calls.append(("url", url))
        return self.url_scope.get(url, "authorized")


class Resolver:
    def __init__(self):
        self.calls = []

    def resolve(self, host):
        self.calls.append(host)
        return copy.deepcopy(DNS.get(host, {"rcode": "NXDOMAIN", "addresses": [], "cnames": []}))


class Prober:
    def __init__(self, overrides=None, events=None):
        self.calls, self.overrides, self.events = [], overrides or {}, events
        self.allow_private = False

    def probe(self, scheme, host, port, address, headers, timeout, max_bytes):
        self.calls.append((scheme, host, port, address, headers))
        if self.events is not None:
            self.events.append(("probe", host, scheme))
        base = self.overrides.get((host, scheme)) or PROBES.get((host, scheme), {"outcome": "refused"})
        return {"scheme": scheme, "port": port, "address": address, **copy.deepcopy(base)}


def run(plan, hosts, *, gate=None, prober=None, baseline=None, **kwargs):
    plan["hosts"] = hosts
    gate, resolver, prober, saved = gate or Gate(), Resolver(), prober or Prober(), []
    state = v.execute(plan, gate=gate, resolver=resolver, prober=prober,
                      save=lambda s: saved.append(copy.deepcopy(s)), baseline=baseline, **kwargs)
    return state, gate, resolver, prober


ALL = ["alive.example.com", "noweb.example.com", "gone.example.com", "dangling.example.com",
       "internal.example.com", "servfail.example.com", "tls.example.com", "oos.example.com", "unknown.example.com"]


def test_example_mission_validates():
    plan = json.loads((v.ROOT / "examples/vigia/mission.json").read_text())
    assert v.validate(plan) is plan


def test_classification_separates_alive_dead_and_unknown(plan):
    gate = Gate(host_scope={"oos.example.com": "out_of_scope", "unknown.example.com": "unverified"})
    state, gate, resolver, prober = run(plan, ALL, gate=gate)
    status = {h: e["status"] for h, e in state["hosts"].items()}
    assert status == {
        "alive.example.com": "vivo", "noweb.example.com": "sem_web", "gone.example.com": "morto",
        "dangling.example.com": "morto", "internal.example.com": "interno",
        "servfail.example.com": "nao_verificado", "tls.example.com": "vivo",
        "oos.example.com": "fora_de_escopo", "unknown.example.com": "nao_verificado"}
    assert state["summary"]["alive"] == 2 and state["summary"]["dead"] == 3
    # Sem DNS antes do escopo confirmado; IP interno nunca é sondado.
    assert "oos.example.com" not in resolver.calls and "unknown.example.com" not in resolver.calls
    assert all(call[3] != "10.0.0.5" for call in prober.calls)
    assert all(call[1] != "internal.example.com" for call in prober.calls)
    # Desconhecido não é morto: há hosts não verificados, então o recon é parcial.
    assert state["status"] == "partial" and state["reason"] == "some_hosts_unverified"


def test_extended_ports_only_probed_on_live_hosts(plan):
    plan["http"].update(extended_ports=["https:8443", "http:8080"])
    over = {
        ("alive.example.com", "https"): {"outcome": "http", "http_status": 200, "server": "nginx"},
        ("alive.example.com", "https-8443"): {"outcome": "http", "http_status": 200, "server": "admin-panel"},
    }
    class PortProber(Prober):
        def probe(self, scheme, host, port, address, headers, timeout, max_bytes):
            key = (host, f"{scheme}-{port}" if port not in (80, 443) else scheme)
            base = over.get(key) or PROBES.get((host, scheme)) or {"outcome": "refused"}
            self.calls.append((scheme, host, port, address, headers))
            return {"scheme": scheme, "port": port, "address": address, **copy.deepcopy(base)}
    # noweb resolve mas nenhuma porta de liveness responde → portas estendidas NÃO são sondadas.
    state, _, _, prober = run(plan, ["alive.example.com", "noweb.example.com"], prober=PortProber())
    alive = state["hosts"]["alive.example.com"]
    assert alive["status"] == "vivo" and alive["extended_ports_scanned"] is True
    ports = {(s["scheme"], s["port"]) for s in alive["services"]}
    assert ports == {("https", 443), ("https", 8443)}  # 8080 recusou, 443 e 8443 subiram
    # noweb: liveness falhou nas 2 portas; estendidas puladas (sem flag de scan estendido).
    noweb = state["hosts"]["noweb.example.com"]
    assert noweb["status"] == "sem_web" and "extended_ports_scanned" not in noweb
    assert not any(host == "noweb.example.com" and port in (8443, 8080) for _, host, port, *_ in prober.calls)


def test_extended_ports_report_extra_ports_and_summary(plan):
    plan["http"].update(extended_ports=["https:8443"])
    over = {("alive.example.com", 443): {"outcome": "http", "http_status": 200, "server": "edge"},
            ("alive.example.com", 8443): {"outcome": "http", "http_status": 401, "server": "grafana"}}
    class PortProber(Prober):
        def probe(self, scheme, host, port, address, headers, timeout, max_bytes):
            self.calls.append((scheme, host, port, address, headers))
            base = over.get((host, port)) or {"outcome": "refused"}
            return {"scheme": scheme, "port": port, "address": address, **copy.deepcopy(base)}
    state, *_ = run(plan, ["alive.example.com"], prober=PortProber())
    assert state["summary"]["services"] == 2 and state["summary"]["multiport_hosts"] == 1
    item = v.row("alive.example.com", state["hosts"]["alive.example.com"])
    assert item["extra_ports"] == ["https:8443"] and item["port"] == 443


def test_extended_ports_each_gated_per_url(plan):
    plan["http"].update(extended_ports=["https:8443"])
    gate = Gate(url_scope={"https://alive.example.com:8443/": "out_of_scope"})
    over = {("alive.example.com", "https"): {"outcome": "http", "http_status": 200, "server": "nginx"}}
    class PortProber(Prober):
        def probe(self, scheme, host, port, address, headers, timeout, max_bytes):
            self.calls.append((scheme, host, port, address, headers))
            base = over.get((host, scheme)) or {"outcome": "refused"}
            return {"scheme": scheme, "port": port, "address": address, **copy.deepcopy(base)}
    state, gate, _, prober = run(plan, ["alive.example.com"], gate=gate, prober=PortProber())
    assert ("url", "https://alive.example.com:8443/") in gate.calls
    # Porta estendida negada pelo Mind: não sondada, mas o host segue vivo pela 443.
    assert not any(port == 8443 for _, _, port, *_ in prober.calls)
    assert state["hosts"]["alive.example.com"]["status"] == "vivo"


def test_extended_ports_must_not_repeat_liveness_probes(plan):
    plan["http"].update(probes=["https:443"], extended_ports=["https:443"])
    with pytest.raises(ValueError):
        v.validate(plan)


def test_stops_at_first_alive_probe_unless_probe_all(plan):
    _, _, _, prober = run(plan, ["alive.example.com"])
    assert [c[0] for c in prober.calls] == ["https"]
    plan["http"]["probe_all"] = True
    _, _, _, prober = run(plan, ["alive.example.com"])
    assert [c[0] for c in prober.calls] == ["https", "http"]


def test_each_probe_url_is_gated_and_attempt_logged_before_request(plan):
    events = []
    gate = Gate()
    _, gate, _, prober = run(plan, ["noweb.example.com"], gate=gate, prober=Prober(events=events),
                             log=lambda e: events.append(("log", e["host"], e["scheme"])))
    assert ("url", "https://noweb.example.com/") in gate.calls and ("url", "http://noweb.example.com/") in gate.calls
    assert events == [("log", "noweb.example.com", "https"), ("probe", "noweb.example.com", "https"),
                      ("log", "noweb.example.com", "http"), ("probe", "noweb.example.com", "http")]
    assert prober.calls[0][4] == {"x-researcher": "lab"}


def test_url_denied_by_mind_is_never_reported_dead(plan):
    gate = Gate(url_scope={"https://noweb.example.com/": "out_of_scope", "http://noweb.example.com/": "out_of_scope"})
    state, _, _, prober = run(plan, ["noweb.example.com"], gate=gate)
    entry = state["hosts"]["noweb.example.com"]
    assert entry["status"] == "nao_verificado" and entry["reason"] == "url_out_of_scope"
    assert prober.calls == []


def test_leads_are_untested_signals(plan):
    state, *_ = run(plan, ["dangling.example.com", "internal.example.com", "gone.example.com"])
    dangling = state["hosts"]["dangling.example.com"]["leads"]
    assert dangling[0]["type"] == "dangling_cname" and "[UNTESTED]" in dangling[0]["note"]
    assert state["hosts"]["internal.example.com"]["leads"][0]["type"] == "non_public_address_in_dns"
    assert state["hosts"]["gone.example.com"]["leads"] == []


def test_diff_against_baseline_reports_what_died_and_revived(plan):
    baseline = {"alive.example.com": {"status": "morto"}, "noweb.example.com": {"status": "vivo"},
                "gone.example.com": {"status": "morto"}}
    state, *_ = run(plan, ["alive.example.com", "noweb.example.com", "gone.example.com", "tls.example.com"],
                    baseline=baseline)
    change = {h: e["change"] for h, e in state["hosts"].items()}
    assert change == {"alive.example.com": "reviveu", "noweb.example.com": "morreu",
                      "gone.example.com": "igual", "tls.example.com": "novo"}


def test_alive_fingerprint_change_is_reported(plan):
    first, *_ = run(plan, ["alive.example.com"])
    baseline = {"alive.example.com": {"status": "vivo", "fingerprint": first["hosts"]["alive.example.com"]["fingerprint"]}}
    same, *_ = run(plan, ["alive.example.com"], baseline=baseline)
    assert same["hosts"]["alive.example.com"]["change"] == "igual"
    changed = Prober(overrides={("alive.example.com", "https"): {"outcome": "http", "http_status": 403, "server": "cloudflare"}})
    other, *_ = run(plan, ["alive.example.com"], baseline=baseline, prober=changed)
    assert other["hosts"]["alive.example.com"]["change"] == "mudou"


def test_revisit_known_rechecks_baseline_hosts(plan):
    plan["revisit_known"] = True
    state, _, resolver, _ = run(plan, [], baseline={"gone.example.com": {"status": "vivo"}})
    assert resolver.calls == ["gone.example.com"]
    assert state["hosts"]["gone.example.com"]["change"] == "morreu"
    assert state["hosts"]["gone.example.com"]["sources"] == ["baseline"]


def test_scope_revision_change_blocks_and_stops_traffic(plan):
    class Changed(Gate):
        def host(self, host):
            if host == "noweb.example.com":
                raise v.Blocked("scope_revision_changed")
            return super().host(host)
    state, _, resolver, prober = run(plan, ["alive.example.com", "noweb.example.com", "gone.example.com"], gate=Changed())
    assert state["status"] == "blocked" and state["reason"] == "scope_revision_changed"
    assert resolver.calls == ["alive.example.com"]
    assert state["hosts"]["alive.example.com"]["status"] == "vivo"
    assert state["hosts"]["gone.example.com"]["status"] == "nao_verificado"


def test_mind_outage_is_blocked_not_dead(plan):
    class Down(Gate):
        def host(self, host):
            raise v.HiveError("SECRET_TOKEN")
    state, *_ = run(plan, ["gone.example.com"], gate=Down())
    assert state["status"] == "blocked" and state["reason"] == "scope_service_unavailable"
    assert state["hosts"]["gone.example.com"]["status"] == "nao_verificado"
    assert "SECRET_TOKEN" not in json.dumps(state)


def test_cancel_and_budget_leave_rest_unverified(plan):
    resolver_calls = []
    class Counting(Resolver):
        def resolve(self, host):
            resolver_calls.append(host)
            return super().resolve(host)
    plan["hosts"] = ["gone.example.com", "alive.example.com", "noweb.example.com"]
    state = v.execute(plan, gate=Gate(), resolver=Counting(), prober=Prober(), save=lambda s: None,
                      cancelled=lambda: len(resolver_calls) >= 1)
    assert state["status"] == "partial" and state["reason"] == "cancelled_by_operator"
    assert state["hosts"]["gone.example.com"]["status"] == "morto"
    assert {state["hosts"][h]["status"] for h in plan["hosts"][1:]} == {"nao_verificado"}

    ticks = iter(range(0, 10 ** 6, 1000))
    state, *_ = run(plan, ["gone.example.com", "alive.example.com"], clock=lambda: next(ticks))
    assert state["status"] == "partial" and state["reason"] == "budget_exhausted"


def test_repeated_429_stops_http_stage(plan):
    limited = {(h, "https"): {"outcome": "http", "http_status": 429} for h in ("a.example.com", "b.example.com", "c.example.com")}
    hosts = ["a.example.com", "b.example.com", "c.example.com", "alive.example.com"]
    for h in hosts[:3]:
        DNS[h] = {"rcode": "NOERROR", "addresses": ["93.184.216.40"], "cnames": []}
    try:
        state, _, _, prober = run(plan, hosts, prober=Prober(overrides=limited))
    finally:
        for h in hosts[:3]:
            DNS.pop(h)
    assert state["hosts"]["a.example.com"]["status"] == "vivo"  # 429 prova serviço respondendo.
    assert state["hosts"]["alive.example.com"]["status"] == "nao_verificado"
    assert state["hosts"]["alive.example.com"]["reason"] == "target_rate_limited"
    assert state["status"] == "partial" and state["reason"] == "target_rate_limited"
    assert len(prober.calls) == 3


def test_max_hosts_truncation_is_partial(plan):
    plan["limits"]["max_hosts"] = 1
    state, *_ = run(plan, ["gone.example.com", "alive.example.com"])
    assert list(state["hosts"]) == ["gone.example.com"]
    assert state["status"] == "partial" and state["reason"] == "max_hosts_truncated"


def test_failed_passive_source_makes_recon_partial(plan):
    plan["passive"]["enabled"] = True
    discover = lambda domains: ({"gone.example.com": ["crt.sh"]},
                                [{"source": "crt.sh", "status": "ok"}, {"source": "otx", "status": "__ERR__:URLError"},
                                 {"source": "virustotal", "status": "sem VT_API_KEY (pulado)"}])
    state, *_ = run(plan, [], discover=discover)
    assert state["discovery"]["failed_sources"] == ["otx"]
    assert state["status"] == "partial" and state["reason"] == "passive_sources_failed"
    assert state["hosts"]["gone.example.com"]["sources"] == ["crt.sh"]


def test_active_dns_generates_candidates_gated_and_prunes_non_resolvers(plan):
    plan["active_dns"].update(enabled=True, wordlist="builtin", permutations=False, max_candidates=5000)
    plan["domains"] = ["example.net"]  # base sem colisão com os fixtures .example.com
    # Só 'api.example.net' existe entre os milhares de candidatos de força bruta.
    DNS["api.example.net"] = {"rcode": "NOERROR", "addresses": ["93.184.216.34"], "cnames": []}
    prober = Prober(overrides={("api.example.net", "https"): {"outcome": "http", "http_status": 200, "server": "nginx"}})
    try:
        state, gate, resolver, _ = run(plan, ["gone.example.com"], prober=prober)
    finally:
        DNS.pop("api.example.net")
    hosts = state["hosts"]
    assert "api.example.net" in hosts and hosts["api.example.net"]["sources"] == ["brute"]
    assert hosts["api.example.net"]["status"] == "vivo"
    # Candidatos que não resolveram foram podados; o host conhecido permanece.
    assert "www.example.net" not in hosts and "gone.example.com" in hosts
    assert state["discovery"]["active_candidates"] > 300
    assert state["discovery"]["active_found"] == 1
    # DNS só foi chamado para hosts gateados por host (nenhuma resolução sem gate).
    gated = {h for kind, h in gate.calls if kind == "host"}
    assert set(resolver.calls) <= gated and "api.example.net" in gated


def test_active_dns_permutations_use_known_labels(plan):
    plan["active_dns"].update(enabled=True, wordlist="none", permutations=True, max_candidates=5000)
    plan["domains"] = ["example.com"]
    candidates = v.active_candidates(plan, {"api.example.com", "example.com"})
    assert "api-staging.example.com" in candidates and "staging-api.example.com" in candidates
    assert "apidev.example.com" in candidates
    assert "api.example.com" not in candidates  # já conhecido, não recandidata
    assert all("api" in host for host in candidates)  # só permuta o rótulo observado


def test_active_dns_speculative_resolving_to_internal_is_kept(plan):
    plan["active_dns"].update(enabled=True, wordlist="builtin", permutations=False, max_candidates=5000)
    plan["domains"] = ["example.com"]
    DNS["admin.example.com"] = {"rcode": "NOERROR", "addresses": ["10.0.0.9"], "cnames": []}
    try:
        state, *_ = run(plan, [])
    finally:
        DNS.pop("admin.example.com")
    assert state["hosts"]["admin.example.com"]["status"] == "interno"  # resolveu: não é poda


def test_active_dns_disabled_adds_no_candidates(plan):
    plan["active_dns"]["enabled"] = False
    state, _, resolver, _ = run(plan, ["gone.example.com"])
    assert resolver.calls == ["gone.example.com"]
    assert state["discovery"]["active_candidates"] == 0


def test_active_dns_requires_dns_and_a_source():
    plan = json.loads((v.ROOT / "examples/vigia/mission.json").read_text())
    plan["active_dns"].update(enabled=True, wordlist="none", permutations=False)
    with pytest.raises(ValueError):
        v.validate(plan)


def test_handoff_targets_separates_standard_and_extended_ports(plan):
    plan["http"].update(extended_ports=["https:8443"])
    over = {("alive.example.com", 443): {"outcome": "http", "http_status": 200, "server": "edge"},
            ("alive.example.com", 8443): {"outcome": "http", "http_status": 401, "server": "grafana"},
            ("tls.example.com", 443): {"outcome": "tls_invalid", "tls_error": "expired"}}
    class PortProber(Prober):
        def probe(self, scheme, host, port, address, headers, timeout, max_bytes):
            self.calls.append((scheme, host, port, address, headers))
            return {"scheme": scheme, "port": port, "address": address,
                    **copy.deepcopy(over.get((host, port)) or {"outcome": "refused"})}
    state, *_ = run(plan, ["alive.example.com", "tls.example.com", "gone.example.com"], prober=PortProber())
    out = v.handoff_targets(state, rate=2.0, level="full")
    assert out["alive_hosts"] == ["alive.example.com", "tls.example.com"]
    assert "gone.example.com" not in out["alive_hosts"]  # morto não vira alvo
    assert set(out["hosts"]) == {"alive.example.com", "tls.example.com"}
    assert out["urls"] == ["https://alive.example.com:8443/"]  # porta estendida vira --url
    assert "--hosts alive.example.com,tls.example.com" in out["suggested_command"]
    assert "--url https://alive.example.com:8443/" in out["suggested_command"]
    assert "--rate 2.0" in out["suggested_command"] and out["suggested_command"].startswith("python3 tools/saquear.py example")


def test_handoff_targets_falls_back_when_services_absent(plan):
    # Resultado de versão antiga: host vivo sem campo services nem porta detalhada.
    state = {"program_id": "1win", "run_id": "old", "status": "completed",
             "hosts": {"a.1win.com": {"status": "vivo", "probes": [{"outcome": "http", "http_status": 200}]},
                       "b.1win.com": {"status": "vivo"}, "d.1win.com": {"status": "morto"}}}
    out = v.handoff_targets(state)
    assert out["hosts"] == ["a.1win.com", "b.1win.com"] and out["urls"] == []
    assert "d.1win.com" not in out["suggested_command"]


def test_targets_cli_requires_terminal_result(plan, tmp_path, capsys):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"program_id": "1win", "status": "running", "hosts": {}}))
    assert v.main(["targets", str(path)]) == 2  # não terminou → erro
    path.write_text(json.dumps({"program_id": "1win", "status": "completed", "hosts": {}}))
    assert v.main(["targets", str(path)]) == 1  # terminou, mas sem hosts vivos
    assert json.loads(capsys.readouterr().out)["alive_hosts"] == []


def test_completed_when_everything_classified(plan):
    state, *_ = run(plan, ["alive.example.com", "gone.example.com"])
    assert state["status"] == "completed" and state["reason"] == "all_hosts_classified"


@pytest.mark.parametrize("mutate", [
    lambda p: p["http"].update(probes=["ftp:21"]),
    lambda p: p["http"].update(probes=["https:443", "https:443"]),
    lambda p: p["dns"].update(enabled=False),          # HTTP sem DNS
    lambda p: p.update(hosts=["App.Example.com"]),
    lambda p: p["policy"].update(scope_revision="unapproved"),
    lambda p: p["policy"].update(automation_allowed=False),
    lambda p: p["limits"].update(rate=50),
    lambda p: p.update(extra=True),
    lambda p: p.update(domains=[], hosts=[], revisit_known=False),
])
def test_invalid_missions_are_rejected(plan, mutate):
    mutate(plan)
    with pytest.raises(ValueError):
        v.validate(plan)


@pytest.mark.parametrize("headers", ['{"Authorization": "Bearer X"}', '{"Cookie": "a=b"}', '{"Host": "x"}', "[]"])
def test_recon_headers_never_carry_credentials(monkeypatch, headers):
    monkeypatch.setenv("VIGIA_REQUIRED_HEADERS", headers)
    with pytest.raises(ValueError):
        v.required_headers("VIGIA_REQUIRED_HEADERS")


def test_public_addresses_excludes_internal_ranges():
    public, private = v.public_addresses(["10.1.2.3", "127.0.0.1", "169.254.169.254", "::1", "93.184.216.34", "fd00::1"])
    assert public == ["93.184.216.34"]
    assert set(private) == {"10.1.2.3", "127.0.0.1", "169.254.169.254", "::1", "fd00::1"}


def test_doh_resolver_reports_cname_chain_and_falls_back_to_aaaa():
    answers = {
        ("dangling.example.com", "A"): {"Status": 3, "Answer": [{"type": 5, "data": "Orphan.Example.net."}]},
        ("v6.example.com", "A"): {"Status": 0},
        ("v6.example.com", "AAAA"): {"Status": 0, "Answer": [{"type": 28, "data": "2606:2800:220:1::1"}]},
    }
    queried = []
    def query(name, rtype, timeout):
        queried.append((name, rtype))
        return answers[(name, rtype)]
    resolver = v.DohResolver(query=query)
    assert resolver.resolve("dangling.example.com") == {"rcode": "NXDOMAIN", "addresses": [], "cnames": ["orphan.example.net"]}
    assert queried == [("dangling.example.com", "A")]  # NXDOMAIN não consulta AAAA.
    assert resolver.resolve("v6.example.com")["addresses"] == ["2606:2800:220:1::1"]
    def broken(name, rtype, timeout):
        raise OSError("network down")
    assert v.DohResolver(query=broken).resolve("x.example.com")["rcode"] == "ERROR"


def test_baseline_keeps_previous_state_for_unverified(plan, monkeypatch, tmp_path):
    monkeypatch.setattr(v, "BASELINES", tmp_path)
    gate = Gate(host_scope={"unknown.example.com": "unverified"})
    state, *_ = run(plan, ["gone.example.com", "unknown.example.com"], gate=gate)
    previous = {"unknown.example.com": {"status": "vivo", "fingerprint": "abc"}}
    v.update_baseline("example", state, previous)
    saved = v.load_baseline("example")
    assert saved["unknown.example.com"] == {"status": "vivo", "fingerprint": "abc"}
    assert saved["gone.example.com"]["status"] == "morto"


def test_stage_splits_inventory_under_remote_limit(plan, monkeypatch, tmp_path):
    monkeypatch.setenv("HIVE_HANDLE", "lab")
    monkeypatch.setenv("HIVE_TEAM_TAG", "test")
    # Com platform/target_name o front matter ganha observed_targets (dobra a lista
    # de hosts): é o caminho de produção que estourava 16 KiB. O teste precisa cobri-lo.
    monkeypatch.setenv("EXCALIBULL_PLATFORM", "h1")
    monkeypatch.setenv("EXCALIBULL_TARGET_NAME", "Lab")
    many = [f"host-de-nome-bem-comprido-{i:04d}.staging.example.com" for i in range(400)]
    alive = {(h, "https"): {"outcome": "http", "http_status": 200, "server": "nginx", "title": "Painel " + "x" * 60} for h in many}
    for h in many:
        DNS[h] = {"rcode": "NOERROR", "addresses": ["93.184.216.50"], "cnames": []}
    try:
        state, *_ = run(plan, many + ["gone.example.com", "dangling.example.com"], prober=Prober(overrides=alive))
    finally:
        for h in many:
            DNS.pop(h)
    notes = v.stage(plan, state, data_dir=tmp_path)
    assert len(notes) >= 4  # resumo + vários blocos de vivos + mortos
    for note in notes:
        text = Path(note).read_text()
        assert len(text.encode()) < 16 * 1024
        assert "x-researcher" not in text.lower() and "93.184.216.50" not in text
    names = " ".join(Path(n).name for n in notes)
    assert "-resumo" in names and "-vivos-2" in names and "-mortos-1" in names
    summary = next(Path(n).read_text() for n in notes if "-resumo" in Path(n).name)
    assert "dangling_cname" in summary and "[UNTESTED]" in summary


def test_validate_cli_sends_no_traffic(plan, tmp_path, capsys):
    path = tmp_path / "mission.json"
    path.write_text(json.dumps(plan))
    assert v.main(["validate", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["traffic_sent"] is False


def test_background_worker_end_to_end_with_fake_mind(plan, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(v, "STATE_DIR", tmp_path)
    monkeypatch.setattr(v, "JOBS", tmp_path / "jobs")
    monkeypatch.setattr(v, "BASELINES", tmp_path / "baselines")
    monkeypatch.setenv("HIVE_HANDLE", "lab")
    monkeypatch.setenv("HIVE_TEAM_TAG", "test")
    monkeypatch.setenv("EXCALIBULL_OUTBOX_DIR", str(tmp_path / "outbox"))
    asked = []
    class Client:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def call(self, name, args):
            asked.append(name)
            return {"items": []}
        def context(self, program, asset, question):
            asked.append(asset["type"])
            return {"program_id": program, "asset": asset,
                    "scope": {"confirmed": True, "status": "authorized", "action_allowed": True, "scope_revision": REVISION}}
    monkeypatch.setattr(v, "HiveClient", Client)
    monkeypatch.setattr(v, "DohResolver", Resolver)
    monkeypatch.setattr(v, "Prober", Prober)
    plan["hosts"] = ["alive.example.com", "gone.example.com"]
    job = "a" * 32
    directory = v.job_directory(job)
    directory.mkdir(parents=True)
    (directory / "plan.json").write_text(json.dumps(plan))
    queued = v.new_state(plan)
    queued["status"] = "queued"
    v.private_write(directory / "result.json", json.dumps(queued))
    assert v.main(["run", str(directory / "plan.json"), "--job", job]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "completed" and output["publication"] == "staged"
    assert output["summary"]["alive"] == 1 and output["summary"]["dead"] == 1
    assert asked[0] == "hive_search" and asked.count("host") == 2 and asked.count("url_prefix") == 1
    assert v.job_status(job)["finished"] is True
    assert v.load_baseline("example")["gone.example.com"]["status"] == "morto"
    events = (directory / "events.jsonl").read_text().splitlines()
    assert [json.loads(e)["host"] for e in events] == ["alive.example.com"]
    assert v.main(["run", str(directory / "plan.json"), "--job", job]) == 2  # Um worker por job.


def test_submit_spawns_worker_and_cancel_signals(plan, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(v, "JOBS", tmp_path / "jobs")
    monkeypatch.setenv("HIVE_HANDLE", "lab")
    monkeypatch.setenv("HIVE_TEAM_TAG", "test")
    calls = []
    def spawn(argv, **kwargs):
        calls.append((argv, kwargs))
        return type("Process", (), {"pid": os.getpid()})()
    monkeypatch.setattr(v.bgjobs.subprocess, "Popen", spawn)
    plan["hosts"] = ["alive.example.com"]
    job = v.submit(plan)
    assert calls[0][0][:3] == [sys.executable, str(Path(v.__file__).resolve()), "run"]
    assert calls[0][1]["start_new_session"] is True
    status = v.job_status(job)
    assert status["status"] == "queued" and status["worker"] == "alive"
    assert v.main(["cancel", job]) == 1
    assert json.loads(capsys.readouterr().out)["cancel_requested"] is True
    assert v.main(["jobs"]) == 0
    assert json.loads(capsys.readouterr().out)["jobs"][0]["job_id"] == job


# ---------------------------------------------------------------- sonda real em loopback

class Handler(BaseHTTPRequestHandler):
    hits = []
    server_version, sys_version = "test-server", ""

    def do_GET(self):
        Handler.hits.append(self.headers.get("Host"))
        if self.server.redirect:
            self.send_response(302)
            self.send_header("Location", "https://login.example.com/u/12345/sso?token=SECRET")
            self.end_headers()
            return
        body = b"<html><head><title> Painel\n Interno </title></head><body>PRIVATE</body></html>"
        self.send_response(200)
        self.send_header("Set-Cookie", "session=SECRET")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.redirect = False
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    Handler.hits = []
    yield httpd
    httpd.shutdown()


def test_real_prober_reads_title_without_storing_body_or_cookies(server):
    port = server.server_address[1]
    result = v.Prober(allow_private=True).probe("http", "app.example.com", port, "127.0.0.1", {"x-researcher": "lab"}, 5, 65536)
    assert result["outcome"] == "http" and result["http_status"] == 200
    assert result["title"] == "Painel Interno" and result["server"] == "test-server"
    assert result["content_type"] == "text/html"
    assert Handler.hits == [f"app.example.com:{port}"]  # Host do alvo, conexão no IP fixado.
    assert "SECRET" not in json.dumps(result) and "PRIVATE" not in json.dumps(result)


def test_real_prober_never_follows_redirect_and_sanitizes_location(server):
    server.redirect = True
    port = server.server_address[1]
    result = v.Prober(allow_private=True).probe("http", "app.example.com", port, "127.0.0.1", {}, 5, 65536)
    assert result["http_status"] == 302 and len(Handler.hits) == 1
    assert "SECRET" not in result["location"] and "token" not in result["location"]
    assert result["location"].startswith("https://login.example.com/")


@pytest.mark.parametrize("value,expected", [
    ("https://[bad/x", "[unparseable]"),
    ("//cdn.example.com/a", "//cdn.example.com/a"),
    ("HTTPS://X.EXAMPLE.COM/A?token=SECRET", "https://x.example.com/A"),
    ("javascript:alert(1)", "[non-http]"),
    ("/pt?ref=1", "/pt"),
])
def test_location_never_raises_and_keeps_destination_host(value, expected):
    assert v._location(value, "h.example.com") == expected


def raw_server(payload):
    """Servidor TCP que responde `payload` cru e fecha: simula serviço que não fala HTTP direito."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    def serve():
        connection, _ = listener.accept()
        with connection:
            connection.recv(4096)
            connection.sendall(payload)
        listener.close()
    threading.Thread(target=serve, daemon=True).start()
    return listener.getsockname()[1]


def test_real_prober_non_http_service_is_protocol_error_with_cause():
    port = raw_server(b"SSH-2.0-OpenSSH_9.6\r\n")
    result = v.Prober(allow_private=True).probe("http", "app.example.com", port, "127.0.0.1", {}, 5, 1024)
    assert result["outcome"] == "protocol_error" and result["error"] == "http:BadStatusLine"


def test_real_prober_truncated_body_still_counts_as_http():
    port = raw_server(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\nServer: edge\r\n\r\n<title>Oi</title>")
    result = v.Prober(allow_private=True).probe("http", "app.example.com", port, "127.0.0.1", {}, 5, 4096)
    assert result["outcome"] == "http" and result["http_status"] == 200 and result["server"] == "edge"
    assert result["body_error"] == "IncompleteRead" and result["title"] == "Oi"


def test_passive_failures_are_retried_with_backoff(monkeypatch):
    import passive
    calls = {"crt.sh": 0}
    def crt(domain):
        calls["crt.sh"] += 1
        return ({"api.example.com"}, "ok") if calls["crt.sh"] >= 2 else (set(), "__ERR__:HTTPError")
    def keyless(domain):
        return set(), "sem VT_API_KEY (pulado)"
    monkeypatch.setattr(passive, "_HOST_SOURCES", (("crt.sh", crt), ("virustotal", keyless)))
    monkeypatch.setattr(passive, "_URL_SOURCES", ())
    monkeypatch.setattr(passive, "_cache_get", lambda *a: None)
    monkeypatch.setattr(passive, "_cache_put", lambda *a: None)
    slept = []
    hosts, sources = v.passive_discovery(["example.com"], sleep=slept.append)
    assert hosts == {"api.example.com": ["crt.sh"]}
    assert slept == [30] and calls["crt.sh"] == 2  # Só a fonte falha foi repetida, uma vez.
    status = {s["source"]: s["status"] for s in sources}
    assert status["crt.sh"].startswith("ok") and "pulado" in status["virustotal"]


@pytest.mark.skipif(not __import__("shutil").which("openssl"), reason="openssl ausente")
def test_real_prober_self_signed_tls_is_alive_but_invalid(tmp_path):
    import ssl
    import subprocess
    key, cert = tmp_path / "key", tmp_path / "cert"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "1", "-subj", "/CN=app.example.com"], check=True, capture_output=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.redirect = False
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    Handler.hits = []
    try:
        result = v.Prober(allow_private=True).probe("https", "app.example.com", httpd.server_address[1],
                                                    "127.0.0.1", {}, 5, 1024)
    finally:
        httpd.shutdown()
    assert result["outcome"] == "tls_invalid" and "self" in result["tls_error"].lower()
    assert Handler.hits == []  # Certificado inválido: nenhum request HTTP enviado.
    assert v.classify({"scope": "authorized", "dns": {"rcode": "NOERROR", "addresses": ["93.184.216.34"]},
                       "public_addresses": ["93.184.216.34"], "probes": [result]})[0] == "vivo"


def test_real_prober_reports_refused_port():
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        port = probe_socket.getsockname()[1]
    result = v.Prober(allow_private=True).probe("http", "app.example.com", port, "127.0.0.1", {}, 2, 1024)
    assert result["outcome"] == "refused"
