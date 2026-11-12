#!/usr/bin/env python3
"""Vigia: recon completo em segundo plano que separa o que está vivo do que morreu (stdlib).

Pipeline por missão (JSON revisado pelo operador):

1. **Descoberta passiva** — fontes de terceiros do `passive.py` (CT, OTX, Wayback...)
   + sementes explícitas + hosts do baseline anterior. Não toca o alvo.
2. **Gate do Mind por host** (`hive_get_context`, tipo `host`) antes de qualquer DNS.
3. **DNS** — DoH (padrão, expõe a cadeia CNAME) ou resolvedor do sistema.
4. **Gate do Mind por URL exata** (`url_prefix`) antes de cada GET.
5. **Sonda HTTP** — um GET em `/` por porta, sem redirect/proxy/cookie/retry,
   conectando ao IP já resolvido (pinning) e jamais a endereços não públicos.
6. **Classificação + diff** com o baseline: vivo / sem_web / morto / interno /
   fora_de_escopo / nao_verificado, e novo / morreu / reviveu / mudou / igual.

Desconhecido nunca vira morto: falha do Mind, SERVFAIL, orçamento ou cancelamento
resultam em `nao_verificado`. Leads (CNAME pendurado, IP interno em DNS público)
são `[UNTESTED]` e exigem verificação humana. Nada aqui autoriza tráfego futuro.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import html
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import bgjobs
from hive_documents import SECRET, identifier, identity, now
from hive_gateway import HiveClient, HiveError
from hive_outbox import prepare, private_write
from hive_scope_cache import normalize_asset
from netcommon import DEFAULT_UA, RateLimiter
from recon_records import safe_path

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / ".hive" / "vigia"
JOBS = STATE_DIR / "jobs"
BASELINES = STATE_DIR / "baselines"
VERSION = 1
KEYS = {"version", "id", "program_id", "domains", "hosts", "revisit_known", "passive", "active_dns", "dns", "http", "policy", "limits"}
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
WORDLIST = Path(__file__).resolve().parent / "data" / "vigia-subdomains.txt"
PROBE = re.compile(r"(https?):([1-9][0-9]{0,4})")

ALIVE, NO_WEB, DEAD, INTERNAL = "vivo", "sem_web", "morto", "interno"
OUT_OF_SCOPE, UNVERIFIED = "fora_de_escopo", "nao_verificado"
DEAD_LIKE = {NO_WEB, DEAD}
TERMINAL = {"completed", "partial", "blocked", "failed"}
# Desfechos de sonda que provam um serviço escutando (TCP aceito).
SERVICE_UP = {"http", "tls_invalid", "tls_error", "protocol_error"}
CONSECUTIVE_429_LIMIT = 3


class Blocked(Exception):
    """Interrompe a missão inteira (revisão de escopo mudou, Mind fora do ar...)."""


class Stop(Exception):
    """Encerra a varredura cedo; hosts restantes ficam `nao_verificado`."""


# ---------------------------------------------------------------- validação

def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("campos ausentes/desconhecidos na missão")


def _int(value, lo, hi, name):
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError("limite inteiro inválido: " + name)


def _host(value):
    return normalize_asset({"type": "host", "value": value})["value"]


def validate(plan):
    keys(plan, KEYS)
    if type(plan["version"]) is not int or plan["version"] != VERSION:
        raise ValueError("versão de missão não suportada")
    identifier(plan["id"])
    identifier(plan["program_id"])
    for field, limit in (("domains", 50), ("hosts", 2000)):
        if not isinstance(plan[field], list) or len(plan[field]) > limit:
            raise ValueError(f"{field}: lista de até {limit} hosts")
        canonical = [_host(h) for h in plan[field]]
        if len(set(canonical)) != len(canonical) or canonical != plan[field]:
            raise ValueError(f"{field}: hosts canônicos (minúsculos) e sem repetição")
    if not plan["domains"] and not plan["hosts"] and not plan["revisit_known"]:
        raise ValueError("informe domínios, hosts ou revisit_known")
    if type(plan["revisit_known"]) is not bool:
        raise ValueError("revisit_known deve ser booleano")
    keys(plan["passive"], {"enabled"})
    keys(plan["active_dns"], {"enabled", "wordlist", "permutations", "max_candidates"})
    keys(plan["dns"], {"enabled", "resolver"})
    keys(plan["http"], {"enabled", "probes", "probe_all", "extended_ports"})
    for stage in ("passive", "active_dns", "dns", "http"):
        if type(plan[stage]["enabled"]) is not bool:
            raise ValueError(f"{stage}.enabled deve ser booleano")
    if plan["passive"]["enabled"] and not plan["domains"]:
        raise ValueError("descoberta passiva exige domains")
    active = plan["active_dns"]
    if active["wordlist"] not in {"builtin", "none"}:
        raise ValueError("active_dns.wordlist deve ser builtin ou none")
    if type(active["permutations"]) is not bool:
        raise ValueError("active_dns.permutations deve ser booleano")
    _int(active["max_candidates"], 0, 20000, "active_dns.max_candidates")
    if active["enabled"]:
        if not plan["dns"]["enabled"]:
            raise ValueError("descoberta ativa de DNS exige dns.enabled")
        if not plan["domains"]:
            raise ValueError("descoberta ativa exige domains como base dos candidatos")
        if active["wordlist"] == "none" and not active["permutations"]:
            raise ValueError("descoberta ativa exige wordlist builtin ou permutações")
    if plan["dns"]["resolver"] not in {"doh", "system"}:
        raise ValueError("dns.resolver deve ser doh ou system")
    if plan["http"]["enabled"] and not plan["dns"]["enabled"]:
        raise ValueError("sonda HTTP exige DNS: o IP resolvido é fixado e conferido")
    probes = plan["http"]["probes"]
    if not isinstance(probes, list) or not 1 <= len(probes) <= 6 or len(set(probes)) != len(probes):
        raise ValueError("http.probes: 1 a 6 entradas distintas")
    extended = plan["http"]["extended_ports"]
    if not isinstance(extended, list) or len(extended) > 16 or len(set(extended)) != len(extended):
        raise ValueError("http.extended_ports: até 16 entradas distintas")
    for probe in list(probes) + list(extended):
        match = PROBE.fullmatch(probe) if isinstance(probe, str) else None
        if not match or not 1 <= int(match[2]) <= 65535:
            raise ValueError("sonda no formato https:443 ou http:80")
    if set(probes) & set(extended):
        raise ValueError("http.extended_ports não deve repetir entradas de http.probes")
    if type(plan["http"]["probe_all"]) is not bool:
        raise ValueError("http.probe_all deve ser booleano")
    policy = plan["policy"]
    keys(policy, {"reviewed", "automation_allowed", "scope_revision", "required_headers_env"})
    if policy["reviewed"] is not True or policy["automation_allowed"] is not True:
        raise ValueError("revise a missão e confirme que o programa permite automação")
    if not isinstance(policy["scope_revision"], str) or not policy["scope_revision"] or policy["scope_revision"] == "unapproved":
        raise ValueError("revisão aprovada do Mind necessária")
    if not isinstance(policy["required_headers_env"], str) or not re.fullmatch(r"VIGIA_[A-Z][A-Z0-9_]{0,80}", policy["required_headers_env"]):
        raise ValueError("alias de ambiente VIGIA_* necessário")
    limits = plan["limits"]
    keys(limits, {"max_hosts", "seconds", "timeout", "rate", "dns_rate", "response_bytes"})
    for name, lo, hi in (("max_hosts", 1, 5000), ("seconds", 30, 14400), ("timeout", 1, 30), ("response_bytes", 1024, 262144)):
        _int(limits[name], lo, hi, name)
    for name, lo, hi in (("rate", 0.1, 10), ("dns_rate", 0.5, 50)):
        value = limits[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not lo <= value <= hi:
            raise ValueError(f"{name} deve estar entre {lo} e {hi} req/s, respeitando o programa")
    return plan


def required_headers(name):
    """Headers de identificação exigidos pelo programa. Recon é anônimo: credencial é erro."""
    value = json.loads(os.environ.get(name, "{}"))
    if not isinstance(value, dict):
        raise ValueError("headers de ambiente devem ser objeto JSON")
    normalized = {}
    for key, item in value.items():
        if (not isinstance(key, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                or not isinstance(item, str) or any(ord(c) < 32 or ord(c) > 126 for c in item)
                or key.lower() in {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization",
                                   "authorization", "cookie", "accept", "accept-encoding", "user-agent"}
                or key.lower() in normalized):
            raise ValueError("header inválido ou credencial nos headers do recon")
        normalized[key.lower()] = item
    return normalized


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


# ---------------------------------------------------------------- componentes

def _failed(status):
    return str(status).startswith(("__ERR__", "parse:"))


def passive_discovery(domains, retries=2, backoff=30, sleep=time.sleep):
    """Fontes de terceiros; devolve ({host: [fontes]}, [status por fonte]).

    crt.sh (502), OTX (429) e Wayback falham de forma passageira com frequência:
    só os pares (domínio, fonte) que falharam são repetidos, com espera crescente.
    Sucesso entra no cache do `passive.py`; fonte sem chave ("pulado") não é repetida.
    """
    import passive  # Importação tardia: o módulo só é necessário com a fase passiva ligada.
    host_sources, _, results = passive.collect(domains)
    table = {(d, n): (nh, st) for (d, n, nh, _, st) in results}
    functions = {name: (fn, "hosts") for name, fn in passive._HOST_SOURCES}
    functions.update({name: (fn, "urls") for name, fn in passive._URL_SOURCES})
    for attempt in range(1, retries + 1):
        failed = sorted(key for key, (_, status) in table.items() if _failed(status) and key[1] in functions)
        if not failed:
            break
        sleep(backoff * attempt)
        for domain, name in failed:
            fn, kind = functions[name]
            _, _, hosts, _, status = passive._run_source(name, fn, domain, kind, 3600)
            for host in hosts:
                host_sources.setdefault(host, set()).add(name)
            table[(domain, name)] = (len(hosts), f"{status} [tentativa {attempt + 1}]")
    results = [(d, n, nh, 0, st) for (d, n), (nh, st) in sorted(table.items())]
    scoped = {}
    for host, sources in host_sources.items():
        if any(host == d or host.endswith("." + d) for d in domains):
            try:
                scoped[_host(host)] = sorted(sources)
            except ValueError:
                continue
    return scoped, [{"domain": d, "source": n, "hosts": nh, "status": st} for (d, n, nh, _, st) in results]


def environment(host):
    try:
        import passive
        return passive.classify_env(host)
    except ImportError:
        return "unknown"


class MindGate:
    """Escopo ao vivo: `host` antes do DNS, `url_prefix` exato antes de cada GET."""
    def __init__(self, client, plan):
        self.client, self.plan = client, plan

    def _check(self, asset, question):
        result = self.client.context(self.plan["program_id"], asset, question)
        scope = result.get("scope", {})
        if (scope.get("confirmed") is True and scope.get("status") == "authorized"
                and scope.get("action_allowed") is True):
            if scope.get("scope_revision") != self.plan["policy"]["scope_revision"]:
                raise Blocked("scope_revision_changed")
            return "authorized"
        if scope.get("confirmed") is True and scope.get("status") == "out_of_scope":
            return "out_of_scope"
        return "unverified"  # unknown/não confirmado/ação negada: sem alegação de escopo.

    def host(self, host):
        return self._check({"type": "host", "value": host},
                           "Vigia: resolver DNS e sondar liveness HTTP (um GET em /) deste host em recon automatizado")

    def url(self, url):
        return self._check({"type": "url_prefix", "value": url},
                           "Vigia: um GET em / sem redirect para classificar o host como vivo/morto")


def _doh_query(name, rtype, timeout):
    query = urllib.parse.urlencode({"name": name, "type": rtype})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request("https://dns.google/resolve?" + query,
                                     headers={"Accept": "application/dns-json", "User-Agent": DEFAULT_UA})
    with opener.open(request, timeout=timeout) as response:
        return json.loads(response.read(65536))


class DohResolver:
    """DNS-over-HTTPS (dns.google): rcode real e cadeia CNAME, que o stdlib não expõe."""
    RCODES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

    def __init__(self, query=_doh_query, timeout=10):
        self.query, self.timeout = query, timeout

    def resolve(self, host):
        cnames, addresses, rcode = [], [], "ERROR"
        try:
            for rtype, code in (("A", 1), ("AAAA", 28)):
                data = self.query(host, rtype, self.timeout)
                rcode = self.RCODES.get(data.get("Status"), "ERROR")
                for answer in data.get("Answer") or []:
                    value = str(answer.get("data", "")).rstrip(".").lower()
                    if answer.get("type") == 5 and value and value not in cnames:
                        cnames.append(value)
                    elif answer.get("type") == code and value:
                        addresses.append(value)
                if rcode != "NOERROR" or addresses:
                    break  # Só consulta AAAA quando A respondeu NOERROR sem endereço.
        except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
            return {"rcode": "ERROR", "addresses": [], "cnames": cnames}
        return {"rcode": rcode, "addresses": sorted(set(addresses)), "cnames": cnames}


class SystemResolver:
    """Resolvedor do sistema: sem cadeia CNAME completa (só o nome canônico)."""
    def resolve(self, host):
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP, flags=socket.AI_CANONNAME)
        except socket.gaierror as exc:
            rcode = "NXDOMAIN" if exc.errno in {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -999)} else "SERVFAIL"
            return {"rcode": rcode, "addresses": [], "cnames": []}
        except (OSError, UnicodeError):
            return {"rcode": "ERROR", "addresses": [], "cnames": []}
        canonical = (infos[0][3] or "").rstrip(".").lower() if infos else ""
        return {"rcode": "NOERROR", "addresses": sorted({info[4][0] for info in infos}),
                "cnames": [canonical] if canonical and canonical != host else []}


def public_addresses(addresses, allow_private=False):
    """Separa endereços públicos dos internos/loopback/link-local/reservados."""
    public, private = [], []
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        (public if allow_private or address.is_global else private).append(address)
    public.sort(key=lambda a: (a.version, int(a)))  # IPv4 primeiro.
    return [str(a) for a in public], [str(a) for a in private]


TITLE = re.compile(rb"<title[^>]*>(.*?)</title", re.I | re.S)


def _title(body):
    match = TITLE.search(body)
    if not match:
        return None
    text = " ".join(html.unescape(match[1].decode("utf-8", "replace")).split())[:120]
    return "[redacted]" if SECRET.search(text) else (text or None)


def _location(value, base_host):
    """Destino do redirect sem query/fragmento e com path sanitizado; nunca é seguido."""
    if not value:
        return None
    try:
        parsed = urllib.parse.urlsplit(value.strip())
        host = (parsed.hostname or "").lower()
        path = safe_path(parsed.path or "/")
    except ValueError:
        return "[unparseable]"  # Location malformado é dado do alvo, não erro de protocolo.
    if parsed.scheme in {"http", "https"}:
        return f"{parsed.scheme.lower()}://{host or base_host}{path}"
    if not parsed.scheme and host:
        return f"//{host}{path}"  # Relativo ao esquema: preservar o host de destino.
    if parsed.scheme:
        return "[non-http]"
    return path


class Prober:
    """Um GET em `/`: conecta ao IP fixado, sem proxy, redirect, cookie ou retry."""
    def __init__(self, allow_private=False):
        self.allow_private = allow_private  # Somente para testes em loopback.
        self.context = ssl.create_default_context()

    def probe(self, scheme, host, port, address, headers, timeout, max_bytes):
        phase, sock = "tcp", None
        result = {"scheme": scheme, "port": port, "address": address}
        try:
            sock = socket.create_connection((address, port), timeout=timeout)
            phase = "tls"
            if scheme == "https":
                sock = self.context.wrap_socket(sock, server_hostname=host)
            phase = "http"
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
            connection.sock = sock
            default = 443 if scheme == "https" else 80
            connection.request("GET", "/", headers={
                "Host": host if port == default else f"{host}:{port}", "User-Agent": DEFAULT_UA,
                "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close", **headers})
            response = connection.getresponse()
            phase = "body"
            status, headers = response.status, response.msg
            deadline, chunks, size = time.monotonic() + timeout, [], 0
            try:
                while size < max_bytes and time.monotonic() < deadline:
                    chunk = response.read(min(16384, max_bytes - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
            except (http.client.HTTPException, OSError, ValueError) as exc:
                # Status e headers já chegaram: o host respondeu HTTP; só o corpo falhou.
                result["body_error"] = type(exc).__name__
            body = b"".join(chunks)
        except ssl.SSLCertVerificationError as exc:
            result.update(outcome="tls_invalid", error=f"{phase}:{type(exc).__name__}",
                          tls_error=str(getattr(exc, "verify_message", "") or "verify_failed")[:80])
            return self._close(sock, result)
        except ssl.SSLError as exc:
            result.update(outcome="tls_error", error=f"{phase}:{type(exc).__name__}")
            return self._close(sock, result)
        except (http.client.HTTPException, OSError, ValueError) as exc:
            # Só a fase TCP distingue "nada escuta" de "algo escuta mas não fala HTTP".
            if phase == "tcp":
                outcome = ("refused" if isinstance(exc, ConnectionRefusedError) else
                           "timeout" if isinstance(exc, TimeoutError) else "unreachable")
            else:
                outcome = "tls_error" if phase == "tls" else "protocol_error"
            result.update(outcome=outcome, error=f"{phase}:{type(exc).__name__}")
            return self._close(sock, result)
        self._close(sock, result)
        # Interpretação local: um erro aqui é defeito do Vigia, nunca comportamento do alvo.
        result.update(outcome="http", http_status=status, body_bytes=size, body_truncated=size >= max_bytes,
                      body_sha256=hashlib.sha256(body).hexdigest())
        declared = (headers.get("Content-Length") or "").strip()
        if declared.isdigit() and int(declared) > size and size < max_bytes and "body_error" not in result:
            result["body_error"] = "IncompleteRead"  # read(n) devolve parcial em silêncio quando a conexão cai.
        for field, parse in (("server", lambda: (headers.get("Server") or "").strip()[:80] or None),
                             ("content_type", lambda: (headers.get("Content-Type") or "").split(";")[0].strip()[:80] or None),
                             ("location", lambda: _location(headers.get("Location"), host)),
                             ("title", lambda: _title(body))):
            try:
                result[field] = parse()
            except Exception:  # noqa: BLE001 — falha de parsing não muda o veredito HTTP
                result[field] = None
                result.setdefault("parse_errors", []).append(field)
        return result

    @staticmethod
    def _close(sock, result):
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        return result


# ---------------------------------------------------------------- decisão

def classify(entry):
    """Veredito de um host a partir de escopo, DNS e sondas (função pura)."""
    if entry.get("scope") == "out_of_scope":
        return OUT_OF_SCOPE, "mind_out_of_scope"
    if entry.get("scope") != "authorized":
        return UNVERIFIED, entry.get("skip_reason") or "scope_not_confirmed"
    dns = entry.get("dns")
    if not dns:
        return UNVERIFIED, entry.get("skip_reason") or "dns_not_run"
    if dns["rcode"] not in {"NOERROR", "NXDOMAIN"}:
        return UNVERIFIED, "dns_" + dns["rcode"].lower()
    if not dns["addresses"]:
        return DEAD, "nxdomain" if dns["rcode"] == "NXDOMAIN" else "no_address"
    if not entry.get("public_addresses"):
        return INTERNAL, "resolves_to_non_public_address_not_probed"
    probes = entry.get("probes") or []
    if any(p.get("outcome") in SERVICE_UP for p in probes):
        return ALIVE, next(p["outcome"] for p in probes if p.get("outcome") in SERVICE_UP)
    skipped = next((p.get("reason") for p in probes if p.get("outcome") == "skipped"), None)
    if entry.get("skip_reason") or not probes or skipped:
        return UNVERIFIED, entry.get("skip_reason") or skipped or "http_not_run"
    return NO_WEB, "no_service_on_probed_ports"


def leads(entry):
    """Sinais `[UNTESTED]`: nunca são achados sem verificação manual."""
    found = []
    dns = entry.get("dns") or {}
    if dns.get("cnames") and entry.get("status") == DEAD:
        found.append({"type": "dangling_cname", "target": dns["cnames"][-1],
                      "note": "[UNTESTED] CNAME aponta para nome sem endereço; checar takeover manualmente"})
    if entry.get("private_addresses"):
        found.append({"type": "non_public_address_in_dns", "addresses": entry["private_addresses"][:4],
                      "note": "[UNTESTED] DNS público expõe endereço interno; não sondado"})
    return found


def fingerprint(entry):
    best = next((p for p in entry.get("probes") or [] if p.get("outcome") in SERVICE_UP), None)
    if not best:
        return None
    return digest({k: best.get(k) for k in ("scheme", "port", "outcome", "http_status", "server", "title", "location")})


def change(previous, entry):
    status = entry["status"]
    if status in {UNVERIFIED, OUT_OF_SCOPE}:
        return status
    if not previous:
        return "novo"
    before = previous.get("status")
    if before == ALIVE and status in DEAD_LIKE:
        return "morreu"
    if before in DEAD_LIKE and status == ALIVE:
        return "reviveu"
    if status == before == ALIVE and previous.get("fingerprint") != entry.get("fingerprint"):
        return "mudou"
    return "igual" if before == status else "mudou"


def new_state(plan):
    return {"version": 1, "run_id": uuid.uuid4().hex, "program_id": plan["program_id"], "mission_id": plan["id"],
            "plan_sha256": digest(plan), "started_at": now(), "status": "running", "reason": "in_progress",
            "stage": "queued", "discovery": {"sources": [], "hosts": 0, "truncated": False,
                                             "known": 0, "active_candidates": 0, "active_found": 0},
            "requests": {"mind": 0, "dns": 0, "http": 0}, "hosts": {}, "summary": {},
            "publication": "pending", "human_review_required": True, "llm_calls": 0}


# ---------------------------------------------------------------- execução

class Engine:
    def __init__(self, plan, gate, resolver, prober, save, log, headers, cancelled, baseline, clock):
        self.plan, self.gate, self.resolver, self.prober = plan, gate, resolver, prober
        self.save, self.log, self.headers = save, log, headers
        self.cancelled, self.baseline, self.clock = cancelled, baseline, clock
        self.limits = plan["limits"]
        self.http_limiter = RateLimiter(self.limits["rate"])
        self.dns_limiter = RateLimiter(self.limits["dns_rate"])
        self.started = clock()
        self.too_many = 0
        self.http_stopped = None

    def checkpoint(self):
        if self.cancelled():
            raise Stop("cancelled_by_operator")
        if self.clock() - self.started >= self.limits["seconds"]:
            raise Stop("budget_exhausted")

    def mind(self, kind, value):
        self.state["requests"]["mind"] += 1
        return getattr(self.gate, kind)(value)

    def scan(self, host, entry):
        self.checkpoint()
        entry["scope"] = self.mind("host", host)
        if entry["scope"] != "authorized" or not self.plan["dns"]["enabled"]:
            return
        self.checkpoint()
        self.dns_limiter.wait()
        self.state["requests"]["dns"] += 1
        entry["dns"] = dns = self.resolver.resolve(host)
        entry["public_addresses"], entry["private_addresses"] = public_addresses(
            dns["addresses"], getattr(self.prober, "allow_private", False))
        if not entry["public_addresses"] or not self.plan["http"]["enabled"]:
            return
        if self.http_stopped:
            entry["skip_reason"] = self.http_stopped
            return
        entry["probes"] = []
        # Fase 1: liveness barata — portas comuns, parando na primeira que responde.
        for probe in self.plan["http"]["probes"]:
            result = self._probe_port(host, probe, entry)
            if result and result.get("outcome") in SERVICE_UP and not self.plan["http"]["probe_all"]:
                break
        # Fase 2 (portas estendidas): só em host já vivo, para não varrer palpites mortos.
        extended = self.plan["http"]["extended_ports"]
        if extended and any(p.get("outcome") in SERVICE_UP for p in entry["probes"]):
            entry["extended_ports_scanned"] = True
            for probe in extended:
                self._probe_port(host, probe, entry)
        services = [{k: p[k] for k in ("scheme", "port", "outcome", "http_status", "server") if p.get(k) is not None}
                    for p in entry["probes"] if p.get("outcome") in SERVICE_UP]
        if services:
            entry["services"] = services

    def _probe_port(self, host, probe, entry):
        """Um gate de URL + um GET numa porta. Respeita rate, orçamento, 429 e cancelamento."""
        if self.http_stopped:
            entry["probes"].append({"outcome": "skipped", "reason": self.http_stopped})
            return None
        scheme, port = probe.split(":")
        port = int(port)
        url = f"{scheme}://{host}/" if port == (443 if scheme == "https" else 80) else f"{scheme}://{host}:{port}/"
        self.checkpoint()
        scope = self.mind("url", url)
        if scope != "authorized":
            entry["probes"].append({"scheme": scheme, "port": port, "outcome": "skipped", "reason": "url_" + scope})
            return None
        self.http_limiter.wait()
        remaining = self.limits["seconds"] - (self.clock() - self.started)
        if remaining <= 0:
            raise Stop("budget_exhausted")
        # Tentativa registrada antes do envio (log append-only, sem dados da resposta).
        self.log({"at": now(), "event": "http_attempt", "host": host, "scheme": scheme, "port": port})
        self.state["requests"]["http"] += 1
        result = self.prober.probe(scheme, host, port, entry["public_addresses"][0], self.headers,
                                   min(self.limits["timeout"], remaining), self.limits["response_bytes"])
        entry["probes"].append(result)
        if result.get("http_status") == 429:
            self.too_many += 1
            if self.too_many >= CONSECUTIVE_429_LIMIT:
                self.http_stopped = "target_rate_limited"
        else:
            self.too_many = 0
        return result

    def run(self, state, hosts):
        self.state = state
        last_save, stop = self.clock(), None
        for host in hosts:
            entry = state["hosts"][host]
            if stop is None:
                try:
                    self.scan(host, entry)
                except Stop as exc:
                    stop = str(exc)
            if stop is not None:
                # Interrompido neste host ou antes dele: sem prova de ausência de serviço.
                # Um serviço já observado continua provando que o host está vivo.
                entry.setdefault("skip_reason", stop)
            entry["status"], entry["reason"] = classify(entry)
            entry["fingerprint"] = fingerprint(entry)
            entry["change"] = change(self.baseline.get(host), entry)
            entry["leads"] = leads(entry)
            if self.clock() - last_save >= 2:
                self.save(state)
                last_save = self.clock()
        return stop


SPECULATIVE = {"brute", "permutation"}  # Fontes geradas pelo Vigia: só entram no inventário se resolverem.
# Afixos para permutar nomes já conhecidos: api -> api-dev, api2, staging-api, api-staging...
AFFIXES = ("dev", "staging", "stg", "test", "qa", "uat", "prod", "preprod", "beta", "demo",
           "internal", "admin", "api", "new", "old", "2", "3", "v2", "01", "02")


def load_wordlist():
    labels = []
    for line in WORDLIST.read_text(encoding="utf-8").splitlines():
        label = line.strip().lower()
        if label and not label.startswith("#") and LABEL.fullmatch(label):
            labels.append(label)
    return list(dict.fromkeys(labels))


def _labels_of(host, domains):
    """Rótulos à esquerda de um domínio-base conhecido (api.x.1win.com sob 1win.com -> api, x)."""
    for base in domains:
        if host.endswith("." + base):
            prefix = host[: -(len(base) + 1)]
            return [part for part in prefix.split(".") if LABEL.fullmatch(part)]
    return []


def permuted_labels(known_hosts, domains):
    """Permutações a partir dos rótulos já observados; afixo some se já for o rótulo (sem api-api)."""
    out = []
    for host in known_hosts:
        for label in _labels_of(host, domains):
            for affix in AFFIXES:
                if affix == label:
                    continue
                out.extend((f"{label}-{affix}", f"{affix}-{label}", f"{label}{affix}"))
    return list(dict.fromkeys(out))


def active_candidates(plan, known_hosts):
    """Nomes `label.base` a testar, excluindo os já conhecidos. Determinístico e limitado.

    Cada candidato ainda passa pelo gate do Mind por host antes do DNS, no scan.
    """
    active = plan["active_dns"]
    labels = load_wordlist() if active["wordlist"] == "builtin" else []
    if active["permutations"]:
        labels = list(dict.fromkeys(labels + permuted_labels(known_hosts, plan["domains"])))
    candidates = {}
    for base in plan["domains"]:
        for label in labels:
            host = f"{label}.{base}"
            if host not in known_hosts and _host(host) == host:
                candidates.setdefault(host, set()).add("permutation" if "-" in label or any(c.isdigit() for c in label[-2:]) else "brute")
    ordered = sorted(candidates)[: active["max_candidates"]]
    return {host: candidates[host] for host in ordered}


def build_targets(plan, discovered, baseline):
    """Sementes, baseline revisitado, descoberta passiva e, por fim, candidatos ativos.

    Fontes especulativas (`brute`/`permutation`) entram na varredura, mas são podadas
    do inventário se não resolverem — um palpite inexistente não é um host morto.
    """
    ordered = {}
    for host in plan["hosts"]:
        ordered.setdefault(host, set()).add("seed")
    if plan["revisit_known"]:
        for host in sorted(baseline):
            ordered.setdefault(host, set()).add("baseline")
    for host in sorted(discovered):
        ordered.setdefault(host, set()).update(discovered[host])
    real = len(ordered)
    if plan["active_dns"]["enabled"]:
        for host, sources in active_candidates(plan, set(ordered)).items():
            ordered.setdefault(host, set()).update(sources)
    hosts = list(ordered)
    limit = plan["limits"]["max_hosts"]
    return hosts[:limit], ordered, len(hosts) > limit, real


def is_speculative(entry):
    return bool(entry.get("sources")) and set(entry["sources"]) <= SPECULATIVE


def resolved(entry):
    return bool((entry.get("dns") or {}).get("addresses"))


def summarize(state):
    hosts = state["hosts"].values()
    count = lambda field, value: sum(1 for e in hosts if e.get(field) == value)
    return {"total": len(state["hosts"]),
            "alive": count("status", ALIVE),
            "dead": sum(1 for e in hosts if e.get("status") in DEAD_LIKE),
            "by_status": {s: count("status", s) for s in (ALIVE, NO_WEB, DEAD, INTERNAL, OUT_OF_SCOPE, UNVERIFIED)},
            "by_change": {c: count("change", c) for c in ("novo", "morreu", "reviveu", "mudou", "igual")},
            "leads": sum(len(e.get("leads") or []) for e in hosts),
            "services": sum(len(e.get("services") or []) for e in hosts),
            "multiport_hosts": sum(1 for e in hosts if len(e.get("services") or []) > 1)}


def execute(plan, *, gate, resolver, prober, save, log=lambda event: None, discover=passive_discovery,
            state=None, cancelled=None, baseline=None, clock=time.monotonic):
    """Dependências injetáveis somente pela API Python para testes offline."""
    validate(plan)
    headers = required_headers(plan["policy"]["required_headers_env"])
    baseline = baseline or {}
    state = new_state(plan) if state is None else state
    state.update(status="running", reason="in_progress", stage="passive")
    save(state)
    discovered = {}
    if plan["passive"]["enabled"]:
        try:
            discovered, sources = discover(plan["domains"])
            state["discovery"]["sources"] = sources
        except (OSError, ValueError, urllib.error.URLError):
            state["discovery"]["sources"] = [{"source": "passive", "status": "__ERR__:discovery_failed"}]
    # Fonte sem chave ("pulado") não é falha; erro/parse deixa a descoberta incompleta.
    degraded = sorted({s.get("source") for s in state["discovery"]["sources"]
                       if str(s.get("status", "")).startswith(("__ERR__", "parse:"))})
    hosts, provenance, truncated, real_count = build_targets(plan, discovered, baseline)
    speculative = sum(1 for host in hosts if provenance[host] <= SPECULATIVE)
    state["discovery"].update(hosts=len(provenance), truncated=truncated, failed_sources=degraded,
                              known=real_count, active_candidates=speculative)
    for host in hosts:
        state["hosts"][host] = {"sources": sorted(provenance[host]), "environment": environment(host)}
    state["stage"] = "scan"
    save(state)
    engine = Engine(plan, gate, resolver, prober, save, log, headers, cancelled or (lambda: False), baseline, clock)
    try:
        stop = engine.run(state, hosts)
    except Blocked as exc:
        stop = None
        state.update(status="blocked", reason=str(exc))
    except HiveError:
        stop = None
        state.update(status="blocked", reason="scope_service_unavailable")
    # Hosts não alcançados por um bloqueio global continuam não verificados.
    for host in hosts:
        entry = state["hosts"][host]
        if "status" not in entry:
            entry.setdefault("skip_reason", state["reason"] if state["status"] == "blocked" else "not_reached")
            entry["status"], entry["reason"] = classify(entry)
            entry["fingerprint"], entry["change"], entry["leads"] = None, entry["status"], leads(entry)
    # Poda: candidato ativo que não resolveu é ruído, não um host morto. Nomes conhecidos ficam.
    pruned = [host for host, entry in state["hosts"].items() if is_speculative(entry) and not resolved(entry)]
    for host in pruned:
        del state["hosts"][host]
    state["discovery"]["active_found"] = state["discovery"]["active_candidates"] - len(pruned)
    state["summary"] = summarize(state)
    if state["status"] != "blocked":
        unverified = state["summary"]["by_status"][UNVERIFIED]
        if stop:
            state.update(status="partial", reason=stop)
        elif engine.http_stopped or truncated or unverified or degraded:
            state.update(status="partial", reason=engine.http_stopped or ("max_hosts_truncated" if truncated else
                                                                          "some_hosts_unverified" if unverified else
                                                                          "passive_sources_failed"))
        else:
            state.update(status="completed", reason="all_hosts_classified")
    state.update(stage="done", ended_at=now(), elapsed_seconds=round(clock() - engine.started, 3))
    save(state)
    return state


# ---------------------------------------------------------------- baseline e notas

def baseline_path(program):
    return BASELINES / f"{identifier(program)}.json"


def load_baseline(program):
    path = baseline_path(program)
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or data.get("program_id") != program or not isinstance(data.get("hosts"), dict):
        raise ValueError("baseline do Vigia inválido; não sobrescrever")
    return data["hosts"]


def update_baseline(program, state, previous):
    """Só hosts classificados entram; não verificados preservam o estado anterior."""
    hosts = dict(previous)
    for host, entry in state["hosts"].items():
        if entry.get("status") in {ALIVE, NO_WEB, DEAD, INTERNAL}:
            hosts[host] = {"status": entry["status"], "fingerprint": entry.get("fingerprint"), "seen_at": state.get("ended_at")}
    private_write(baseline_path(program), json.dumps({"program_id": program, "updated_at": now(),
                                                       "run_id": state["run_id"], "hosts": hosts},
                                                      ensure_ascii=False, indent=2))


def row(host, entry):
    best = next((p for p in entry.get("probes") or [] if p.get("outcome") in SERVICE_UP), {})
    item = {"host": host, "status": entry["status"], "reason": entry.get("reason"), "change": entry.get("change"),
            "env": entry.get("environment")}
    if best:
        item.update({k: best[k] for k in ("scheme", "port", "http_status", "server", "title", "location", "tls_error", "error")
                     if best.get(k) is not None})
    dns = entry.get("dns") or {}
    if dns.get("cnames"):
        item["cname"] = dns["cnames"][-1]
    if entry.get("leads"):
        item["leads"] = [lead["type"] for lead in entry["leads"]]
    # Múltiplos serviços (portas estendidas) além da porta principal de liveness.
    extra = [f"{s['scheme']}:{s['port']}" for s in entry.get("services") or []
             if (s.get("scheme"), s.get("port")) != (best.get("scheme"), best.get("port"))]
    if extra:
        item["extra_ports"] = extra
    return item


def service_url(host, service):
    scheme, port = service["scheme"], service["port"]
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}/" if port == default else f"{scheme}://{host}:{port}/"


def handoff_targets(state, *, rate=1.0, level="full"):
    """Lista de alvos vivos pronta para o `saquear o navio`. Não autoriza tráfego.

    O Vigia faz liveness; o recon de conteúdo (crawl/JS/endpoints/CORS) é do `saquear`,
    que re-gateia cada URL via `authorized()` antes de qualquer tráfego. Esta ponte só
    separa os hosts vivos: `hosts` (porta padrão, viram https://host/ no saquear) e
    `urls` (serviços em porta não padrão, passados com --url).
    """
    hosts = state.get("hosts", {})
    alive = sorted(h for h in hosts if hosts[h].get("status") == ALIVE)
    standard, extra_urls = [], []
    for host in alive:
        # Fonte da verdade são as sondas; `services` pode faltar em resultados antigos.
        up = [p for p in hosts[host].get("probes") or [] if p.get("outcome") in SERVICE_UP and p.get("port")]
        ports = {p["port"] for p in up}
        if not ports or ports & {443, 80}:
            standard.append(host)  # sem detalhe de porta: saquear tenta https://host/
        for probe in up:
            if probe["port"] not in (443, 80):
                extra_urls.append(service_url(host, probe))
    program = state["program_id"]
    command = ["python3", "tools/saquear.py", program, "--level", level, "--rate", str(rate), "--cors"]
    if standard:
        command += ["--hosts", ",".join(standard)]
    for url in extra_urls:
        command += ["--url", url]
    return {"program_id": program, "run_id": state.get("run_id"), "alive_hosts": alive,
            "hosts": standard, "urls": sorted(set(extra_urls)),
            "note": "candidatos; o saquear re-gateia cada URL via hive_get_context antes de tráfego",
            "suggested_command": " ".join(command)}


# O limite real é remoto: 16 KiB (16384 B) por documento, incluindo front matter
# (asset_refs + observed_targets duplicam a lista de hosts) e marker. Orçar só o
# corpo não basta — o front matter escala com o nº de hosts do bloco. Medimos o
# documento renderizado inteiro e bisseccionamos até caber.
PUBLISH_LIMIT = 15200  # folga sob 16384 para variações de session_id/revisão


def _document_bytes(program, body, *, assets, tags, document_type, source):
    """Tamanho do documento renderizado (front matter + marker + corpo) sem enfileirar nem gerar tráfego."""
    import hive_documents as _hd
    prepared = _hd.document(program, body, assets=list(assets), tags=list(tags),
                            document_type=document_type, source=source)
    text, _marker, _witness = _hd.render(prepared, "0" * 32, "0" * 24, 1)
    return len(text.encode())


def _inventory_body(label, run, mission, rows, index="N"):
    return (f"# Vigia — {label} ({index})\n\nExecução `{run}`; missão `{mission}`. "
            "Inventário de liveness; não é achado nem autorização de tráfego.\n\n~~~json\n"
            + json.dumps(rows, ensure_ascii=False, indent=1) + "\n~~~\n")


def _fit_blocks(program, run, mission, label, hosts, members, common):
    """Divide os hosts do grupo em blocos cujo documento renderizado cabe no limite remoto."""
    tags = ["vigia", "recon-inventory", f"vigia-{label}"]
    blocks = []

    def place(group):
        if not group:
            return
        rows = [row(h, hosts[h]) for h in group]
        body = _inventory_body(label, run, mission, rows)
        fits = _document_bytes(program, body, assets=group, tags=tags,
                               document_type=common["document_type"], source=common["source"]) <= PUBLISH_LIMIT
        if fits or len(group) == 1:
            blocks.append(group)
            return
        middle = len(group) // 2
        place(group[:middle])
        place(group[middle:])

    place(sorted(members))
    return blocks


def stage(plan, state, *, data_dir=None):
    """Prepara resumo + inventário em blocos na outbox. Positivos e negativos."""
    run = state["run_id"]
    mission = state["mission_id"]
    hosts = state["hosts"]
    common = {"data_dir": data_dir, "source": "vigia", "document_type": "asset"}
    groups = (("vivos", [h for h in hosts if hosts[h]["status"] == ALIVE]),
              ("mortos", [h for h in hosts if hosts[h]["status"] in DEAD_LIKE]),
              ("outros", [h for h in hosts if hosts[h]["status"] in {INTERNAL, OUT_OF_SCOPE, UNVERIFIED}]))
    written = []
    for label, members in groups:
        for index, block in enumerate(_fit_blocks(plan["program_id"], run, mission, label, hosts, members, common), 1):
            body = _inventory_body(label, run, mission, [row(h, hosts[h]) for h in block], index)
            written.append(prepare(plan["program_id"], f"vigia-{run}-{label}-{index}", body,
                                   assets=block, tags=["vigia", "recon-inventory", f"vigia-{label}"],
                                   **common))
    interesting = {key: sorted(h for h in hosts if hosts[h].get("change") == key)[:200] for key in ("morreu", "reviveu", "novo")}
    lead_rows = [{"host": h, **lead} for h in sorted(hosts) for lead in hosts[h].get("leads") or []][:100]

    def resumo_body(changes, leads):
        summary = {"run_id": run, "mission_id": mission, "status": state["status"], "reason": state["reason"],
                   "started_at": state["started_at"], "ended_at": state.get("ended_at"), "requests": state["requests"],
                   "summary": state["summary"], "discovery": state["discovery"], "changes": changes,
                   "leads_untested": leads, "inventory_notes": len(written), "human_review_required": True}
        return ("# Vigia — resumo do recon\n\nLiveness por host com gate do Mind por host/URL. `nao_verificado` "
                "não é morto; `[UNTESTED]` não é achado. Baseline de comparação: local ao operador.\n\n~~~json\n"
                + json.dumps(summary, ensure_ascii=False, indent=1) + "\n~~~\n")

    # O resumo carrega listas longas no corpo; o front matter leva só uma amostra de
    # vivos para referência (asset_refs/observed_targets não precisam do inventário todo).
    alive = sorted(h for h in hosts if hosts[h]["status"] == ALIVE)
    assets = alive[:25]
    body = resumo_body(interesting, lead_rows)
    if _document_bytes(plan["program_id"], body, assets=assets, tags=["vigia", "recon-coverage"],
                       document_type="note", source="vigia") > PUBLISH_LIMIT:
        body = resumo_body({k: v[:40] for k, v in interesting.items()}, lead_rows[:30])
    written.insert(0, prepare(plan["program_id"], f"vigia-{run}-resumo", body, assets=assets,
                              tags=["vigia", "recon-coverage"], **{**common, "document_type": "note"}))
    return written


# ---------------------------------------------------------------- jobs

def job_directory(job):
    return bgjobs.job_directory(JOBS, job)


def submit(plan):
    validate(plan)
    identity()
    required_headers(plan["policy"]["required_headers_env"])
    job = uuid.uuid4().hex
    directory = job_directory(job)
    directory.mkdir(parents=True, mode=0o700)
    private_write(directory / "plan.json", json.dumps(plan, ensure_ascii=False))
    state = new_state(plan)
    state.update(status="queued", reason="awaiting_worker")
    private_write(directory / "result.json", json.dumps(state))
    try:
        bgjobs.spawn(Path(__file__), ["run", str(directory / "plan.json"), "--job", job], directory, job, ROOT)
    except OSError:
        state.update(status="failed", reason="worker_launch_failed")
        private_write(directory / "result.json", json.dumps(state))
        raise
    return job


def job_status(job):
    directory = job_directory(job)
    state = json.loads((directory / "result.json").read_text())
    finished = state["status"] in TERMINAL and state["publication"] in {"staged", "pending", "published"}
    worker = bgjobs.worker_state(directory, finished)
    hosts = state.get("hosts", {})
    return {"job_id": job, "status": state["status"], "reason": state.get("reason"), "stage": state.get("stage"),
            "publication": state["publication"], "worker": worker, "stale": worker == "dead",
            "cancel_requested": bgjobs.cancel_requested(directory),
            "progress": {"hosts": len(hosts), "classified": sum(1 for e in hosts.values() if "status" in e),
                         "requests": state.get("requests")},
            "summary": state.get("summary") or None, "result": str(directory / "result.json"),
            "human_review_required": True, "finished": finished}


def wait_job(job, seconds):
    if not 0 < seconds <= 300:
        raise ValueError("espera deve estar entre 1 e 300 segundos")
    deadline = time.monotonic() + seconds
    while True:
        result = job_status(job)
        if result["finished"] or result["stale"] or time.monotonic() >= deadline:
            return result
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))


def list_jobs():
    rows = []
    for job in bgjobs.list_jobs(JOBS):
        try:
            status = job_status(job)
        except (OSError, ValueError, KeyError):
            rows.append({"job_id": job, "status": "unreadable"})
            continue
        rows.append({k: status[k] for k in ("job_id", "status", "reason", "stage", "publication", "worker", "stale", "finished")}
                    | {"alive": (status["summary"] or {}).get("alive"), "dead": (status["summary"] or {}).get("dead")})
    return {"jobs": rows, "count": len(rows), "root": str(JOBS)}


@contextmanager
def event_log(path):
    with path.open("a", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        def log(event):
            output.write(json.dumps(event, ensure_ascii=False) + "\n")
            output.flush()
            os.fsync(output.fileno())
        yield log


def worker(plan, args):
    identity()  # Falhar antes do tráfego se a autoria de publicação não estiver configurada.
    run_dir = job_directory(args.job) if args.job else STATE_DIR / "runs" / uuid.uuid4().hex
    run_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    if args.job:
        with (run_dir / "started").open("x"):
            pass  # Um worker por job; status/wait jamais repetem tráfego.
    path = run_dir / "result.json"

    def save(state):
        if state["status"] in TERMINAL:
            state["publication"] = "preparing"
        private_write(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")

    state = json.loads(path.read_text()) if args.job else new_state(plan)
    if state["plan_sha256"] != digest(plan) or state["status"] not in {"queued", "running"}:
        raise ValueError("snapshot do job diverge da missão")
    state["publication"] = "preparing"
    try:
        baseline = load_baseline(plan["program_id"])
        with HiveClient() as client, event_log(run_dir / "events.jsonl") as log:
            # Recon anterior/negativos: dado não confiável, guardado só para o operador.
            history = client.call("hive_search", {"program_id": plan["program_id"], "query": "recon inventário hosts vivos mortos vigia"})
            private_write(run_dir / "history.json", json.dumps(history, ensure_ascii=False))
            cancelled = (lambda: bgjobs.cancel_requested(run_dir)) if args.job else None
            resolver = DohResolver() if plan["dns"]["resolver"] == "doh" else SystemResolver()
            state = execute(plan, gate=MindGate(client, plan), resolver=resolver, prober=Prober(), save=save, log=log,
                            state=state, cancelled=cancelled, baseline=baseline)
        if state["status"] in {"completed", "partial"}:
            update_baseline(plan["program_id"], state, baseline)
    except HiveError:
        state.update(status="blocked", reason="history_or_mind_unavailable", ended_at=now())
        save(state)
    except (OSError, ValueError, TypeError, KeyError):
        state.update(status="failed", reason="worker_preconditions_or_storage_failed", ended_at=now())
        save(state)
    state["publication"] = "preparing"
    save(state)
    try:
        notes = stage(plan, state)
        state["publication"] = "staged"
        private_write(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")
    except (OSError, ValueError):
        state["publication"] = "pending"
        private_write(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"status": state["status"], "publication": "pending", "result": str(path)}))
        return 2
    print(json.dumps({"status": state["status"], "reason": state["reason"], "summary": state["summary"],
                      "result": str(path), "notes": len(notes), "publication": "staged", "human_review_required": True}))
    return 0 if state["status"] == "completed" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "submit", "stage", "run"):
        sub.add_parser(command).add_argument("plan", type=Path)
    sub.choices["run"].add_argument("--job", help=argparse.SUPPRESS)
    sub.choices["stage"].add_argument("result", type=Path)
    for command in ("status", "wait", "cancel"):
        sub.add_parser(command).add_argument("job")
    sub.choices["wait"].add_argument("--seconds", type=int, default=30)
    sub.add_parser("jobs")
    targets = sub.add_parser("targets")
    targets.add_argument("result", type=Path)
    targets.add_argument("--level", choices=["medium", "full"], default="full")
    targets.add_argument("--rate", type=float, default=1.0)
    args = parser.parse_args(argv)
    try:
        if args.command == "jobs":
            print(json.dumps(list_jobs()))
            return 0
        if args.command == "targets":
            state = json.loads(args.result.read_text())
            if state.get("status") not in TERMINAL:
                raise ValueError("resultado do Vigia não terminou; alvos incompletos")
            result = handoff_targets(state, rate=args.rate, level=args.level)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result["alive_hosts"] else 1
        if args.command in {"status", "wait", "cancel"}:
            if args.command == "cancel":
                directory = job_directory(args.job)
                if not (directory / "result.json").exists():
                    raise ValueError("job inexistente")
                first = bgjobs.request_cancel(directory)
                result = {**job_status(args.job), "cancel_already_requested": not first}
            else:
                result = job_status(args.job) if args.command == "status" else wait_job(args.job, args.seconds)
            print(json.dumps(result))
            if result["stale"]:
                return 2
            return 0 if result["finished"] else 1
        plan = validate(json.loads(args.plan.read_text()))
        if args.command == "validate":
            print(json.dumps({"valid": True, "program_id": plan["program_id"], "max_hosts": plan["limits"]["max_hosts"],
                              "stages": [s for s in ("passive", "active_dns", "dns", "http") if plan[s]["enabled"]],
                              "extended_ports": plan["http"]["extended_ports"], "traffic_sent": False}))
            return 0
        if args.command == "submit":
            print(json.dumps({"job_id": submit(plan), "status": "queued", "background": True}))
            return 0
        if args.command == "stage":
            state = json.loads(args.result.read_text())
            if state["plan_sha256"] != digest(plan) or state["program_id"] != plan["program_id"] or state["status"] not in TERMINAL:
                raise ValueError("resultado não pertence à missão ou não terminou")
            notes = stage(plan, state)
            state["publication"] = "staged"
            private_write(args.result, json.dumps(state, ensure_ascii=False, indent=2))
            print(json.dumps({"publication": "staged", "notes": [str(n) for n in notes]}))
            return 0
        return worker(plan, args)
    except (OSError, ValueError, TypeError, KeyError, HiveError):
        print("Vigia: missão, autoria, headers ou Hive inválidos/indisponíveis; detalhes sensíveis omitidos.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
