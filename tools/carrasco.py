#!/usr/bin/env python3
"""Carrasco: executor local de planos de hipótese (stdlib), com registro de perfis.

Cada perfil declara seu schema, seus oráculos (sequência de passos e controles) e
seus vereditos. Perfis atuais (somente leitura, GET): `cross-account-read` (IDOR de
leitura entre duas contas) e `unauthenticated-read` (objeto privado legível sem
autenticação). Perfis de escrita exigem política de efeitos, leitura de volta e
limpeza antes de existirem; não há método não-GET neste transporte.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid

from hive_documents import identifier, identity, now
from hive_gateway import HiveClient, HiveError
from hive_outbox import prepare, private_write
from hive_scope_cache import normalize_asset
from netcommon import RateLimiter

ROOT = Path(__file__).resolve().parents[1]
DENIED = {401, 403, 404}
COMMON_KEYS = {"version", "id", "program_id", "profile", "hypothesis", "evidence_refs", "policy", "limits"}


class Blocked(ValueError):
    pass


class CleanupError(Exception):
    """A restauração obrigatória do objeto não pôde ser confirmada; intervenção humana."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("campos ausentes/desconhecidos no plano")


def env_name(name):
    if not isinstance(name, str) or not re.fullmatch(r"CARRASCO_[A-Z][A-Z0-9_]{0,80}", name):
        raise ValueError("alias de ambiente CARRASCO_* necessário")


def _validate_assertion(plan):
    keys(plan["assertion"], {"json_pointer"})
    pointer = plan["assertion"]["json_pointer"]
    if not isinstance(pointer, str) or not pointer.startswith("/") or len(pointer) > 256 or re.search(r"~(?![01])", pointer):
        raise ValueError("JSON Pointer RFC 6901 necessário")


def _validate_account(account):
    """Conta de teste própria: URL HTTPS sem query/credencial, alias de ambiente e marcador sintético."""
    keys(account, {"url", "headers_env", "marker"})
    parsed = urlsplit(account["url"])
    # Queries podem conter tokens; o piloto exige identificadores no path.
    if parsed.scheme != "https" or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("URLs HTTPS sem query, fragmento ou credenciais necessárias")
    normalize_asset({"type": "url_prefix", "value": account["url"]})
    env_name(account["headers_env"])
    if not isinstance(account["marker"], str) or not re.fullmatch(r"carrasco-[a-zA-Z0-9_-]{16,80}", account["marker"]):
        raise ValueError("use marcador sintético carrasco- seguido de 16 a 80 caracteres")
    return parsed


def _marker(value):
    return isinstance(value, str) and bool(re.fullmatch(r"carrasco-[a-zA-Z0-9_-]{16,80}", value))


def _validate_write(spec, pointer, expected_marker, *, with_marker):
    """Corpo de escrita autorado e revisado pelo operador: JSON sintético, limitado,
    que posiciona exatamente o marcador esperado no JSON Pointer. O executor só envia
    o que consegue verificar; nunca inventa o corpo. Método restrito a PATCH/PUT."""
    keys(spec, {"method", "body", "marker"} if with_marker else {"method", "body"})
    if spec["method"] not in {"PATCH", "PUT"}:
        raise ValueError("método de escrita deve ser PATCH ou PUT")
    if not isinstance(spec["body"], dict):
        raise ValueError("corpo de escrita deve ser objeto JSON")
    try:
        payload = json.dumps(spec["body"], ensure_ascii=False)
    except (TypeError, ValueError):
        raise ValueError("corpo de escrita deve ser JSON serializável")
    if len(payload.encode()) > 4096:
        raise ValueError("corpo de escrita excede 4096 bytes")
    if with_marker and not _marker(spec["marker"]):
        raise ValueError("marcador de escrita sintético necessário")
    try:
        placed = pointer_value(payload.encode(), pointer)
    except (ValueError, KeyError, TypeError, IndexError, UnicodeError, RecursionError):
        raise ValueError("corpo de escrita deve conter o marcador no JSON Pointer")
    if placed != expected_marker:
        raise ValueError("corpo de escrita deve posicionar exatamente o marcador esperado")


class CrossAccountRead:
    """IDOR de leitura: a sessão A lê o marcador privado do objeto da conta B."""
    name = "cross-account-read"
    VERSION = 1
    REQUESTS = 6
    SUBJECT_KEYS = {"accounts", "assertion"}

    def validate_subject(self, plan):
        accounts = plan["accounts"]
        keys(accounts, {"a", "b"})
        origins = set()
        for account in accounts.values():
            parsed = _validate_account(account)
            origins.add((parsed.hostname, parsed.port or 443))
        if (len(origins) != 1 or accounts["a"]["url"] == accounts["b"]["url"]
                or accounts["a"]["marker"] == accounts["b"]["marker"]
                or accounts["a"]["headers_env"] == accounts["b"]["headers_env"]):
            raise ValueError("contas exigem URLs, marcadores e aliases diferentes, no mesmo origin")
        _validate_assertion(plan)

    def credentials(self, plan):
        return {k: plan["accounts"][k]["headers_env"] for k in ("a", "b")}

    def check_credentials(self, credentials):
        if credentials["a"] == credentials["b"]:
            raise ValueError("credenciais das contas devem ser diferentes")

    def objects(self, plan):
        return {k: plan["accounts"][k] for k in ("a", "b")}

    def asset_urls(self, plan):
        return [plan["accounts"][k]["url"] for k in ("a", "b")]

    def run(self, plan, engine):
        observe, state = engine.observe, engine.state
        if observe("control_a", "a", "a") != (200, True) or observe("control_b", "b", "b") != (200, True):
            state.update(status="inconclusive", reason="owner_control_failed")
        elif observe("anonymous_b", "anonymous", "b")[0] not in DENIED:
            state.update(status="inconclusive", reason="privacy_control_failed")
        else:
            first = observe("cross_a_b", "a", "b")
            repeat = observe("repeat_a_b", "a", "b")
            readback = observe("readback_b", "b", "b")
            if readback != (200, True):
                state.update(status="inconclusive", reason="readback_failed")
            elif first == repeat == (200, True):
                state.update(status="confirmed", reason="private_test_marker_read_cross_account_twice")
            elif first[0] in {403, 404} and repeat[0] in {403, 404}:
                state.update(status="refuted", reason="cross_account_denied_in_tested_conditions")
            else:
                state.update(status="inconclusive", reason="ambiguous_cross_account_response")


class UnauthenticatedRead:
    """Objeto privado próprio legível sem credencial alguma (autenticação ausente)."""
    name = "unauthenticated-read"
    VERSION = 1
    REQUESTS = 4
    SUBJECT_KEYS = {"owner", "assertion"}

    def validate_subject(self, plan):
        _validate_account(plan["owner"])
        _validate_assertion(plan)

    def credentials(self, plan):
        return {"owner": plan["owner"]["headers_env"]}

    def check_credentials(self, credentials):
        pass  # Uma única conta própria; não há par para comparar.

    def objects(self, plan):
        return {"owner": plan["owner"]}

    def asset_urls(self, plan):
        return [plan["owner"]["url"]]

    def run(self, plan, engine):
        observe, state = engine.observe, engine.state
        if observe("control_owner", "owner", "owner") != (200, True):
            state.update(status="inconclusive", reason="owner_control_failed")
        else:
            first = observe("anonymous_1", "anonymous", "owner")
            repeat = observe("anonymous_2", "anonymous", "owner")
            readback = observe("readback_owner", "owner", "owner")
            if readback != (200, True):
                state.update(status="inconclusive", reason="readback_failed")
            elif first == repeat == (200, True):
                state.update(status="confirmed", reason="private_object_readable_unauthenticated_twice")
            elif first[0] in DENIED and repeat[0] in DENIED:
                state.update(status="refuted", reason="unauthenticated_denied_in_tested_conditions")
            else:
                state.update(status="inconclusive", reason="ambiguous_unauthenticated_response")


class CrossAccountWrite:
    """IDOR de escrita: a conta A altera o objeto privado de B, com restauração obrigatória.

    Fronteira de escrita: exige política de efeitos revisada, leitura de volta e limpeza.
    O corpo de escrita e o de restauração são autorados/revisados pelo operador; o worker
    valida que posicionam exatamente os marcadores sintéticos e envia apenas isso. A limpeza
    (restaurar o marcador original de B) é obrigatória e roda mesmo em erro/bloqueio: se não
    for confirmada, o resultado é `failed` com `manual_restoration_required`.
    """
    name = "cross-account-write"
    VERSION = 1
    REQUESTS = 5            # controle, escrita, leitura de volta, limpeza, verificação
    ATTACK_REQUESTS = 3     # controle/escrita/leitura; limpeza+verificação reservadas e obrigatórias
    SUBJECT_KEYS = {"target", "attacker", "write", "cleanup", "assertion"}
    POLICY_EXTRA = {"effects"}

    def validate_subject(self, plan):
        target = plan["target"]
        _validate_account(target)
        attacker = plan["attacker"]
        keys(attacker, {"headers_env"})
        env_name(attacker["headers_env"])
        if attacker["headers_env"] == target["headers_env"]:
            raise ValueError("atacante e dono exigem aliases de credenciais diferentes")
        _validate_assertion(plan)
        pointer = plan["assertion"]["json_pointer"]
        write = plan["write"]
        _validate_write(write, pointer, write.get("marker"), with_marker=True)
        if write["marker"] == target["marker"]:
            raise ValueError("marcador de escrita deve diferir do marcador original")
        _validate_write(plan["cleanup"], pointer, target["marker"], with_marker=False)

    def validate_effects(self, effects):
        keys(effects, {"reversible", "idempotent_write", "own_objects_only", "no_third_party_data"})
        if any(effects[k] is not True for k in effects):
            raise ValueError("política de efeitos exige reversível, idempotente, objetos próprios e sem dados de terceiros")

    def credentials(self, plan):
        return {"owner": plan["target"]["headers_env"], "attacker": plan["attacker"]["headers_env"]}

    def check_credentials(self, credentials):
        if credentials["owner"] == credentials["attacker"]:
            raise ValueError("credenciais de dono e atacante devem ser diferentes")

    def objects(self, plan):
        return {"target": {"url": plan["target"]["url"], "marker": plan["target"]["marker"]}}

    def asset_urls(self, plan):
        return [plan["target"]["url"]]

    def run(self, plan, engine):
        state = engine.state
        original, write = plan["target"]["marker"], plan["write"]
        attempted = False
        try:
            if engine.observe("control_owner", "owner", "target") != (200, True):
                state.update(status="inconclusive", reason="owner_control_failed")
                return
            attempted = True
            write_status = engine.observe_write("attempt_write", "attacker", "target", write["method"], write["body"])
            _, after_match = engine.observe("readback_after", "owner", "target", expect_marker=write["marker"])
            if after_match and write_status in {200, 201, 202, 204}:
                state.update(status="confirmed", reason="cross_account_write_took_effect")
            elif write_status in DENIED and not after_match:
                state.update(status="refuted", reason="cross_account_write_denied_object_intact")
            else:
                state.update(status="inconclusive", reason="ambiguous_cross_account_write")
        finally:
            if attempted:
                state["attack_status"] = state.get("status")
                state["cleanup"] = "pending"
                engine.restore("target", "owner", plan["cleanup"]["method"], plan["cleanup"]["body"], original)
                state["cleanup"] = "restored"


PROFILES = {profile.name: profile for profile in (CrossAccountRead(), UnauthenticatedRead(), CrossAccountWrite())}


def validate(plan):
    if not isinstance(plan, dict) or plan.get("profile") not in PROFILES:
        raise ValueError("versão/perfil não suportado")
    profile = PROFILES[plan["profile"]]
    keys(plan, COMMON_KEYS | profile.SUBJECT_KEYS)
    if type(plan["version"]) is not int or plan["version"] != profile.VERSION:
        raise ValueError("versão/perfil não suportado")
    identifier(plan["id"])
    identifier(plan["program_id"])
    if not isinstance(plan["evidence_refs"], list) or not 1 <= len(plan["evidence_refs"]) <= 20:
        raise ValueError("informe 1 a 20 aliases de evidência")
    for ref in plan["evidence_refs"]:
        identifier(ref)
    if not isinstance(plan["hypothesis"], str) or not 1 <= len(plan["hypothesis"]) <= 1000:
        raise ValueError("hipótese obrigatória, até 1000 caracteres")
    policy = plan["policy"]
    keys(policy, {"reviewed", "automation_allowed", "owned_test_accounts", "private_objects", "scope_revision", "required_headers_env"} | getattr(profile, "POLICY_EXTRA", set()))
    if any(policy[k] is not True for k in ("reviewed", "automation_allowed", "owned_test_accounts", "private_objects")):
        raise ValueError("revise política, automação, contas próprias e objetos privados")
    if not isinstance(policy["scope_revision"], str) or not policy["scope_revision"] or policy["scope_revision"] == "unapproved":
        raise ValueError("revisão aprovada do Mind necessária")
    if "effects" in policy:  # perfis de escrita exigem política de efeitos revisada
        profile.validate_effects(policy["effects"])
    env_name(policy["required_headers_env"])
    limits = plan["limits"]
    keys(limits, {"requests", "seconds", "timeout", "rate", "response_bytes"})
    for name, lo, hi in (("requests", profile.REQUESTS, profile.REQUESTS), ("seconds", 1, 300), ("timeout", 1, 30), ("response_bytes", 1, 1048576)):
        if type(limits[name]) is not int or not lo <= limits[name] <= hi:
            raise ValueError("limite inteiro inválido: " + name)
    rate = limits["rate"]
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or not 0.1 <= rate <= 2:
        raise ValueError("rate deve estar entre 0.1 e 2 req/s, respeitando o programa")
    profile.validate_subject(plan)
    return plan


def headers_from_env(name, *, authenticated):
    value = json.loads(os.environ.get(name, "{}"))
    if not isinstance(value, dict):
        raise ValueError("headers de ambiente devem ser objeto JSON")
    normalized = {}
    for key, item in value.items():
        if (not isinstance(key, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                or not isinstance(item, str) or any(ord(c) < 32 or ord(c) > 126 for c in item)
                or key.lower() in {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization"}
                or key.lower() in normalized):
            raise ValueError("header inválido")
        normalized[key.lower()] = item
    has_auth = any(normalized.get(k) for k in ("authorization", "cookie"))
    if has_auth != authenticated:
        raise ValueError("credencial ausente na conta ou presente nos headers compartilhados")
    return normalized


def pointer_value(body, pointer):
    value = json.loads(body)
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", token):
                raise ValueError("índice inválido")
            value = value[int(token)]
        else:
            value = value[token]
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Transport:
    """Sem proxy herdado, cookies persistidos, redirect ou retry implícito."""
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def _drain(self, response, timeout, max_bytes):
        with response:
            chunks, size = [], 0
            deadline = time.monotonic() + timeout
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("response_timeout")
                chunk = response.read1(min(65536, max_bytes + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError("response_limit")
                chunks.append(chunk)
            return response.code, b"".join(chunks)

    def get(self, url, headers, timeout, max_bytes):
        request = urllib.request.Request(url, headers={**headers, "Accept": "application/json", "Accept-Encoding": "identity"}, method="GET")
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        return self._drain(response, timeout, max_bytes)

    def send(self, url, headers, method, body, timeout, max_bytes):
        """Escrita restrita (PATCH/PUT) com corpo JSON sintético; mesmo opener sem redirect/proxy/cookie."""
        if method not in {"PATCH", "PUT"}:
            raise ValueError("método de escrita inválido")
        request = urllib.request.Request(
            url, data=body, method=method,
            headers={**headers, "Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity"})
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        return self._drain(response, timeout, max_bytes)


class MindGate:
    def __init__(self, client, plan):
        self.client, self.plan = client, plan

    def check(self, url):
        asset = {"type": "url_prefix", "value": url}
        result = self.client.context(self.plan["program_id"], asset,
                                     "Carrasco: conferir escopo para GET automatizado de objeto próprio de teste")
        scope = result.get("scope", {})
        if (scope.get("confirmed") is not True or scope.get("status") != "authorized"
                or scope.get("action_allowed") is not True
                or scope.get("scope_revision") != self.plan["policy"]["scope_revision"]):
            raise Blocked("scope_denied_or_changed")
        return scope["scope_revision"]


def new_state(plan):
    return {"version": 1, "run_id": uuid.uuid4().hex, "program_id": plan["program_id"],
            "hypothesis_id": plan["id"], "profile": plan["profile"], "plan_sha256": digest(plan), "started_at": now(),
            "status": "running", "reason": "in_progress", "observations": [],
            "evidence_refs": plan["evidence_refs"],
            "publication": "pending", "human_review_required": True, "llm_calls": 0}


class Engine:
    """Oráculo compartilhado: uma observação = escopo ao vivo + GET + match de marcador.

    `observe` jamais repete tráfego por conta própria; o perfil decide a sequência
    de passos e os vereditos. Orçamento, rate e gate do Mind são checados aqui.
    """
    def __init__(self, plan, gate, transport, save, common, credentials, objects, limiter, limits, started, state, attack_requests):
        self.plan, self.gate, self.transport, self.save = plan, gate, transport, save
        self.common, self.credentials, self.objects = common, credentials, objects
        self.limiter, self.limits, self.started, self.state = limiter, limits, started, state
        self.attack_requests = attack_requests

    def _budget(self):
        # Orçamento de ataque: limpeza/verificação obrigatórias não passam por aqui.
        if len(self.state["observations"]) >= self.attack_requests or time.monotonic() - self.started >= self.limits["seconds"]:
            raise Blocked("budget_exhausted")

    def _headers(self, actor):
        return {**self.common, **self.credentials.get(actor, {})}

    def observe(self, label, actor, obj_key, expect_marker=None):
        self.limiter.wait()
        self._budget()
        limits = self.limits
        target = self.objects[obj_key]
        revision = self.gate.check(target["url"])
        remaining = limits["seconds"] - (time.monotonic() - self.started)
        if remaining <= 0:
            raise Blocked("budget_exhausted")
        event = {"step": label, "actor": actor, "object": obj_key, "at": now(),
                 "scope_revision": revision, "state": "attempted"}
        self.state["observations"].append(event)
        self.save(self.state)
        status, body = self.transport.get(target["url"], self._headers(actor),
                                          min(limits["timeout"], remaining), limits["response_bytes"])
        expected = target["marker"] if expect_marker is None else expect_marker
        match = False
        try:
            match = pointer_value(body, self.plan["assertion"]["json_pointer"]) == expected
        except (ValueError, KeyError, TypeError, IndexError, UnicodeError, RecursionError):
            pass
        event.update(state="received", http_status=status, marker_match=match,
                     response_bytes=len(body), response_sha256=hashlib.sha256(body).hexdigest())
        self.save(self.state)
        if time.monotonic() - self.started > limits["seconds"]:
            raise Blocked("budget_exhausted")
        if status == 429 or status >= 500:
            raise Blocked("target_unavailable_or_rate_limited")
        return status, match

    def observe_write(self, label, actor, obj_key, method, body_obj):
        self.limiter.wait()
        self._budget()
        limits = self.limits
        target = self.objects[obj_key]
        revision = self.gate.check(target["url"])
        remaining = limits["seconds"] - (time.monotonic() - self.started)
        if remaining <= 0:
            raise Blocked("budget_exhausted")
        event = {"step": label, "actor": actor, "object": obj_key, "method": method, "at": now(),
                 "scope_revision": revision, "state": "attempted"}
        self.state["observations"].append(event)
        self.save(self.state)
        status, body = self.transport.send(target["url"], self._headers(actor), method,
                                           json.dumps(body_obj).encode(), min(limits["timeout"], remaining), limits["response_bytes"])
        event.update(state="received", http_status=status, response_bytes=len(body),
                     response_sha256=hashlib.sha256(body).hexdigest())
        self.save(self.state)
        if time.monotonic() - self.started > limits["seconds"]:
            raise Blocked("budget_exhausted")
        if status == 429 or status >= 500:
            raise Blocked("target_unavailable_or_rate_limited")
        return status

    def restore(self, obj_key, actor, method, body_obj, original_marker):
        """Restauração obrigatória: escrita do dono de volta ao marcador original + verificação.

        Fora do orçamento de ataque (restaurar é mandatório), mas ainda sob rate e gate do
        Mind. Qualquer falha vira CleanupError → o experimento é `failed` e exige intervenção.
        """
        target, limits = self.objects[obj_key], self.limits
        self.limiter.wait()
        try:
            revision = self.gate.check(target["url"])
        except (Blocked, HiveError) as exc:
            raise CleanupError("cleanup_blocked_scope") from exc
        event = {"step": "cleanup", "actor": actor, "object": obj_key, "method": method, "at": now(),
                 "scope_revision": revision, "state": "attempted", "mandatory": True}
        self.state["observations"].append(event)
        self.save(self.state)
        try:
            status, _ = self.transport.send(target["url"], self._headers(actor), method,
                                            json.dumps(body_obj).encode(), limits["timeout"], limits["response_bytes"])
        except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException, TimeoutError) as exc:
            raise CleanupError("cleanup_write_failed") from exc
        event.update(state="received", http_status=status)
        self.save(self.state)
        if status >= 400:
            raise CleanupError("cleanup_write_rejected")
        self.limiter.wait()
        try:
            revision = self.gate.check(target["url"])
        except (Blocked, HiveError) as exc:
            raise CleanupError("cleanup_unverified_scope") from exc
        verify = {"step": "verify_cleanup", "actor": actor, "object": obj_key, "at": now(),
                  "scope_revision": revision, "state": "attempted", "mandatory": True}
        self.state["observations"].append(verify)
        self.save(self.state)
        try:
            status, body = self.transport.get(target["url"], self._headers(actor), limits["timeout"], limits["response_bytes"])
            ok = status == 200 and pointer_value(body, self.plan["assertion"]["json_pointer"]) == original_marker
        except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException, TimeoutError, KeyError, IndexError, UnicodeError, RecursionError) as exc:
            raise CleanupError("cleanup_unverified") from exc
        verify.update(state="received", http_status=status, marker_match=ok)
        self.save(self.state)
        if not ok:
            raise CleanupError("cleanup_unverified")


def execute(plan, gate, transport, save):
    """Dependências injetáveis somente pela API Python para testes offline."""
    validate(plan)
    profile = PROFILES[plan["profile"]]
    common = headers_from_env(plan["policy"]["required_headers_env"], authenticated=False)
    credentials = {key: headers_from_env(env, authenticated=True) for key, env in profile.credentials(plan).items()}
    if any(set(common) & set(h) for h in credentials.values()) or set(common) & {"accept", "accept-encoding"}:
        raise ValueError("headers obrigatórios não podem ser sobrescritos")
    profile.check_credentials(credentials)
    limits = plan["limits"]
    started = time.monotonic()
    limiter = RateLimiter(limits["rate"])
    state = new_state(plan)
    save(state)
    attack_requests = getattr(profile, "ATTACK_REQUESTS", profile.REQUESTS)
    engine = Engine(plan, gate, transport, save, common, credentials, profile.objects(plan), limiter, limits, started, state, attack_requests)
    try:
        profile.run(plan, engine)
    except CleanupError as exc:
        # Restauração não confirmada: o objeto pode estar modificado. Resultado mais grave que o veredito.
        state.update(status="failed", reason=str(exc), manual_restoration_required=True)
    except Blocked as exc:
        state.update(status="blocked", reason=str(exc))
    except HiveError:
        state.update(status="blocked", reason="scope_service_unavailable")
    except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
        state.update(status="inconclusive", reason="transport_or_response_failure")
    state.update(ended_at=now(), elapsed_seconds=round(time.monotonic() - started, 3))
    save(state)
    return state


def stage(plan, state):
    profile = PROFILES[plan["profile"]]
    mapping = {"confirmed": "confirmed", "refuted": "discarded", "blocked": "inconclusive", "inconclusive": "inconclusive", "failed": "inconclusive"}
    # Somente aliases/metadados calculados: hipótese, URLs, headers, marcadores e bodies não entram na nota.
    body = "Carrasco: experimento local; revisão humana de elegibilidade/impacto pendente.\n\n" + json.dumps(state, ensure_ascii=False, indent=2)
    return prepare(plan["program_id"], "carrasco-" + state["run_id"], body,
                   assets=profile.asset_urls(plan), source="carrasco",
                   result=mapping[state["status"]], tags=["carrasco"])


JOBS = ROOT / ".hive" / "carrasco" / "jobs"
TERMINAL = {"confirmed", "refuted", "inconclusive", "blocked", "failed"}


def job_directory(job):
    if not isinstance(job, str) or not re.fullmatch(r"[a-f0-9]{32}", job):
        raise ValueError("ID de job inválido")
    return JOBS / job


def submit(plan):
    validate(plan)
    identity()
    profile = PROFILES[plan["profile"]]
    # Credenciais ficam somente no ambiente herdado; nunca no snapshot do plano.
    headers_from_env(plan["policy"]["required_headers_env"], authenticated=False)
    for env in profile.credentials(plan).values():
        headers_from_env(env, authenticated=True)
    job = uuid.uuid4().hex
    directory = job_directory(job)
    directory.mkdir(parents=True, mode=0o700)
    private_write(directory / "plan.json", json.dumps(plan, ensure_ascii=False))
    state = new_state(plan)
    state.update(status="queued", reason="awaiting_worker")
    private_write(directory / "result.json", json.dumps(state))
    try:
        with (directory / "worker.log").open("wb") as output:
            os.chmod(directory / "worker.log", 0o600)
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "run", str(directory / "plan.json"),
                                        "--job", job], stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                       cwd=ROOT, start_new_session=True)
        private_write(directory / "job.json", json.dumps({"job_id": job, "pid": process.pid, "created_at": now()}))
    except OSError:
        state.update(status="failed", reason="worker_launch_failed")
        private_write(directory / "result.json", json.dumps(state))
        raise
    return job


def job_status(job):
    directory = job_directory(job)
    state = json.loads((directory / "result.json").read_text())
    # Status descreve o journal; um processo interrompido pode deixar running.
    return {"job_id": job, "status": state["status"], "publication": state["publication"],
            "result": str(directory / "result.json"), "human_review_required": True,
            "finished": state["status"] in TERMINAL and state["publication"] in {"staged", "pending", "published"}}


def wait_job(job, seconds):
    if not 0 < seconds <= 300:
        raise ValueError("espera deve estar entre 1 e 300 segundos")
    deadline = time.monotonic() + seconds
    while True:
        result = job_status(job)
        if result["finished"] or time.monotonic() >= deadline:
            return result
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "submit", "stage", "run"):
        sub.add_parser(command).add_argument("plan", type=Path)
    sub.choices["run"].add_argument("--job", help=argparse.SUPPRESS)
    sub.choices["stage"].add_argument("result", type=Path)
    for command in ("status", "wait"):
        sub.add_parser(command).add_argument("job")
    sub.choices["wait"].add_argument("--seconds", type=int, default=30)
    args = parser.parse_args(argv)
    try:
        if args.command in {"status", "wait"}:
            result = job_status(args.job) if args.command == "status" else wait_job(args.job, args.seconds)
            print(json.dumps(result))
            return 0 if result["finished"] else 1
        plan = validate(json.loads(args.plan.read_text()))
        if args.command == "validate":
            print(json.dumps({"valid": True, "profile": plan["profile"], "requests_max": PROFILES[plan["profile"]].REQUESTS, "traffic_sent": False}))
            return 0
        if args.command == "submit":
            print(json.dumps({"job_id": submit(plan), "status": "queued", "background": True}))
            return 0
        if args.command == "stage":
            state = json.loads(args.result.read_text())
            if state["plan_sha256"] != digest(plan) or state["program_id"] != plan["program_id"] or state["status"] not in TERMINAL:
                raise ValueError("resultado não pertence ao plano ou não terminou")
            contribution = stage(plan, state)
            state["publication"] = "staged"
            private_write(args.result, json.dumps(state, ensure_ascii=False, indent=2))
            print(json.dumps({"publication": "staged", "contribution": str(contribution)}))
            return 0
        identity()  # Falhar antes do tráfego se a autoria de publicação não estiver configurada.
        run_dir = job_directory(args.job) if args.job else ROOT / ".hive" / "carrasco" / uuid.uuid4().hex
        run_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        if args.job:
            with (run_dir / "started").open("x"):
                pass  # Um worker por job; consultas/espera jamais repetem tráfego.
        path = run_dir / "result.json"
        def save(state):
            if state["status"] in TERMINAL:
                state["publication"] = "preparing"
            private_write(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")
        state = new_state(plan)
        state["publication"] = "preparing"
        save(state)
        try:
            with HiveClient() as client:
                # Histórico é dado não confiável; ausência na busca não significa teste inédito.
                history = client.call("hive_search", {"program_id": plan["program_id"], "query": plan["hypothesis"]})
                private_write(run_dir / "history.json", json.dumps(history, ensure_ascii=False))
                state = execute(plan, MindGate(client, plan), Transport(), save)
        except HiveError:
            state.update(status="blocked", reason="history_or_mind_unavailable", ended_at=now())
            save(state)
        except (OSError, ValueError, TypeError, KeyError):
            state.update(status="failed", reason="worker_preconditions_or_storage_failed", ended_at=now())
            save(state)
        # Só liberar wait após tentativa de staging: resultado de teste e entrega têm estados próprios.
        state["publication"] = "preparing"
        save(state)
        try:
            contribution = stage(plan, state)
            state["publication"] = "staged"
            private_write(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")
        except (OSError, ValueError):
            state["publication"] = "pending"
            private_write(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")
            print(json.dumps({"status": state["status"], "publication": "pending", "result": str(path)}))
            return 2
        print(json.dumps({"status": state["status"], "result": str(path), "contribution": str(contribution),
                          "publication": "staged", "human_review_required": True}))
        return 0 if state["status"] in {"confirmed", "refuted"} else 1
    except (OSError, ValueError, TypeError, KeyError, HiveError):
        print("Carrasco: plano, credenciais, autoria ou Hive inválidos/indisponíveis; detalhes sensíveis omitidos.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
