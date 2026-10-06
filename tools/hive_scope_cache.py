#!/usr/bin/env python3
"""Recibos curtos de hive_get_context, isolados por programa e sessão.

O cache não aprova escopo. Apenas respostas do Hive para o ativo exato podem
liberar tráfego. Esquemas antigos são ignorados; não há aprovação por arquivo.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

from file_safety import atomic_write_text, locked_file

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CACHE_PATH = PROJECT_ROOT / ".hive" / "scope-cache.json"
SCHEMA_VERSION = 2
DEFAULT_TTL_HOURS = 0.25
MAX_TTL_HOURS = 1.0
PROGRAM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _now():
    return datetime.now(timezone.utc)


def _iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp sem fuso")
    return parsed


def _boundary():
    # Identifica a configuração do cliente sem ler/exportar seus tokens.
    values = [os.environ.get(k, "") for k in ("HIVE_MIND_URL", "HIVE_CENTER_URL")]
    return hashlib.sha256(json.dumps(values).encode()).hexdigest()


def _empty():
    return {"schema_version": SCHEMA_VERSION, "receipts": [], "boundary": _boundary()}


def _read_json(path):
    return json.load(sys.stdin) if path == "-" else json.loads(Path(path).read_text())


def _unwrap_context(value):
    if not isinstance(value, dict) or value.get("isError") or value.get("error"):
        raise ValueError("resposta Hive inválida/com erro")
    current = value
    for key in ("result", "structuredContent"):
        if isinstance(current.get(key), dict):
            current = current[key]
        if current.get("isError") or current.get("error"):
            raise ValueError("resposta Hive com erro")
    if {"program_id", "asset", "scope"} <= current.keys():
        return current
    for item in current.get("content", []):
        if isinstance(item, dict) and item.get("type") == "text":
            try:
                return _unwrap_context(json.loads(item["text"]))
            except (ValueError, KeyError, TypeError):
                continue
    raise ValueError("JSON não contém hive_get_context estruturado")


def _load_cache():
    try:
        data = json.loads(CACHE_PATH.read_text())
    except (OSError, ValueError):
        return _empty()
    if (not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION
            or data.get("boundary") != _boundary() or not isinstance(data.get("receipts"), list)):
        return _empty()
    if data.get("active_program") is not None and (
            not isinstance(data["active_program"], str) or not PROGRAM_RE.fullmatch(data["active_program"])
            or not isinstance(data.get("session_id"), str) or not re.fullmatch(r"[0-9a-f]{32}", data["session_id"])):
        return _empty()
    return data


def _save_cache(data):
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(CACHE_PATH.parent, 0o700)
    atomic_write_text(CACHE_PATH, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    os.chmod(CACHE_PATH, 0o600)


def _active_receipts(data, now=None):
    current = now or _now()
    active = []
    for receipt in data.get("receipts", []):
        try:
            if (isinstance(receipt, dict) and receipt.get("session_id") == data.get("session_id")
                    and _parse_time(receipt["recorded_at"]) <= current < _parse_time(receipt["expires_at"])):
                active.append(receipt)
        except (KeyError, TypeError, ValueError):
            continue
    return active


def _hostname(value):
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        pass
    parsed = urlsplit(value if "://" in value else "//" + value)
    return (parsed.hostname or "").lower()


def _host(value):
    if not value or not value.isascii() or value.endswith(".") or any(c in value for c in "/:@[] "):
        raise ValueError("host inválido; use ativo ASCII canônico do Hive")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in value.lower().split(".")) or len(value) > 253:
        raise ValueError("host inválido")
    return value.lower()


def _url(value):
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or any(ord(c) < 33 or c == "\\" for c in value)):
        raise ValueError("URL HTTP(S) válida sem credenciais necessária")
    hostname = parsed.hostname
    try:
        hostname = ipaddress.ip_address(hostname).compressed
    except ValueError:
        hostname = _host(hostname)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("porta inválida")
    path = parsed.path or "/"
    decoded = path
    for _ in range(3):
        if "\\" in decoded or any(part in {".", ".."} for part in decoded.split("/")):
            raise ValueError("caminho ambíguo; revalide ativo exato")
        decoded = unquote(decoded)
    return parsed.scheme, hostname, port, path.rstrip("/") or "/"


def normalize_asset(asset):
    if not isinstance(asset, dict) or not isinstance(asset.get("value"), str):
        raise ValueError("asset tipado inválido")
    kind, value = asset.get("type"), asset["value"]
    if kind == "host":
        value = _host(value)
    elif kind == "wildcard_domain":
        if not value.startswith("*."):
            raise ValueError("wildcard inválido")
        value = "*." + _host(value[2:])
    elif kind == "ip":
        value = ipaddress.ip_address(value).compressed
    elif kind == "cidr":
        value = str(ipaddress.ip_network(value, strict=True))
    elif kind == "url_prefix":
        parsed = urlsplit(value)
        if parsed.query or parsed.fragment:
            raise ValueError("asset URL sem query/fragmento necessário")
        scheme, host, port, path = _url(value)
        if ":" in host:
            host = "[" + host + "]"
        authority = host if port == (443 if scheme == "https" else 80) else f"{host}:{port}"
        value = f"{scheme}://{authority}{path}"
    else:
        raise ValueError("tipo de asset inválido")
    return {"type": kind, "value": value}


def record_context(raw, ttl_hours=DEFAULT_TTL_HOURS):
    if (isinstance(ttl_hours, bool) or not isinstance(ttl_hours, (int, float))
            or not math.isfinite(ttl_hours) or not 0 < ttl_hours <= MAX_TTL_HOURS):
        raise ValueError("TTL deve estar entre 0 e 1 hora")
    context = _unwrap_context(raw)
    program = context.get("program_id")
    if not isinstance(program, str) or not PROGRAM_RE.fullmatch(program):
        raise ValueError("program_id inválido")
    asset = normalize_asset(context.get("asset"))
    scope = context.get("scope")
    if not isinstance(scope, dict) or scope.get("status") not in {"authorized", "out_of_scope", "unknown"}:
        raise ValueError("scope inválido")
    if any(not isinstance(scope.get(k), bool) for k in ("confirmed", "action_allowed")):
        raise ValueError("flags de escopo devem ser booleanas")
    revision = scope.get("scope_revision")
    if scope["action_allowed"] and (not scope["confirmed"] or scope["status"] != "authorized"
                                    or not isinstance(revision, str) or revision in {"", "unapproved"}):
        raise ValueError("veredito inconsistente: autorização não confirmada")
    now = _now()
    with locked_file(CACHE_PATH):
        data = _load_cache()
        if data.get("active_program") != program:
            data = {**_empty(), "active_program": program, "session_id": uuid.uuid4().hex}
        receipts = [r for r in _active_receipts(data)
                    if r.get("program_id") == program and r.get("scope_revision") == revision
                    and r.get("asset") != asset]
        receipt = {"program_id": program, "asset": asset, "status": scope["status"],
                   "confirmed": scope["confirmed"], "action_allowed": scope["action_allowed"],
                   "scope_revision": revision, "matched_rules": scope.get("matched_rules", []),
                   "session_id": data["session_id"], "recorded_at": _iso(now),
                   "expires_at": _iso(now + timedelta(hours=ttl_hours))}
        data["receipts"] = receipts + [receipt]
        _save_cache(data)
    return receipt


def _asset_matches(asset, target):
    """Matcher de regras para negações; permissões nunca se expandem por ele."""
    try:
        asset = normalize_asset(asset)
        kind, value = asset["type"], asset["value"]
        host = _hostname(target)
        if kind == "host":
            return host == value
        if kind == "wildcard_domain":
            return host != value[2:] and host.endswith("." + value[2:])
        if kind == "url_prefix":
            prefix, candidate = _url(value), _url(target)
            return (prefix[:3] == candidate[:3] and (prefix[3] == candidate[3]
                    or candidate[3].startswith(prefix[3].rstrip("/") + "/")))
        if kind == "ip":
            return ipaddress.ip_address(host) == ipaddress.ip_address(value)
        if kind == "cidr":
            return ipaddress.ip_address(host) in ipaddress.ip_network(value)
    except (ValueError, TypeError):
        pass
    return False


def _exact_asset_matches(asset, target):
    try:
        if "://" in target:
            return asset.get("type") == "url_prefix" and _url(asset["value"]) == _url(target)
        if "/" in target:
            return False
        return asset.get("type") in {"host", "ip"} and _asset_matches(asset, target)
    except (KeyError, ValueError, TypeError):
        return False


def authorization_for(target, now=None, *, program_id=None):
    data = _load_cache()
    program = program_id or os.environ.get("EXCALIBULL_PROGRAM_ID") or data.get("active_program")
    if not program or program != data.get("active_program"):
        return None
    receipts = [r for r in _active_receipts(data, now) if r.get("program_id") == program]
    denied = [r for r in receipts if r.get("action_allowed") is not True
              and _asset_matches(r.get("asset", {}), target)]
    # Não liberar comando de host quando há exclusão por caminho que ele oculta.
    if "://" not in target:
        denied += [r for r in receipts if r.get("action_allowed") is not True
                   and r.get("asset", {}).get("type") == "url_prefix"
                   and _hostname(r["asset"]["value"]) == _hostname(target)]
    if denied:
        return denied[-1]
    allowed = [r for r in receipts if r.get("confirmed") is True and r.get("status") == "authorized"
               and r.get("action_allowed") is True and _exact_asset_matches(r.get("asset", {}), target)]
    return allowed[-1] if allowed else None


def invalidate():
    """Falha do serviço/auth exige contexto novo antes de mais tráfego."""
    with locked_file(CACHE_PATH):
        _save_cache(_empty())


def _is_loopback_host(host):
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def preflight(targets, *, program_id=None):
    results = []
    for target in dict.fromkeys(str(t) for t in targets):
        try:
            host = _hostname(target)
            if _is_loopback_host(host):
                results.append((target, True, "loopback"))
                continue
            receipt = authorization_for(target, program_id=program_id)
            ok = bool(receipt and receipt.get("action_allowed") is True)
            reason = "ok" if ok else "sem recibo vigente do programa/ativo exato"
        except (ValueError, TypeError):
            ok, reason = False, "ativo inválido"
        results.append((target, ok, reason))
    return results


def require_authorized(targets, tool_name="tool", *, program_id=None):
    problems = [(target, why) for target, ok, why in preflight(targets, program_id=program_id) if not ok]
    if problems:
        sys.stderr.write(f"BLOQUEADO (Hive fail-closed): {tool_name}: autorização ausente para {len(problems)} ativo(s).\n"
                         "Consulte hive_get_context com programa e ativo exato; registre a resposta estruturada.\n")
        raise SystemExit(2)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record", help="registra resposta de hive_get_context e seleciona o programa")
    rec.add_argument("json_file")
    rec.add_argument("--ttl-hours", type=float, default=DEFAULT_TTL_HOURS)
    check = sub.add_parser("check")
    check.add_argument("target")
    check.add_argument("--program")
    sub.add_parser("list")
    sub.add_parser("clear")
    args = parser.parse_args(argv)
    try:
        if args.command == "record":
            print(json.dumps(record_context(_read_json(args.json_file), args.ttl_hours), indent=2))
        elif args.command == "check":
            receipt = authorization_for(args.target, program_id=args.program)
            print(json.dumps(receipt or {"action_allowed": False, "reason": "no_live_hive_receipt"}, indent=2))
            return 0 if receipt and receipt["action_allowed"] else 1
        elif args.command == "list":
            print(json.dumps(_active_receipts(_load_cache()), indent=2))
        else:
            with locked_file(CACHE_PATH):
                _save_cache(_empty())
            print("cache de escopo Hive limpo")
    except (OSError, ValueError, TypeError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
