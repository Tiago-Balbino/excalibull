#!/usr/bin/env python3
"""Cache local de vereditos emitidos por ``hive_get_context``.

O cache nao cria autorizacao. Ele apenas materializa, por poucas horas, o
veredito estruturado retornado pelo Hive para que o hook Bash consiga operar
em modo fail-closed sem abrir uma conexao MCP a cada comando.

Uso:
    python3 tools/hive_scope_cache.py record /tmp/hive-context.json
    python3 tools/hive_scope_cache.py check api.example.com
    python3 tools/hive_scope_cache.py list
    python3 tools/hive_scope_cache.py clear
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CACHE_PATH = PROJECT_ROOT / ".hive" / "scope-cache.json"
SCHEMA_VERSION = 1
DEFAULT_TTL_HOURS = 8.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _read_json(path: str) -> object:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _unwrap_context(value: object) -> dict:
    """Aceita structuredContent, resultado MCP ou o JSON estruturado direto."""
    if not isinstance(value, dict):
        raise ValueError("a resposta do Hive deve ser um objeto JSON")
    current = value
    for key in ("result", "structuredContent"):
        nested = current.get(key)
        if isinstance(nested, dict):
            current = nested
    if "program_id" in current and "asset" in current and "scope" in current:
        return current
    content = current.get("content")
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict) or item.get("type") != "text":
                continue
            try:
                decoded = json.loads(item.get("text", ""))
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(decoded, dict) and {"program_id", "asset", "scope"} <= decoded.keys():
                return decoded
    raise ValueError("JSON nao contem uma resposta estruturada de hive_get_context")


def _load_cache() -> dict:
    if not CACHE_PATH.exists():
        return {"schema_version": SCHEMA_VERSION, "receipts": []}
    try:
        data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": SCHEMA_VERSION, "receipts": []}
    if data.get("schema_version") != SCHEMA_VERSION or not isinstance(data.get("receipts"), list):
        return {"schema_version": SCHEMA_VERSION, "receipts": []}
    return data


def _save_cache(data: dict) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CACHE_PATH)


def _active_receipts(data: dict, now: datetime | None = None) -> list[dict]:
    now = now or _now()
    active: list[dict] = []
    for receipt in data.get("receipts", []):
        try:
            if _parse_time(receipt["expires_at"]) > now:
                active.append(receipt)
        except (KeyError, TypeError, ValueError):
            continue
    return active


def record_context(raw: object, ttl_hours: float = DEFAULT_TTL_HOURS) -> dict:
    context = _unwrap_context(raw)
    program_id = context.get("program_id")
    asset = context.get("asset")
    scope = context.get("scope")
    if not isinstance(program_id, str) or not program_id:
        raise ValueError("program_id ausente")
    if not isinstance(asset, dict) or asset.get("type") not in {
        "host", "wildcard_domain", "ip", "cidr", "url_prefix"
    } or not isinstance(asset.get("value"), str):
        raise ValueError("asset tipado ausente ou invalido")
    if not isinstance(scope, dict):
        raise ValueError("scope ausente")

    receipt = {
        "program_id": program_id,
        "asset": {"type": asset["type"], "value": asset["value"]},
        "status": scope.get("status"),
        "confirmed": scope.get("confirmed") is True,
        "action_allowed": scope.get("action_allowed") is True,
        "scope_revision": scope.get("scope_revision"),
        "matched_rules": scope.get("matched_rules", []),
        "recorded_at": _iso(_now()),
        "expires_at": _iso(_now() + timedelta(hours=ttl_hours)),
    }
    if receipt["action_allowed"] and (
        not receipt["confirmed"]
        or receipt["status"] != "authorized"
        or not isinstance(receipt["scope_revision"], str)
        or not receipt["scope_revision"]
    ):
        raise ValueError("veredito inconsistente: action_allowed sem escopo autorizado confirmado")

    data = _load_cache()
    receipts = _active_receipts(data)
    receipts = [
        item for item in receipts
        if not (item.get("program_id") == program_id and item.get("asset") == receipt["asset"])
    ]
    receipts.append(receipt)
    data = {"schema_version": SCHEMA_VERSION, "receipts": receipts}
    _save_cache(data)
    return receipt


def _hostname(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or value.split("/", 1)[0].split(":", 1)[0]).rstrip(".").lower()


def _asset_matches(asset: dict, target: str) -> bool:
    kind = asset.get("type")
    value = str(asset.get("value", "")).strip()
    host = _hostname(target)
    if kind == "host":
        return host == _hostname(value)
    if kind == "wildcard_domain":
        base = _hostname(value[2:] if value.startswith("*.") else value)
        return host == base or host.endswith("." + base)
    if kind == "url_prefix":
        return target.startswith(value)
    if kind == "ip":
        return host == value
    if kind == "cidr":
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
    return False


def authorization_for(target: str, now: datetime | None = None) -> dict | None:
    matches = [
        receipt for receipt in _active_receipts(_load_cache(), now)
        if _asset_matches(receipt.get("asset", {}), target)
    ]
    if not matches:
        return None
    # Uma negacao explicita ganha de permissoes mais amplas.
    denied = [item for item in matches if not item.get("action_allowed")]
    if denied:
        return denied[-1]
    allowed = [
        item for item in matches
        if item.get("confirmed") is True
        and item.get("status") == "authorized"
        and item.get("action_allowed") is True
    ]
    return allowed[-1] if allowed else matches[-1]


def record_scope(program: str, data_dir: str, revision: str,
                 ttl_hours: float = DEFAULT_TTL_HOURS) -> list[dict]:
    """Materializa recibos p/ TODO o programa a partir do scope.json APROVADO.

    Um recibo por regra: includes viram autorização (wildcard cobre todos os
    subdomínios via _asset_matches → 1 recibo p/ *.dominio); excludes viram
    negação (action_allowed=false → 'denied wins' no authorization_for).
    `revision` (sha256 do `scope approve`) é a prova de aprovação — o agente
    não pode inventá-la; substitui a materialização host-a-host.
    """
    if not program:
        raise ValueError("program ausente")
    if not revision or not isinstance(revision, str):
        raise ValueError("--revision (sha256 do `scope approve`) obrigatório: prova de aprovacao")
    # Anti-forja: exige que a revisão tenha FORMA de sha256 (64 hex). Não impede
    # todo abuso, mas fecha o caso trivial (agente passar 'approved'/palavra solta).
    # Vincular ao valor real exigiria o Hive expor a revisão do `scope approve`
    # (o binário Go a computa internamente; canonicalização desconhecida aqui —
    # por isso NÃO hard-falhamos no mismatch, só auditamos + avisamos).
    if not re.fullmatch(r"[0-9a-fA-F]{64}", revision.strip()):
        raise ValueError(
            "--revision deve ser um sha256 (64 hex) do `scope approve`; "
            f"recebido {revision!r:.40} — nao parece um hash de aprovacao."
        )
    revision = revision.strip().lower()
    scope_path = Path(data_dir).expanduser() / "programs" / program / "scope.json"
    if not scope_path.is_file():
        raise ValueError(f"scope.json nao encontrado: {scope_path}")
    scope_bytes = scope_path.read_bytes()
    scope_sha256 = hashlib.sha256(scope_bytes).hexdigest()
    manifest = json.loads(scope_bytes.decode("utf-8"))
    # Hash canônico (ordem de chaves estável) — audita drift do conteúdo.
    canonical_sha256 = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if revision not in (scope_sha256, canonical_sha256):
        print(
            f"[!] aviso: --revision nao bate com sha256 do scope.json "
            f"(raw={scope_sha256[:12]}… / canonical={canonical_sha256[:12]}…). "
            "Confirme que rodou `scope approve` na versao atual do escopo.",
            file=sys.stderr,
        )
    if manifest.get("program_id") not in (None, program):
        raise ValueError("program_id do scope.json nao bate com o argumento")
    valid = {"host", "wildcard_domain", "ip", "cidr", "url_prefix"}
    now = _now()
    expires = _iso(now + timedelta(hours=ttl_hours))
    kept = [r for r in _active_receipts(_load_cache()) if r.get("program_id") != program]
    new: list[dict] = []
    for rule in manifest.get("rules", []):
        atype, value, action = rule.get("asset_type"), rule.get("value"), rule.get("action")
        if atype not in valid or not isinstance(value, str) or action not in {"include", "exclude"}:
            continue
        allowed = action == "include"
        new.append({
            "program_id": program,
            "asset": {"type": atype, "value": value},
            "status": "authorized" if allowed else "out_of_scope",
            "confirmed": allowed,
            "action_allowed": allowed,
            "scope_revision": revision,
            "scope_sha256": scope_sha256,
            "matched_rules": [rule],
            "recorded_at": _iso(now),
            "expires_at": expires,
        })
    if not new:
        raise ValueError("nenhuma regra valida no scope.json")
    _save_cache({"schema_version": SCHEMA_VERSION, "receipts": kept + new})
    return new


def _is_loopback_host(host: str) -> bool:
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def preflight(hosts) -> list[tuple[str, bool, str]]:
    """Checa autorização de cada host. Retorna (host, ok, motivo). Loopback → ok."""
    seen, results = set(), []
    for raw in hosts:
        host = _hostname(str(raw))
        if not host or host in seen:
            continue
        seen.add(host)
        if _is_loopback_host(host):
            results.append((host, True, "loopback"))
            continue
        r = authorization_for(host)
        ok = bool(r and r.get("action_allowed") is True)
        reason = "ok" if ok else ("sem recibo vigente" if not r else f"status={r.get('status')}")
        results.append((host, ok, reason))
    return results


def require_authorized(hosts, tool_name: str = "tool") -> None:
    """Preflight fail-closed p/ tools que fazem tráfego DIRETO (recon/cors_headers).

    Se algum host não tiver recibo `action_allowed=true`, imprime o motivo e
    encerra (SystemExit 2) ANTES de qualquer request. Espelha a autoridade
    exclusiva do Hive que o scope_hook aplica ao Bash. Loopback é isento.
    """
    problems = [(h, why) for (h, ok, why) in preflight(hosts) if not ok]
    if problems:
        sys.stderr.write(
            f"🚫 {tool_name}: BLOQUEADO (Hive fail-closed) — sem autorizacao vigente para:\n"
            + "".join(f"   - {h}: {why}\n" for h, why in problems)
            + "Rode hive_get_context no asset exato e "
              "`python3 tools/hive_scope_cache.py record <ctx.json>` (exija action_allowed=true).\n"
            "Scope local em targets/ nao concede autorizacao.\n"
        )
        raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cache fail-closed de escopo confirmado pelo Hive")
    sub = parser.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record", help="registra a resposta JSON de hive_get_context")
    rec.add_argument("json_file", help="arquivo JSON ou - para stdin")
    rec.add_argument("--ttl-hours", type=float, default=DEFAULT_TTL_HOURS)
    rsc = sub.add_parser("record-scope",
                         help="materializa recibos (wildcard+host) do scope.json APROVADO — 1 comando p/ todo o programa")
    rsc.add_argument("program")
    rsc.add_argument("--revision", required=True, help="sha256 do `scope approve` (prova de aprovacao)")
    rsc.add_argument("--data-dir", default=None, help="dir do Hive (default: $HIVE_DATA_DIR)")
    rsc.add_argument("--ttl-hours", type=float, default=DEFAULT_TTL_HOURS)
    chk = sub.add_parser("check", help="consulta autorizacao em cache")
    chk.add_argument("target")
    sub.add_parser("list", help="lista recibos ainda validos")
    sub.add_parser("clear", help="remove todos os recibos")
    args = parser.parse_args(argv)

    if args.command == "record":
        if not 0 < args.ttl_hours <= 24:
            parser.error("--ttl-hours deve estar entre 0 e 24")
        try:
            receipt = record_context(_read_json(args.json_file), args.ttl_hours)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"ERRO: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(receipt, ensure_ascii=False, indent=2))
        return 0
    if args.command == "record-scope":
        if not 0 < args.ttl_hours <= 24:
            parser.error("--ttl-hours deve estar entre 0 e 24")
        data_dir = args.data_dir or os.environ.get("HIVE_DATA_DIR")
        if not data_dir:
            parser.error("passe --data-dir ou defina HIVE_DATA_DIR (ex.: .../hive_instance/data)")
        try:
            recs = record_scope(args.program, data_dir, args.revision, args.ttl_hours)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"ERRO: {exc}", file=sys.stderr)
            return 2
        allow = sum(1 for r in recs if r["action_allowed"])
        print(f"[+] {len(recs)} recibos p/ '{args.program}' "
              f"({allow} include / {len(recs) - allow} exclude), expira {recs[0]['expires_at']}",
              file=sys.stderr)
        print(json.dumps([{**r["asset"], "allow": r["action_allowed"]} for r in recs],
                         ensure_ascii=False, indent=2))
        return 0
    if args.command == "check":
        receipt = authorization_for(args.target)
        print(json.dumps(receipt or {"action_allowed": False, "reason": "no_live_hive_receipt"}, ensure_ascii=False, indent=2))
        return 0 if receipt and receipt.get("action_allowed") else 1
    if args.command == "list":
        print(json.dumps(_active_receipts(_load_cache()), ensure_ascii=False, indent=2))
        return 0
    _save_cache({"schema_version": SCHEMA_VERSION, "receipts": []})
    print("cache de escopo Hive limpo")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
