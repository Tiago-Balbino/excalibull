"""Contrato comum das contribuições; metadados nunca aprovam escopo."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timezone

from hive_scope_cache import normalize_asset

IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
MAX_DOCUMENT_BYTES = 5 * 1024 * 1024
SECRET = re.compile(r"(?i)(authorization:\s*bearer|set-cookie:|private key|session[_ -]?cookie|password\s*[=:])")


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("identificador inválido")
    return value


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def identity(handle=None, team=None):
    handle, team = handle or os.environ.get("HIVE_HANDLE"), team or os.environ.get("HIVE_TEAM_TAG")
    if not handle or not team:
        raise ValueError("informe HIVE_HANDLE/HIVE_TEAM_TAG ou --handle/--team; autoria não tem default pessoal")
    return identifier(handle), identifier(team)


def concrete_asset(value):
    if not isinstance(value, str):
        raise ValueError("ativo deve ser string")
    if value.startswith(("host:", "ip:", "url_prefix:")):
        kind, raw = value.split(":", 1)
    elif value.startswith(("https://", "http://")):
        kind, raw = "url_prefix", value
    else:
        try:
            ipaddress.ip_address(value)
            kind, raw = "ip", value
        except ValueError:
            kind, raw = "host", value
    if "*" in raw or (kind == "ip" and "/" in raw):
        raise ValueError("contribuições exigem ativos concretos, sem wildcard/CIDR")
    asset = normalize_asset({"type": kind, "value": raw})
    return asset["type"] + ":" + asset["value"]


def document(program, body, *, handle=None, team=None, assets=(), platform=None,
             target_name=None, document_type="note", classification="internal", tags=(),
             source="excalibull", collected_at=None, result="observation"):
    handle, team = identity(handle, team)
    platform = platform or os.environ.get("EXCALIBULL_PLATFORM")
    target_name = target_name or os.environ.get("EXCALIBULL_TARGET_NAME")
    identifier(program)
    if document_type not in {"note", "endpoint", "asset", "evidence"} or classification not in {"internal", "restricted"}:
        raise ValueError("tipo/classificação de contribuição inválido")
    if result not in {"observation", "hypothesis", "confirmed", "discarded", "inconclusive"}:
        raise ValueError("estado de evidência inválido")
    if not isinstance(source, str) or not source.strip():
        raise ValueError("fonte da contribuição obrigatória")
    if not isinstance(body, str) or not body.strip() or SECRET.search(body):
        raise ValueError("contribuição vazia ou possível credencial; higienize antes de preparar")
    if len(body.encode()) > MAX_DOCUMENT_BYTES:
        raise ValueError("divida a contribuição: limite 5 MiB por documento")
    if bool(platform) != bool(target_name):
        raise ValueError("platform e target_name devem ser informados juntos")
    if platform:
        identifier(platform)
        if not isinstance(target_name, str) or target_name != target_name.strip() or len(target_name.encode()) > 120 or target_name == "@program" or any(ord(c) < 32 or ord(c) == 127 for c in target_name):
            raise ValueError("target_name inválido")
    stamp = collected_at or now()
    try:
        if not isinstance(stamp, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", stamp):
            raise ValueError()
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
    except (ValueError, AttributeError):
        raise ValueError("collected_at deve usar RFC 3339 com fuso") from None
    refs = sorted({concrete_asset(a) for a in assets})
    if len(refs) > 5000:
        raise ValueError("divida a contribuição: limite 5000 ativos")
    normalized_tags = sorted({identifier(t) for t in (handle, team, "excalibull", *tags)})
    if len(normalized_tags) > 64:
        raise ValueError("contribuição supera 64 tags")
    metadata = {"program_id": program, "document_type": document_type, "classification": classification,
                "source": source, "collected_at": stamp, "tags": normalized_tags,
                "asset_refs": [a.split(":", 1)[1] for a in refs], "handle": handle, "team": team,
                "result": result}
    if platform:
        metadata.update(platform=platform, target_name=target_name, observed_targets=refs)
    # Data automática não cria revisão nova durante retry do mesmo conteúdo.
    canonical = {"metadata": {k: v for k, v in metadata.items() if k != "collected_at"}, "body": body.rstrip() + "\n"}
    digest = hashlib.sha256(json.dumps(canonical, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    return {"metadata": metadata, "body": canonical["body"], "content_sha256": digest, "assets": refs}


def render(prepared, session, contribution, revision):
    marker = f"excalibull:{session}:{contribution}:r{revision}:{prepared['content_sha256']}"
    metadata = {**prepared["metadata"], "session_id": session, "contribution_id": contribution, "contribution_revision": revision}
    lines = []
    for key, value in metadata.items():
        scalar = value if key in {"program_id", "document_type", "classification", "source"} and re.fullmatch(r"[a-z0-9_-]+", str(value)) else json.dumps(value, ensure_ascii=False)
        lines.append(f"{key}: {scalar}")
    text = "---\n" + "\n".join(lines) + "\n---\n" + marker + "\n\n" + prepared["body"]
    if len(text.encode()) > MAX_DOCUMENT_BYTES:
        raise ValueError("documento com metadados supera 5 MiB; divida a contribuição")
    lines = [line.strip() for line in prepared["body"].splitlines() if line.strip()]
    content_lines = [line for line in lines if not line.startswith(("#", "```", "~~~", "<!--")) and line not in {"{", "[", "}", "]"}]
    witness = (content_lines or lines)[0][:160]
    return text, marker, witness
