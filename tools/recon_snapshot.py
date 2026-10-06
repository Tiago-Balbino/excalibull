"""Snapshots de superfície observada; baseline durável como nota writer do Hive."""
from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path

from file_safety import atomic_write_text
from recon_records import normalize_record
from hive_outbox import prepare

BLOCK = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)


def load_snapshot(path):
    if not path.exists():
        return {}
    match = BLOCK.search(path.read_text(encoding="utf-8"))
    if not match:
        raise ValueError("snapshot existente sem JSON; não substituir")
    data = json.loads(match[1])
    if not isinstance(data, dict) or not isinstance(data.get("hosts"), dict):
        raise ValueError("snapshot inválido")
    return data["hosts"]


def surface(data):
    records = [normalize_record(r) for r in data.get("records", [])]
    return {"endpoints": sorted({r["path"] for r in records}),
            "graphql_operations": sorted(data.get("graphql_ops", [])),
            "stacks": sorted(fp["name"] for fp in data.get("fingerprints", []) if fp.get("name")),
            "content_hashes": data.get("content_hashes", {}),
            "coverage": data.get("coverage", {"status": "unknown"})}


def compare(previous, current):
    if previous is None:
        return {"status": "first-observation", "added_endpoints": current["endpoints"], "removed_endpoints": []}
    changed = [field for field in ("endpoints", "graphql_operations", "stacks", "content_hashes")
               if previous.get(field) != current.get(field)]
    return {"status": "changed" if changed else "unchanged", "changed_fields": changed,
            "added_endpoints": sorted(set(current["endpoints"]) - set(previous.get("endpoints", []))),
            "removed_endpoints": sorted(set(previous.get("endpoints", [])) - set(current["endpoints"])),
            "interpretation": "ausência nesta coleta não comprova remoção do endpoint"}


def save_snapshot(path, program, hosts, *, data_dir=None, contribute_hosts=None, session=None):
    text = ("# Snapshot de recon\n\nProjeção local para comparação; baseline de cobertura local.\n"
            "`unchanged` significa superfície observada igual, não ausência de vulnerabilidade.\n\n```json\n")
    body = text + json.dumps({"program_id": program, "hosts": hosts}, ensure_ascii=False, indent=2) + "\n```\n"
    if data_dir is not None:
        for host, pages in sorted(hosts.items()):
            if contribute_hosts is not None and host not in contribute_hosts:
                continue
            subject = "snapshot-" + hashlib.sha256(host.encode()).hexdigest()[:16]
            prepare(program, subject, "# Snapshot de recon\n\nCobertura local; ausência não comprova remoção.\n\n```json\n" +
                    json.dumps({"program_id": program, "hosts": {host: pages}}, ensure_ascii=False, indent=2) + "\n```\n",
                    data_dir=data_dir, session=session, assets=[host], tags=["recon-snapshot"])
    atomic_write_text(path, body)
