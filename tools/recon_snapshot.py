"""Snapshots de superfície observada; baseline durável como nota writer do Hive."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from file_safety import atomic_write_text
from recon_records import normalize_record

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


def save_snapshot(path, program, hosts):
    stamp = datetime.now(timezone.utc).isoformat()
    text = (f"---\nprogram_id: {program}\ndocument_type: note\nclassification: internal\n"
            f"source: excalibull\ncollected_at: {stamp}\ntags: [excalibull, recon-snapshot]\n"
            f"asset_refs: {json.dumps(sorted(hosts))}\n---\n"
            "# Snapshot de recon\n\nEstado writer para comparação; confirmar ingestão e read-back.\n"
            "`unchanged` significa superfície observada igual, não ausência de vulnerabilidade.\n\n```json\n")
    atomic_write_text(path, text + json.dumps({"program_id": program, "hosts": hosts}, ensure_ascii=False, indent=2) + "\n```\n")
