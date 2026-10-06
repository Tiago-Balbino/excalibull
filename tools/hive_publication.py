"""Entrega explícita, relatório do writer e read-back limitado ao contrato atual."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from datetime import datetime, timezone

from hive_documents import now
from hive_documents import MAX_DOCUMENT_BYTES
from hive_gateway import HiveClient
from hive_outbox import safe_path

VERIFICATION_TTL_SECONDS = 15 * 60
OUTCOMES = {"created", "updated", "unchanged", "skipped", "missing", "failed", "cancelled"}


def file_hash(path):
    with Path(path).open("rb") as source:
        content = source.read(MAX_DOCUMENT_BYTES + 1)
    if len(content) > MAX_DOCUMENT_BYTES:
        raise ValueError("arquivo do writer supera o limite da contribuição")
    return hashlib.sha256(content).hexdigest()


def boundary():
    values = [os.environ.get(name, "") for name in ("HIVE_MIND_URL", "HIVE_CENTER_URL")]
    return hashlib.sha256(repr(values).encode()).hexdigest()


def writer_root(queue, workspace):
    path = Path(workspace).expanduser()
    if path.is_symlink() or not path.is_dir():
        raise ValueError("workspace de writer deve existir e não ser symlink")
    path = path.resolve()
    if path.is_relative_to(queue.root) or queue.root.is_relative_to(path):
        raise ValueError("workspace de writer deve ficar separado da outbox")
    # O checkout de engenharia não é workspace operacional.
    if (path / ".git").exists():
        raise ValueError("raiz de repositório não é workspace operacional de writer")
    return path


def deliver(queue, session, program, workspace):
    root = writer_root(queue, workspace)
    with queue.edit(session, program) as state:
        entries = queue.current(state)
        if not entries:
            raise ValueError("sessão sem contribuições")
        state.update(ingestion_ok=False, verification=None, status="open")
        for entry in entries:
            try:
                content = queue.bytes_for(state, entry)
                target = safe_path(root, entry["path"])
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    if file_hash(target) != entry["sha256"]:
                        raise ValueError("destination-mismatch")
                else:
                    with os.fdopen(descriptor, "wb") as output:
                        output.write(content)
                        output.flush()
                        os.fsync(output.fileno())
            except (OSError, ValueError, KeyError, TypeError):
                entry.update(state="reconciliation-required", verification=None)
                entry["attempts"].append({"at": now(), "operation": "delivery", "ok": False, "reason": "destination-unavailable-or-mismatch"})
                return {"ok": False, "publication": "pending-writer", "reason": "destination-unavailable-or-mismatch"}
            entry.update(state="delivered", verification=None,
                         delivery={"at": now(), "workspace": str(root), "sha256": entry["sha256"]})
            entry["attempts"].append({"at": now(), "operation": "delivery", "ok": True})
        return {"ok": True, "publication": "delivered", "session_id": session, "files": len(entries)}


def validate_report(report):
    if not isinstance(report, dict) or type(report.get("schema_version")) is not int or report["schema_version"] != 1 or type(report.get("ok")) is not bool or type(report.get("exit_code")) is not int:
        raise ValueError("relatório de ingestão inválido/desconhecido")
    summary = report.get("summary")
    if not isinstance(summary, dict) or summary.get("scan_complete") is not True or not isinstance(summary.get("results"), list):
        raise ValueError("varredura incompleta; relatório não confirma o conjunto")
    results = {}
    for item in summary["results"]:
        if not isinstance(item, dict) or item.get("outcome") not in OUTCOMES or type(item.get("published")) is not bool:
            raise ValueError("outcome de ingestão inválido/desconhecido")
        path = item.get("path")
        if path is None:
            continue
        if not isinstance(path, str) or path in results or Path(path).is_absolute() or ".." in Path(path).parts or "\\" in path:
            raise ValueError("path duplicado/inválido no relatório")
        results[path] = item
    # Consistência do envelope e dos contadores antes de promover contribuições.
    counts = [summary.get(outcome) for outcome in OUTCOMES]
    if any(type(value) is not int or value < 0 for value in counts) or type(summary.get("total")) is not int or summary.get("total") != len(summary["results"]) or sum(counts) != summary["total"]:
        raise ValueError("contadores do relatório divergem dos arquivos")
    for outcome in OUTCOMES:
        if summary[outcome] != sum(item["outcome"] == outcome for item in summary["results"]):
            raise ValueError("contador de outcome inconsistente")
    if report["ok"] and (report["exit_code"] != 0 or summary["failed"] or summary["cancelled"]):
        raise ValueError("envelope declara sucesso com falha/cancelamento")
    return results


def ingest(queue, session, program, workspace, config, *, client_factory=HiveClient):
    root = writer_root(queue, workspace)
    with queue.edit(session, program) as state:
        entries = queue.current(state)
        if not entries:
            raise ValueError("sessão sem contribuições")
        state.update(ingestion_ok=False, verification=None, status="open")
        try:
            # Verifica o snapshot entregue imediatamente antes e depois do lote.
            for entry in entries:
                queue.bytes_for(state, entry)
                receipt = entry.get("delivery") or {}
                if receipt.get("workspace") != str(root) or receipt.get("sha256") != entry["sha256"] or file_hash(safe_path(root, entry["path"])) != entry["sha256"]:
                    raise ValueError("entrega ausente/divergente; execute deliver primeiro")
            with client_factory(writer_config=config, writer_workspace=root, timeout=300) as client:
                if "ingest_workspace" not in client.tools:
                    raise ValueError("writer não anunciou ingest_workspace")
                report = client.ingest_report()
            outcomes = validate_report(report)
            for entry in entries:
                item = outcomes.get(entry["path"])
                entry["verification"] = None
                if not item:
                    entry["state"] = "delivered"
                    reason = "missing-result"
                elif file_hash(safe_path(root, entry["path"])) != entry["sha256"]:
                    entry["state"] = "reconciliation-required"
                    reason = "content-changed-during-ingestion"
                elif item["outcome"] == "unchanged" or (item["outcome"] in {"created", "updated"} and item["published"] is True):
                    entry["state"] = "indexed"
                    reason = None
                else:
                    entry["state"] = "reconciliation-required" if item["published"] else "delivered"
                    reason = item.get("reason_code", item["outcome"])
                entry["attempts"].append({"at": now(), "operation": "ingest", "ok": reason is None,
                                           "outcome": item.get("outcome") if item else "missing", "published": item.get("published") if item else False,
                                           "reason": reason})
            state["ingestion_ok"] = (report["ok"] is True and report["exit_code"] == 0 and
                                     report.get("_mcp_is_error", False) is False and all(e["state"] == "indexed" for e in entries))
            state["ingestion"] = {"at": now(), "ok": state["ingestion_ok"], "exit_code": report["exit_code"],
                                  "expected": state["expected"].copy()}
        except (OSError, ValueError, KeyError, TypeError):
            for entry in entries:
                entry.update(state="reconciliation-required", verification=None)
                entry["attempts"].append({"at": now(), "operation": "ingest", "ok": False, "reason": "writer-unavailable-or-invalid-report"})
        return {"ok": state["ingestion_ok"], "session_id": session,
                "publication": "indexed" if state["ingestion_ok"] else "pending-reconciliation"}


def verify(queue, session, program, *, client_factory=HiveClient):
    with queue.edit(session, program) as state:
        entries = queue.current(state)
        state.update(verification=None, status="open")
        for entry in entries:
            entry["verification"] = None
            if entry["state"] == "verified":
                entry["state"] = "indexed"
        if not entries or not state.get("ingestion_ok") or not all(e["state"] == "indexed" for e in entries):
            return {"ok": False, "reason": "ingestion-not-confirmed", "publication": "pending"}
        try:
            for entry in entries:
                queue.bytes_for(state, entry)
            with client_factory() as client:
                status = client.call("get_sync_status", {})
                if status.get("status") != "idle" or status.get("queue_confirmed") is not True:
                    raise ValueError("fila desconhecida/ocupada")
                for entry in entries:
                    response = client.call("hive_search", {"program_id": program, "query": entry["marker"], "limit": 20})
                    matches = [r for r in response.get("results", []) if isinstance(r, dict) and r.get("path") == entry["path"] and
                               isinstance(r.get("text"), str) and entry["marker"] in r["text"] and entry["witness"] in r["text"]]
                    if not matches:
                        raise ValueError("contribuição não recuperada ou revisão divergente")
                    entry.update(state="verified", verification={"at": now(), "scope": "retrieved-fragment",
                                 "path": entry["path"], "marker": entry["marker"], "boundary": boundary(),
                                 "fragment_sha256": hashlib.sha256(matches[0]["text"].encode()).hexdigest(),
                                 "truncated": response.get("truncated", False)})
                    entry["attempts"].append({"at": now(), "operation": "read-back", "ok": True})
                final_status = client.call("get_sync_status", {})
                if final_status.get("status") != "idle" or final_status.get("queue_confirmed") is not True:
                    raise ValueError("fila deixou de estar confirmada")
            state.update(status="verified", verification={"at": now(), "expected": state["expected"].copy(),
                         "queue_confirmed": True, "boundary": boundary(), "scope": "retrieved-fragment"})
        except (OSError, ValueError, KeyError, TypeError):
            for entry in entries:
                entry.update(state="indexed", verification=None)
                entry["attempts"].append({"at": now(), "operation": "read-back", "ok": False, "reason": "unavailable-or-divergent"})
        return {"ok": state["verification"] is not None, "session_id": session,
                "publication": "verified" if state["verification"] else "pending-read-back",
                "verification_scope": "retrieved-fragment"}


def publication_problems(queue, state):
    problems = []
    entries = queue.current(state)
    verification = state.get("verification") or {}
    if not entries:
        problems.append("sessão sem contribuições esperadas")
    if state.get("ingestion_ok") is not True or verification.get("expected") != state["expected"] or verification.get("queue_confirmed") is not True or verification.get("boundary") != boundary():
        problems.append("publicação da sessão sem ingestão/fila/read-back confirmados")
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(verification["at"])).total_seconds()
        if not 0 <= age < VERIFICATION_TTL_SECONDS:
            raise ValueError()
    except (KeyError, ValueError, TypeError):
        problems.append("confirmação ausente/expirada; execute hive_outbox.py verify")
    for entry in entries:
        queue.bytes_for(state, entry)
        proof = entry.get("verification") or {}
        if entry["state"] != "verified" or proof.get("path") != entry["path"] or proof.get("marker") != entry["marker"] or proof.get("boundary") != boundary() or proof.get("scope") != "retrieved-fragment":
            problems.append(f"contribuição {entry['id']} r{entry['revision']} ainda não verificada")
    return problems
