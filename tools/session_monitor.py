#!/usr/bin/env python3
"""Métricas de sessão em WAL; somente números/metadados, sem conteúdo de requests."""
from __future__ import annotations

import argparse
import json
import math
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from brain import get_brain_dir
from file_safety import atomic_write_text, locked_file
from hive_workspace import _program, _slug, resolve_data_dir


def now():
    return datetime.now(timezone.utc).isoformat()


def folder():
    return get_brain_dir() / "metrics"


def active_path():
    return folder() / "active.json"


def load_active():
    pointer = active_path()
    if not pointer.exists():
        return None, None
    sid = _program(json.loads(pointer.read_text())["session_id"])
    path = folder() / f"{sid}.json"
    state = json.loads(path.read_text())
    if state.get("status") != "active":
        return None, None
    return path, state


def usage(values):
    result = {}
    for key in ("input_tokens", "output_tokens", "cached_input_tokens"):
        value = values.get(key)
        if value is not None:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("tokens devem ser inteiros não negativos fornecidos pelo executor")
            result[key] = value
    if not {"input_tokens", "output_tokens"} <= result.keys():
        raise ValueError("usage requer input_tokens e output_tokens reais; não use estimativas")
    if result.get("cached_input_tokens", 0) > result["input_tokens"]:
        raise ValueError("cached_input_tokens é subconjunto de input_tokens")
    result["source"] = _slug(str(values.get("source") or "executor"))
    return result


def totals(state, at=None):
    end = at or state.get("ended_at") or now()
    elapsed = max(0, (datetime.fromisoformat(end) - datetime.fromisoformat(state["started_at"])).total_seconds())
    usage_events = [e for e in state["events"] if e["kind"] == "usage"]
    tokens = ({key: sum(e["usage"][key] for e in usage_events)
               for key in ("input_tokens", "output_tokens")} if usage_events else None)
    if tokens:
        cache_samples = [e["usage"]["cached_input_tokens"] for e in usage_events
                         if "cached_input_tokens" in e["usage"]]
        tokens["cached_input_tokens"] = sum(cache_samples) if len(cache_samples) == len(usage_events) else None
        tokens["cached_input_tokens_reported"] = sum(cache_samples) if cache_samples else None
        tokens["cached_input_samples"] = len(cache_samples)
        tokens["total_tokens"] = tokens["input_tokens"] + tokens["output_tokens"]
        tokens["coverage"] = "reported-usage-only"
    calls = [e for e in state["events"] if e["kind"] == "hive"]
    samples = [e["duration_ms"] for e in calls if e.get("duration_ms") is not None]
    by_name = {}
    for event in calls:
        by_name[event["name"]] = by_name.get(event["name"], 0) + 1
    contexts = {}
    for event in state["events"]:
        key = event.get("context", {}).get("protocol", "unknown")
        contexts[key] = contexts.get(key, 0) + 1
    return {"elapsed_wall_seconds": elapsed, "tokens": tokens,
            "token_availability": "reported" if tokens else "unavailable",
            "hive_calls": len(calls), "hive_calls_by_operation": by_name,
            "hive_failed_calls": sum(e.get("success") is False for e in calls),
            "hive_duration_ms_reported": sum(samples) if samples else None,
            "hive_duration_samples": len(samples), "events_by_protocol": contexts,
            "metric_coverage": "registered-events-only"}


def record(kind, name, *, duration_ms=None, success=True, values=None, event_id=None, program=None):
    if not active_path().exists():
        return False
    event_id = _slug(event_id) if event_id else None
    with locked_file(active_path()):
        path, state = load_active()
        if state is None or (program and state["program_id"] != program):
            return False
        if event_id and any(e.get("event_id") == event_id for e in state["events"]):
            return False
        if duration_ms is not None and (not isinstance(duration_ms, (int, float)) or isinstance(duration_ms, bool)
                                       or not math.isfinite(duration_ms) or duration_ms < 0):
            raise ValueError("duration_ms deve ser medida, não negativa")
        item = {"at": now(), "kind": kind, "name": _slug(name), "context": state["context"].copy(),
                "success": success, "duration_ms": duration_ms}
        if event_id:
            item["event_id"] = _slug(event_id)
        if values is not None:
            item["usage"] = usage(values)
        state["events"].append(item)
        atomic_write_text(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")
    return True


def tool_metric(name, elapsed, success, program):
    try:
        record("tool", name, duration_ms=elapsed * 1000, success=success, program=program)
    except (OSError, ValueError, KeyError, TypeError):
        print("Monitor: métrica não registrada; revise o WAL antes de publicar números.", file=sys.stderr)


def report(state, data_dir=None):
    destination = resolve_data_dir(data_dir, writer=True)
    metrics = {"session_id": state["session_id"], "program_id": state["program_id"],
               "started_at": state["started_at"], "ended_at": state.get("ended_at"),
               "status": state["status"], "current_context": state["context"],
               "totals": totals(state), "findings": state["findings"],
               "events": state["events"], "publication": "pending-ingest-idle-readback"}
    target = destination / "programs" / state["program_id"] / "notes" / f"excalibull-monitor-{state['session_id']}.md"
    fm = (f"---\nprogram_id: {state['program_id']}\ndocument_type: note\nclassification: internal\n"
          f"source: excalibull\ncollected_at: {now()}\ntags: [excalibull, session-metrics, monitor]\nasset_refs: []\n---\n")
    text = "# Monitor — métricas da sessão\n\nTempo é duração de parede; tokens cobrem somente usage real registrado. "
    text += "Sem usage, tokens são indisponíveis. Não interpretar omissões como zero.\n\n```json\n"
    atomic_write_text(target, fm + text + json.dumps(metrics, ensure_ascii=False, indent=2) + "\n```\n")
    return target


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start")
    start.add_argument("program", type=_program)
    start.add_argument("--mode", default="hunter")
    start.add_argument("--posture", default="unknown")
    start.add_argument("--protocol", default="monitor")
    where = sub.add_parser("where")
    for key in ("mode", "posture", "protocol"):
        where.add_argument(f"--{key}")
    event = sub.add_parser("event")
    event.add_argument("kind", choices=["hive", "tool", "protocol"])
    event.add_argument("name")
    event.add_argument("--duration-ms", type=float)
    event.add_argument("--failed", action="store_true")
    event.add_argument("--event-id")
    tokens = sub.add_parser("usage")
    tokens.add_argument("input", help="JSON usage com contagens reais do executor; só metadados permitidos")
    tokens.add_argument("--event-id", required=True, help="ID único do intervalo de usage (evita duplicar tokens)")
    finding = sub.add_parser("finding")
    finding.add_argument("id", type=_program, help="ID/alias, sem título ou dados sensíveis")
    finding.add_argument("--confirmed", action="store_true")
    sub.add_parser("status")
    for command in ("report", "stop"):
        parser = sub.add_parser(command)
        parser.add_argument("--data-dir")
    args = ap.parse_args(argv)
    if args.command == "event":
        return 0 if record(args.kind, args.name, duration_ms=args.duration_ms, success=not args.failed, event_id=args.event_id) else 1
    if args.command == "usage":
        values = json.loads(Path(args.input).read_text())
        return 0 if record("usage", "model-usage", values=values, event_id=args.event_id) else 1
    with locked_file(active_path()):
        path, state = load_active()
        if args.command == "start":
            if state:
                raise ValueError("monitor já ativo; reutilize a sessão ou encerre antes de iniciar outra")
            sid = uuid.uuid4().hex
            path = folder() / f"{sid}.json"
            state = {"session_id": sid, "program_id": args.program, "status": "active", "started_at": now(),
                     "context": {key: _slug(getattr(args, key)) for key in ("mode", "posture", "protocol")},
                     "events": [], "findings": []}
            atomic_write_text(path, json.dumps(state, ensure_ascii=False, indent=2))
            atomic_write_text(active_path(), json.dumps({"session_id": sid}))
        elif state is None:
            raise ValueError("monitor não está ativo")
        elif args.command == "where":
            for key in ("mode", "posture", "protocol"):
                value = getattr(args, key)
                if value:
                    state["context"][key] = _slug(value)
            state["events"].append({"at": now(), "kind": "context", "name": "where", "context": state["context"].copy()})
            atomic_write_text(path, json.dumps(state, ensure_ascii=False, indent=2))
        elif args.command == "finding":
            stamp = now()
            existing = next((f for f in state["findings"] if f["id"] == args.id), None)
            if existing:
                if existing["confirmed"] or not args.confirmed:
                    raise ValueError("marco já registrado; não duplicar tempo/contagem")
                existing.update({"confirmed": True, "confirmed_at": stamp,
                                 "context_at_confirmation": state["context"].copy(),
                                 "metrics_at_confirmation": totals(state, stamp)})
            else:
                item = {"id": args.id, "confirmed": args.confirmed, "at": stamp,
                        "context": state["context"].copy(), "metrics_at_finding": totals(state, stamp)}
                if args.confirmed:
                    item.update({"confirmed_at": stamp, "metrics_at_confirmation": totals(state, stamp)})
                state["findings"].append(item)
            atomic_write_text(path, json.dumps(state, ensure_ascii=False, indent=2))
        elif args.command in {"report", "stop"}:
            if args.command == "stop":
                state["ended_at"] = now()
                state["status"] = "stopped"
            target = report(state, args.data_dir)
            if args.command == "stop":
                atomic_write_text(path, json.dumps(state, ensure_ascii=False, indent=2))
                atomic_write_text(active_path(), json.dumps({"session_id": state["session_id"]}))
            print(target)
            print("Publicação pendente: ingestão → idle → read-back.")
            return 0
        print(json.dumps({"session_id": state["session_id"], "program_id": state["program_id"],
                          "context": state["context"], "totals": totals(state), "findings": state["findings"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError):
        print("Monitor falhou; verifique estado/configuração ou contagens reais do executor.", file=sys.stderr)
        sys.exit(2)
