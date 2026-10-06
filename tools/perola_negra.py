#!/usr/bin/env python3
"""Pérola negra: tráfego observado + requisições estruturadas + revisita com diff.

Hive pre-flight/policy e publicação confirmada permanecem passos do agente.
Nenhum host descoberto é acessado automaticamente. HAR é importação offline;
CDP observa navegação manual. Revisitas fazem coleta estática autorizada.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from browser_recon import authorized, observe_cdp, read_har
from endpoints import load_existing
from file_safety import atomic_write_text, locked_file
from hive_workspace import _program, resolve_data_dir
from hive_documents import identity
from hive_outbox import Outbox, prepare
from recon_records import normalize_record, safe_path
from recon_snapshot import compare, load_snapshot, save_snapshot, surface
from session_monitor import tool_metric

ROOT = Path(__file__).resolve().parent
_PROGRAM = None
_SESSION = None


def run_tool(args, timeout=300):
    started = time.monotonic()
    env = os.environ.copy()
    if _SESSION:
        env["EXCALIBULL_SESSION_ID"] = _SESSION
    try:
        result = subprocess.run([sys.executable, str(ROOT / args[0]), *args[1:]],
                                capture_output=True, text=True, timeout=timeout, env=env)
        # Não imprimir stderr com URLs ou conteúdo bruto de ferramentas.
        tool_metric(args[0], time.monotonic() - started, result.returncode == 0, _PROGRAM)
        return result.returncode, result.stdout
    except (OSError, subprocess.TimeoutExpired):
        tool_metric(args[0], time.monotonic() - started, False, _PROGRAM)
        return 2, ""


def known_urls(notes, snapshot):
    """Revisita raízes web; não reproduz automaticamente métodos/ações de APIs."""
    urls = set()
    hosts = set(snapshot)
    for pages in snapshot.values():
        urls.update(key for key in pages if key.startswith(("http://", "https://")) and "{redacted}" not in key)
    for corpus in notes.glob("*-excalibull-endpoints-corpus.md"):
        hosts.update(row["host"] for row in load_existing(str(corpus)).values())
    represented = {urlsplit(url).hostname for url in urls}
    urls.update(f"https://{host}/" for host in hosts - represented)
    return sorted(urls)


def select_urls(explicit, hosts, known, revisit):
    urls = list(explicit) + [f"https://{host.strip()}/" for host in hosts.split(",") if host.strip()]
    if revisit:
        urls += known
    result = []
    for url in urls:
        parsed = urlsplit(url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("URL HTTP(S) sem credenciais necessária")
        if url not in result:
            result.append(url)
    return result


def write_coverage(path, program, report, *, session=None):
    hosts = sorted({item["host"] for item in report["revisits"]})
    text = ("# Pérola negra — cobertura da execução\n\n"
            "Cobertura observada, não veredito de vulnerabilidade. Revisar antes de ingerir.\n\n```json\n")
    return prepare(program, "perola-negra-coverage", text + json.dumps(report, ensure_ascii=False, indent=2) + "\n```\n",
                   data_dir=path, session=session, assets=hosts, tags=["perola-negra", "recon-coverage"])


def main():
    global _PROGRAM, _SESSION
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("program", type=_program)
    ap.add_argument("--data-dir", default=os.environ.get("EXCALIBULL_OUTBOX_DIR", ""))
    ap.add_argument("--scratch")
    ap.add_argument("--session")
    ap.add_argument("--url", action="append", default=[], help="página de entrada autorizada; repetível")
    ap.add_argument("--hosts", default="", help="CSV de hosts explícitos")
    ap.add_argument("--revisit-known", action="store_true")
    ap.add_argument("--har", action="append", default=[], help="HAR local; repetível; não é copiado")
    ap.add_argument("--cdp", help="observador Chromium local; não navega nem reproduz requests")
    ap.add_argument("--seconds", type=float, default=120)
    ap.add_argument("--role", default="unknown")
    ap.add_argument("--flow", default="unknown")
    ap.add_argument("--max-js", type=int, default=40)
    ap.add_argument("--max-hosts", type=int, default=10)
    ap.add_argument("--rate", type=float, default=1.0, help="req/s da coleta estática; respeitar policy do Hive")
    a = ap.parse_args()
    _PROGRAM = a.program
    a.data_dir = str(resolve_data_dir(a.data_dir or None))
    identity()
    _SESSION = Outbox(a.data_dir).session(a.program, a.session, create=True)
    if a.max_hosts < 1 or a.max_js < 0 or a.rate <= 0 or not 0 < a.seconds <= 3600:
        ap.error("limites inválidos: max-hosts >=1, max-js >=0, rate >0, seconds 0..3600")
    if not (a.url or a.hosts or a.revisit_known or a.har or a.cdp):
        ap.error("selecione HAR/CDP, URLs/hosts ou --revisit-known")
    scratch = Path(a.scratch or tempfile.mkdtemp(prefix="perola_negra_"))
    scratch.mkdir(parents=True, exist_ok=True)
    notes = Path(a.data_dir).expanduser() / "programs" / a.program / "notes"
    projection = Path(a.data_dir) / "projections" / a.program
    snapshot_path = projection / "excalibull-perola-negra-snapshot.md"
    baseline = load_snapshot(snapshot_path)
    urls = select_urls(a.url, a.hosts, known_urls(projection, baseline) if a.revisit_known else [], a.revisit_known)
    report = {"program_id": a.program, "protocol": "perola-negra", "revisits": [],
              "browser": [], "deferred_urls": len(urls[a.max_hosts:]),
              "publication": "pending-writer"}
    records, updates = [], {}
    for path in a.har:
        imported, coverage = read_har(path, a.role, a.flow)
        records.extend(imported)
        report["browser"].append(coverage)
    if a.cdp:
        imported, coverage = observe_cdp(a.cdp, a.program, a.seconds, a.role, a.flow)
        records.extend(imported)
        report["browser"].append(coverage)
    for url in urls[:a.max_hosts]:
        parsed = urlsplit(url)
        host = parsed.hostname.lower()
        key = f"{parsed.scheme}://{parsed.netloc.lower()}{safe_path(parsed.path or '/')}"
        visit = {"host": host, "entry": key}
        if not authorized(url, a.program):
            visit["status"] = "blocked-without-receipt"
            report["revisits"].append(visit)
            continue
        rc, out = run_tool(["jsrecon.py", url, "--program", a.program, "--max-js", str(a.max_js),
                            "--rate", str(a.rate), "--json"], timeout=600)
        try:
            data = json.loads(out) if rc == 0 else None
        except ValueError:
            data = None
        if not isinstance(data, dict) or "records" not in data:
            visit["status"] = "failed"
            report["revisits"].append(visit)
            continue
        records.extend(data["records"])
        current = surface(data)
        # Snapshot por página de entrada, sem confundir duas SPAs no mesmo host.
        previous = baseline.get(host, {}).get(key)
        visit.update(compare(previous, current))
        visit["coverage"] = current["coverage"]
        # Não substituir baseline completo por coleta truncada/erro de bundles.
        if current["coverage"].get("status") == "collected":
            updates.setdefault(host, {})[key] = current
        else:
            visit["baseline_advanced"] = False
        report["revisits"].append(visit)
    # Somente registros permitidos pelo contrato entram no corpus.
    records = [normalize_record(row) for row in records]
    records_path = scratch / "perola-negra-records.json"
    atomic_write_text(records_path, json.dumps({"program_id": a.program, "records": records}, ensure_ascii=False, indent=2) + "\n")
    if records:
        rc, _ = run_tool(["endpoints.py", "merge", a.program, "--input", str(records_path),
                          "--source", "perola-negra", "--data-dir", a.data_dir, "--session", _SESSION])
        if rc:
            raise ValueError("merge do corpus falhou; snapshot não será avançado")
    if updates:
        with locked_file(snapshot_path):
            latest = load_snapshot(snapshot_path)
            for host, pages in updates.items():
                latest.setdefault(host, {}).update(pages)
            save_snapshot(snapshot_path, a.program, latest, data_dir=a.data_dir, contribute_hosts=updates, session=_SESSION)
    report["record_count"] = len(records)
    report["status"] = "partial" if (report["deferred_urls"] or
        any(v["status"] in {"failed", "blocked-without-receipt"} or v.get("coverage", {}).get("status") != "collected"
            for v in report["revisits"]) or any(b.get("invalid") or b.get("filtered_without_receipt") or b.get("network_failures") or b.get("requests_pending") for b in report["browser"])) else "collected"
    atomic_write_text(scratch / "perola-negra-coverage.json", json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    write_coverage(Path(a.data_dir), a.program, report, session=_SESSION)
    print(f"Pérola negra: {len(records)} registros; {len(report['revisits'])} revisitas; cobertura {report['status']}.")
    print(f"Contribuições locais: {notes}\nScratch sanitizado: {scratch}\nPublicação pendente: entregar a writer → ingestão → read-back.")
    return 1 if report["status"] == "partial" else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ImportError:
        print("CDP requer Playwright; HAR e revisita usam stdlib. Veja docs/RECON-AMPLIADO.md.", file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("Pérola negra falhou; confira os arquivos/formatos. Dados crus omitidos; publicação não confirmada.", file=sys.stderr)
        sys.exit(2)
