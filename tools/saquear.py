#!/usr/bin/env python3
"""Saquear o navio: recon web médio/completo, JS e auditoria CORS/headers opcional.

Tráfego autenticado e revisitas com diff pertencem ao pérola negra.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from browser_recon import authorized
from file_safety import atomic_write_text
from hive_paths import workspace
from hive_workspace import _program
from hive_documents import identity
from hive_outbox import Outbox, prepare
from recon_records import normalize_record
from session_monitor import tool_metric

ROOT = Path(__file__).resolve().parent
_PROGRAM = None
_SESSION = None


def run(cmd, timeout=300):
    started = time.monotonic()
    env = os.environ.copy()
    if _SESSION:
        env["EXCALIBULL_SESSION_ID"] = _SESSION
    try:
        r = subprocess.run([sys.executable, str(ROOT / cmd[0]), *cmd[1:]],
                           capture_output=True, text=True, timeout=timeout, env=env)
        tool_metric(cmd[0], time.monotonic() - started, r.returncode == 0, _PROGRAM)
        return r.stdout, r.stderr, r.returncode
    except (OSError, subprocess.TimeoutExpired):
        tool_metric(cmd[0], time.monotonic() - started, False, _PROGRAM)
        return "", "falha/timeout da ferramenta", 2


def parse_json(out):
    try:
        result = json.loads(out)
        return result if isinstance(result, dict) else None
    except (ValueError, TypeError):
        return None


def new_hosts_from_passive(data):
    return list((data or {}).get("delta_prod") or [])


def inventory_from_passive(data):
    """Inventário por ativo (prod E não-prod) com ambiente, fontes e escopo.

    Preserva ambientes não-produtivos em vez de reduzi-los a um contador. Nenhum
    item aqui autoriza tráfego: `probe_authorization` fica pendente por ativo e
    cada URL exige hive_get_context ao vivo antes de sondar.
    """
    return [a for a in ((data or {}).get("inventory") or []) if isinstance(a, dict)]


def endpoints_from_jsrecon(host, data):
    eps = [p for p in (data or {}).get("api_endpoints", []) if isinstance(p, str) and p.startswith("/")]
    return [f"{host} {p}" for p in eps]


def stacks_from_jsrecon(data):
    return [fp for fp in (data or {}).get("fingerprints", []) if isinstance(fp, dict) and fp.get("name")]


def main():
    global _PROGRAM, _SESSION
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("program", type=_program)
    ap.add_argument("--domains", default="", help="CSV para fontes de terceiros")
    ap.add_argument("--spa-hosts", "--hosts", dest="spa_hosts", default="", help="hosts explícitos")
    ap.add_argument("--url", action="append", default=[])
    ap.add_argument("--level", choices=["medium", "full"], default="medium")
    ap.add_argument("--cors", action="store_true", help="auditar CORS/headers dos URLs explícitos")
    ap.add_argument("--skip-crawl", action="store_true")
    ap.add_argument("--skip-js", action="store_true")
    ap.add_argument("--max-pages", type=int)
    ap.add_argument("--max-js", type=int, default=40)
    ap.add_argument("--rate", type=float, default=1)
    ap.add_argument("--data-dir")
    ap.add_argument("--scratch")
    ap.add_argument("--session")
    a = ap.parse_args()
    _PROGRAM = a.program
    if a.max_js < 0 or a.rate <= 0 or (a.max_pages is not None and a.max_pages < 1):
        ap.error("limites inválidos")
    if not (a.domains or a.spa_hosts or a.url):
        ap.error("informe domínios passivos ou hosts/URLs explícitos")
    info = workspace(a.data_dir)
    data_dir = info["data_dir"]
    identity()
    _SESSION = Outbox(data_dir).session(a.program, a.session, create=True)
    scratch = Path(a.scratch or tempfile.mkdtemp(prefix="saque_"))
    scratch.mkdir(parents=True, exist_ok=True)
    report = {"program_id": a.program, "protocol": "saquear-o-navio", "level": a.level,
              "steps": [], "publication": "pending-writer"}
    records = []
    if a.domains:
        out, _, rc = run(["passive.py", *[d.strip() for d in a.domains.split(",") if d.strip()],
                          "--diff-program", a.program, "--data-dir", data_dir, "--json"])
        data = parse_json(out)
        atomic_write_text(scratch / "passive.json", json.dumps(data or {}, ensure_ascii=False, indent=2))
        errors = any(str(s.get("status", "")).lower().startswith(("err", "timeout", "fail")) for s in (data or {}).get("sources", []))
        inventory = inventory_from_passive(data)
        report["steps"].append({"step": "passive", "status": "partial" if rc or data is None or errors else "collected",
                                "new_hosts": new_hosts_from_passive(data),
                                "observed_prod": (data or {}).get("prod", []),
                                "observed_nonprod": (data or {}).get("nonprod", []),
                                "new_nonprod_hosts": (data or {}).get("delta_nonprod") or [],
                                "new_nonprod_count": len((data or {}).get("delta_nonprod") or []),
                                "inventory": inventory,
                                "inventory_count": len(inventory),
                                "probe_authorization": "pending-per-asset",
                                "note": "inventário passivo (prod+não-prod) preservado; sondar exige hive_get_context por ativo",
                                "baseline_coverage": "local-only"})
    urls = list(dict.fromkeys(a.url + [f"https://{h.strip()}/" for h in a.spa_hosts.split(",") if h.strip()]))
    for index, url in enumerate(urls):
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            ap.error("URL HTTP(S) sem credenciais necessária")
        host = parsed.hostname.lower()
        if not authorized(url, a.program):
            report["steps"].append({"step": "authorization", "host": host, "status": "blocked"})
            continue
        if not a.skip_crawl:
            cmd = ["active_recon.py", a.program, url, "--level", a.level, "--rate", str(a.rate)]
            if a.max_pages is not None:
                cmd += ["--max-pages", str(a.max_pages)]
            out, _, rc = run(cmd, 600)
            data = parse_json(out)
            if data:
                records.extend(data.get("records", []))
            report["steps"].append({"step": "crawl", "host": host,
                                    "status": (data or {}).get("coverage", {}).get("status", "failed") if rc in (0, 1) else "failed",
                                    "coverage": (data or {}).get("coverage", {})})
        if not a.skip_js:
            out, _, rc = run(["jsrecon.py", url, "--program", a.program, "--max-js", str(a.max_js),
                              "--rate", str(a.rate), "--json"], 600)
            data = parse_json(out)
            if data and rc == 0:
                records.extend(data.get("records", []))
            report["steps"].append({"step": "js", "host": host,
                                    "status": (data or {}).get("coverage", {}).get("status", "failed") if rc == 0 else "failed",
                                    "coverage": (data or {}).get("coverage", {}),
                                    "stacks": [fp["name"] for fp in stacks_from_jsrecon(data)]})
        if a.cors:
            target = scratch / f"cors-{index}.json"
            _, _, rc = run(["cors_headers_scan.py", url, "--program", a.program, "--rate", str(a.rate),
                            "--workers", "1", "--json", str(target)], 300)
            report["steps"].append({"step": "cors-headers", "host": host, "status": "collected" if rc == 0 else "partial"})
    records = [normalize_record(r) for r in records]
    epf = scratch / "endpoints.json"
    atomic_write_text(epf, json.dumps({"program_id": a.program, "records": records}, ensure_ascii=False, indent=2))
    if records:
        _, _, rc = run(["endpoints.py", "merge", a.program, "--input", str(epf), "--source", "saquear", "--data-dir", data_dir,
                        "--session", _SESSION], 60)
        report["steps"].append({"step": "merge", "status": "written" if rc == 0 else "failed"})
    report["record_count"] = len(records)
    report["status"] = "partial" if any(s["status"] not in ("collected", "written") for s in report["steps"]) else "collected"
    atomic_write_text(scratch / "saquear-coverage.json", json.dumps(report, ensure_ascii=False, indent=2))
    prepare(a.program, "saquear-coverage", "# Saquear o navio — cobertura\n\n~~~json\n" +
            json.dumps(report, ensure_ascii=False, indent=2) + "\n~~~\n", data_dir=data_dir, session=_SESSION,
            assets=sorted({urlsplit(u).hostname for u in urls}), tags=["recon-coverage"])
    print(f"Saquear o navio: {len(records)} registros; coleta {report['status']}.")
    print("Desenvolver sinais pelos protocolos; entregar a writer → ingerir → idle → read-back. Publicação pendente.")
    return 1 if report["status"] == "partial" else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError):
        print("Saquear falhou; confira configuração/artefatos. Publicação pendente.", file=sys.stderr)
        sys.exit(2)
