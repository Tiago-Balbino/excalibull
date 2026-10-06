#!/usr/bin/env python3
"""Importa HAR offline ou observa tráfego de um Chromium aberto via CDP local.

Não navega, reproduz ou muta requests. O operador conduz o navegador e escolhe
contas/fluxos autorizados. Saída contém somente estrutura sanitizada; HAR bruto
e perfil autenticado permanecem fora do Hive/repo. Playwright é opcional.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from file_safety import atomic_write_text
from hive_scope_cache import authorization_for
from hive_workspace import _program
from recon_records import request_record


def authorized(url, program):
    receipt = authorization_for(url, program_id=program)
    return bool(receipt and receipt.get("program_id") == program
                and receipt.get("confirmed") is True and receipt.get("status") == "authorized"
                and receipt.get("action_allowed") is True)


def read_har(path, role="unknown", flow="unknown"):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    records, invalid = [], 0
    entries = data.get("log", {}).get("entries")
    if not isinstance(entries, list):
        raise ValueError("HAR sem log.entries")
    for entry in entries:
        try:
            req = entry["request"]
            post = req.get("postData") or {}
            records.append(request_record(
                req["url"], req.get("method", "?"),
                {h["name"]: h.get("value", "") for h in req.get("headers", [])},
                post.get("text"), post.get("mimeType", ""), role, flow, "browser-har",
                entry.get("response", {}).get("status"),
                [p["name"] for p in req.get("queryString", [])],
                [p["name"] for p in post.get("params", [])]))
        except (ValueError, TypeError, KeyError):
            invalid += 1
    return records, {"mode": "har", "entries": len(entries), "invalid": invalid,
                     "coverage": "observed-only", "credential_values_saved": False}


def observe_cdp(endpoint, program, seconds, role, flow):
    parsed = urlsplit(endpoint)
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"} or parsed.username or parsed.password:
        raise ValueError("CDP deve ser HTTP local, sem credenciais na URL")
    from playwright.sync_api import sync_playwright

    records, filtered, failed = [], [], []
    observed, completed, network_failures = {}, set(), []
    with sync_playwright() as pw:
        browser = pw.chromium.connect_over_cdp(endpoint)
        def request(req):
            try:
                if not authorized(req.url, program):
                    filtered.append(True)
                    return
                record = request_record(req.url, req.method, req.all_headers(),
                                        req.post_data, role=role, flow=flow, source="browser-cdp")
                observed[req] = record
                records.append(record)
            except (ValueError, TypeError, KeyError):
                failed.append(True)
        def response(resp):
            if resp.request in observed:
                observed[resp.request]["response_status"] = resp.status
                completed.add(resp.request)
        def request_failed(req):
            if req in observed:
                network_failures.append(True)
                completed.add(req)
        contexts = list(browser.contexts)
        if not contexts:
            raise ValueError("nenhum contexto de navegador aberto")
        for ctx in contexts:
            ctx.on("request", request)
            ctx.on("response", response)
            ctx.on("requestfailed", request_failed)
        print("Observando a sessão; navegue manualmente nas contas/fluxos autorizados.", file=sys.stderr)
        # Bombeia eventos sem navegar/criar página/alterar sessão.
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            pages = [page for ctx in contexts for page in ctx.pages if not page.is_closed()]
            if not pages:
                break
            pages[0].wait_for_timeout(min(250, max(1, (deadline - time.monotonic()) * 1000)))
        for ctx in contexts:
            ctx.remove_listener("request", request)
            ctx.remove_listener("response", response)
            ctx.remove_listener("requestfailed", request_failed)
        # A saída de sync_playwright desconecta; não fecha o navegador do operador.
    return records, {"mode": "cdp-observer", "filtered_without_receipt": len(filtered),
                     "invalid": len(failed), "coverage": "observed-only",
                     "requests_pending": len(set(observed) - completed), "network_failures": len(network_failures),
                     "credential_values_saved": False}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("program", type=_program)
    sources = ap.add_mutually_exclusive_group(required=True)
    sources.add_argument("--har")
    sources.add_argument("--cdp", help="endpoint local do Chromium já aberto pelo operador")
    ap.add_argument("--seconds", type=float, default=120)
    ap.add_argument("--role", default="unknown", help="alias de papel, sem nome/e-mail da conta")
    ap.add_argument("--flow", default="unknown", help="alias do fluxo, ex.: checkout")
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    if not 0 < a.seconds <= 3600:
        ap.error("--seconds deve estar entre 0 e 3600")
    try:
        records, coverage = (read_har(a.har, a.role, a.flow) if a.har else
                             observe_cdp(a.cdp, a.program, a.seconds, a.role, a.flow))
        atomic_write_text(Path(a.output), json.dumps({"program_id": a.program,
                          "records": records, "coverage": coverage}, ensure_ascii=False, indent=2) + "\n")
    except ImportError:
        print("CDP requer Playwright. Instale conforme docs/RECON-AMPLIADO.md; HAR usa só stdlib.", file=sys.stderr)
        return 2
    except Exception:
        print("Falha na captura/importação; verifique formato, CDP e arquivos (dados crus omitidos).", file=sys.stderr)
        return 2
    print(f"{len(records)} requisições estruturadas; saída sanitizada: {a.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
