#!/usr/bin/env python3
"""Recibos Hive em lote para URLs exatas + linha de curl pronta. NÃO emite tráfego ao alvo.

Uma única sessão MCP pede `hive_get_context` (url_prefix exato) por URL e materializa
cada veredito com `record_context`. O tráfego continua fora desta ferramenta: ela só
imprime os pares `-o <nome> <url>` para colar num comando curl visível ao scope_hook.

Atenção: um contexto negado/inválido dispara `invalidate()` no gateway e apaga TODOS os
recibos vigentes. Por isso a execução para no primeiro negado e reporta quais URLs
precisam sair da lista antes de repetir.

Uso:
  hive_batch_receipts.py <program> --urls arquivo.txt [--question "..."] [--curl-out args.txt]
  hive_batch_receipts.py <program> --hosts a.ex.com,b.ex.com --paths /,/robots.txt
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_QUESTION = "recon não destrutivo (GET) sem conta, sob postura do operador"


def build_urls(urls_file=None, hosts=None, paths=None):
    urls = []
    if urls_file:
        urls += [line.strip() for line in Path(urls_file).read_text(encoding="utf-8").splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
    if hosts:
        for host in [h.strip() for h in hosts.split(",") if h.strip()]:
            for path in (paths or "/").split(","):
                path = path.strip() or "/"
                urls.append(f"https://{host}{path if path.startswith('/') else '/' + path}")
    out = []
    for url in dict.fromkeys(urls):
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError(f"URL inválida (precisa http(s), host e sem credenciais): {url}")
        if parsed.query or parsed.fragment or "@" in parsed.netloc:
            raise ValueError(f"URL com query/fragmento não é suportada pelo recibo; use o caminho base: {url}")
        out.append(url)
    return out


def output_name(url, prefix="o_"):
    parsed = urlsplit(url)
    raw = (parsed.hostname or "") + (parsed.path or "/")
    return prefix + (re.sub(r"[^A-Za-z0-9]+", "_", raw).strip("_")[-80:] or "root")


def curl_pairs(urls, prefix="o_"):
    seen, pairs = set(), []
    for url in urls:
        name = output_name(url, prefix)
        while name in seen:
            name += "_"
        seen.add(name)
        pairs.append(f"-o {name} {url}")
    return " ".join(pairs)


def run(program, urls, question, client_factory=None, recorder=None):
    if client_factory is None:
        from hive_gateway import HiveClient as client_factory  # noqa: N813
    if recorder is None:
        from hive_scope_cache import record_context as recorder
    allowed, report = [], []
    with client_factory() as client:
        for url in urls:
            try:
                result = client.context(program, {"type": "url_prefix", "value": url}, question)
            except Exception as exc:  # gateway já invalidou o cache
                report.append({"url": url, "verdict": "error", "detail": str(exc)[:200]})
                return allowed, report, "stopped"
            scope = result.get("scope", {}) if isinstance(result, dict) else {}
            ok = scope.get("confirmed") is True and scope.get("status") == "authorized" and scope.get("action_allowed") is True
            if not ok:
                report.append({"url": url, "verdict": "denied", "status": scope.get("status")})
                return allowed, report, "stopped"
            recorder(result)
            allowed.append(url)
            report.append({"url": url, "verdict": "authorized"})
    return allowed, report, "complete"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("program")
    ap.add_argument("--urls", help="arquivo com uma URL exata por linha")
    ap.add_argument("--hosts", help="CSV de hosts (combinado com --paths)")
    ap.add_argument("--paths", default="/", help="CSV de caminhos para cada host")
    ap.add_argument("--question", default=DEFAULT_QUESTION)
    ap.add_argument("--prefix", default="o_", help="prefixo dos arquivos de saída do curl")
    ap.add_argument("--curl-out", help="grava os pares -o/URL neste arquivo")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        urls = build_urls(a.urls, a.hosts, a.paths)
    except (OSError, ValueError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2
    if not urls:
        print("ERRO: nenhuma URL", file=sys.stderr)
        return 2
    allowed, report, state = run(a.program, urls, a.question)
    pairs = curl_pairs(allowed, a.prefix) if state == "complete" else ""
    if a.curl_out and pairs:
        Path(a.curl_out).write_text(pairs + "\n", encoding="utf-8")
    if a.json:
        print(json.dumps({"program_id": a.program, "state": state, "requested": len(urls),
                          "authorized": len(allowed), "report": report}, ensure_ascii=False, indent=2))
    else:
        print(f"{state}: {len(allowed)}/{len(urls)} recibos")
        for r in report:
            if r["verdict"] != "authorized":
                print(f"  PARADA em {r['url']}: {r['verdict']} {r.get('status') or r.get('detail', '')}")
                print("  (recibos anteriores foram invalidados pelo gateway; remova a URL e repita)")
        if pairs:
            print("Pares para o curl (cole na linha de comando, sem ';' depois da última URL):")
            print(pairs)
    return 0 if state == "complete" else 1


if __name__ == "__main__":
    sys.exit(main())
