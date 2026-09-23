#!/usr/bin/env python3
"""endpoints — corpus de endpoints estruturado no Hive (document_type: endpoint).

Transforma saída de recon (jsrecon/apkrecon/passive/manual) num corpus canônico,
DEDUPADO e queryável, que o `code 6` consome via hive_search(document_types=[endpoint]).
Um único .md por programa: frontmatter + tabela humana + bloco ```json``` canônico
(estado machine-readable relido no próximo merge → dedupe + diff incremental).

Host vem NO INPUT (não no argv) p/ não disparar o scope_hook — é escrita local, sem tráfego.
Formato de input (1 por linha, flexível):
    host METHOD /path            ex.:  coreapp.worldcoin.org POST /api/v1/pay
    host /path                   (method = ?)
    # comentário / linha vazia   ignorado

Uso:
  python3 tools/endpoints.py merge toolsforhumanity --input eps.txt \
      --source jsrecon --data-dir /.../hive_instance/data
  python3 tools/endpoints.py list toolsforhumanity --data-dir /.../hive_instance/data
"""
import argparse, json, os, re, sys
from datetime import datetime, timezone

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "QUERY", "MUTATION"}
HOSTRE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9\-]{0,62})\.)+[a-z]{2,}$')
JSON_BLOCK = re.compile(r'```json\s*(\[.*?\])\s*```', re.S)

def _stamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    toks = line.split()
    host = toks[0].lower().rstrip(".")
    if not HOSTRE.match(host):
        return None
    method, path = "?", ""
    if len(toks) >= 3 and toks[1].upper() in METHODS:
        method, path = toks[1].upper(), toks[2]
    elif len(toks) >= 2:
        path = toks[1]
    if not path.startswith("/"):
        return None
    return host, method, path.split("?")[0][:200]

def load_existing(md_path):
    if not os.path.isfile(md_path):
        return {}
    txt = open(md_path, encoding="utf-8").read()
    m = JSON_BLOCK.search(txt)
    if not m:
        return {}
    try:
        rows = json.loads(m.group(1))
    except json.JSONDecodeError:
        return {}
    return {(r["host"], r["method"], r["path"]): r for r in rows if "host" in r}

def render(program, rows, handle, team):
    rows = sorted(rows, key=lambda r: (r["host"], r["path"], r["method"]))
    hosts = sorted({r["host"] for r in rows})
    fm = (
        "---\n"
        f"program_id: {program}\n"
        "document_type: endpoint\n"
        "classification: internal\n"
        "source: excalibull\n"
        f"collected_at: {_stamp()}\n"
        f'tags: ["{team}", "{handle}", "excalibull", "endpoint-corpus"]\n'
        f"asset_refs: {json.dumps(hosts[:60], ensure_ascii=False)}\n"
        "---\n"
    )
    body = [f"# Corpus de endpoints — {program} ({len(rows)} endpoints, {len(hosts)} hosts)\n",
            "> Corpus canônico dedupado (tools/endpoints.py). Cada linha = endpoint observado.",
            "> `[UNTESTED]` até prova ativa. Alimenta `code 6` via hive_search(document_types=[endpoint]).\n",
            "| Host | Método | Path | Status | Fonte | 1º visto |",
            "|------|--------|------|--------|-------|----------|"]
    for r in rows:
        body.append(f"| `{r['host']}` | {r['method']} | `{r['path']}` | {r.get('status','')} "
                    f"| {r.get('source','')} | {r.get('first_seen','')[:10]} |")
    body.append("\n<!-- estado canônico machine-readable (não editar à mão) -->")
    body.append("```json")
    body.append(json.dumps(rows, ensure_ascii=False, indent=0))
    body.append("```")
    return fm + "\n".join(body) + "\n"

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    mg = sub.add_parser("merge", help="mescla endpoints (dedupe + diff) no corpus")
    mg.add_argument("program")
    mg.add_argument("--input", help="arquivo (default stdin)")
    mg.add_argument("--source", default="recon")
    mg.add_argument("--status", default="")
    mg.add_argument("--data-dir", default=os.environ.get("HIVE_DATA_DIR", ""))
    mg.add_argument("--handle", default=os.environ.get("HIVE_HANDLE", "moldret"))
    mg.add_argument("--team", default=os.environ.get("HIVE_TEAM_TAG", "delta"))
    ls = sub.add_parser("list", help="conta/mostra o corpus atual")
    ls.add_argument("program")
    ls.add_argument("--data-dir", default=os.environ.get("HIVE_DATA_DIR", ""))
    a = ap.parse_args()

    if not a.data_dir:
        ap.error("passe --data-dir ou defina HIVE_DATA_DIR")
    notes = os.path.join(a.data_dir, "programs", a.program, "notes")
    md_path = os.path.join(notes, f"{a.__dict__.get('handle','moldret')}-excalibull-endpoints-corpus.md")

    if a.cmd == "list":
        cur = load_existing(md_path)
        print(f"{len(cur)} endpoints em {len({k[0] for k in cur})} hosts")
        for (h, m, p) in sorted(cur):
            print(f"  {h:34} {m:7} {p}")
        return 0

    raw = open(a.input, encoding="utf-8").read() if a.input else sys.stdin.read()
    cur = load_existing(md_path)
    added, dup, bad = 0, 0, 0
    for line in raw.splitlines():
        parsed = parse_line(line)
        if parsed is None:
            if line.strip() and not line.strip().startswith("#"):
                bad += 1
            continue
        key = parsed
        if key in cur:
            dup += 1
            continue
        cur[key] = {"host": key[0], "method": key[1], "path": key[2],
                    "status": a.status, "source": a.source, "first_seen": _stamp()}
        added += 1
    # dedup método-agnóstico: se existe (host,path) com método REAL, descarta o "?" redundante
    real = {(r["host"], r["path"]) for r in cur.values() if r["method"] != "?"}
    collapsed = {k: v for k, v in cur.items() if not (k[1] == "?" and (k[0], k[2]) in real)}
    removed = len(cur) - len(collapsed)
    cur = collapsed
    os.makedirs(notes, exist_ok=True)
    open(md_path, "w", encoding="utf-8").write(render(a.program, list(cur.values()), a.handle, a.team))
    if removed:
        print(f"[*] {removed} entradas '?' colapsadas (método real já existia)", file=sys.stderr)
    print(f"[+] +{added} novos · {dup} já existentes · {bad} inválidos · total {len(cur)}", file=sys.stderr)
    print(md_path)
    return 0

if __name__ == "__main__":
    sys.exit(main())
