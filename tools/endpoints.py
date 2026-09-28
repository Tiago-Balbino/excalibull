#!/usr/bin/env python3
"""endpoints — corpus de endpoints estruturado no Hive (document_type: endpoint).

Transforma saída de recon (jsrecon/apkrecon/passive/manual) num corpus canônico,
DEDUPADO e queryável via hive_search(document_types=[endpoint]).
Um único .md por programa: frontmatter + tabela humana + bloco ```json``` canônico
(estado machine-readable relido no próximo merge → dedupe + diff incremental).

Host vem NO INPUT (não no argv) p/ não disparar o scope_hook — é escrita local, sem tráfego.
Formato de input (1 por linha, flexível):
    host METHOD /path            ex.:  coreapp.worldcoin.org POST /api/v1/pay
    host /path                   (method = ?)
    JSON {records: [...]}        métodos, nomes/tipos de parâmetros e contextos
    # comentário / linha vazia   ignorado

Uso:
  python3 tools/endpoints.py merge toolsforhumanity --input eps.txt \
      --source jsrecon --data-dir /.../hive_instance/data
  python3 tools/endpoints.py list toolsforhumanity --data-dir /.../hive_instance/data
"""
import argparse, json, os, re, sys
from datetime import datetime, timezone
from pathlib import Path
from file_safety import atomic_write_text, locked_file
from hive_workspace import _program, resolve_data_dir
from recon_records import normalize_record, request_record, METHODS

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
    return host, method, request_record(f"https://{host}{path}", method)["path"]


def read_records(raw):
    """Compatibilidade com texto antigo e JSON estruturado do browser/saquear."""
    if raw.lstrip().startswith(("{", "[")):
        data = json.loads(raw)
        rows = data.get("records") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            raise ValueError("JSON deve conter lista records")
        return [normalize_record(row) for row in rows], 0
    rows, bad = [], 0
    for line in raw.splitlines():
        parsed = parse_line(line)
        if parsed:
            toks = line.split()
            path = toks[2] if len(toks) >= 3 and toks[1].upper() in METHODS else toks[1]
            rows.append(request_record(f"https://{parsed[0]}{path}", parsed[1]))
        elif line.strip() and not line.strip().startswith("#"):
            bad += 1
    return rows, bad

def load_existing(md_path):
    if not os.path.isfile(md_path):
        return {}
    txt = open(md_path, encoding="utf-8").read()
    m = JSON_BLOCK.search(txt)
    if not m:
        raise ValueError("corpus existente sem estado JSON; merge recusado")
    rows = json.loads(m.group(1))
    if not isinstance(rows, list) or any(not isinstance(r, dict) or
            not {"host", "method", "path"} <= r.keys() for r in rows):
        raise ValueError("corpus com linhas inválidas; merge recusado")
    return {(r["host"], r["method"], r["path"]): r for r in rows}

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
            "> `[UNTESTED]` até prova ativa. Contexto observado não comprova autenticação ou vulnerabilidade.\n",
            "| Host | Método | Path | Parâmetros query | Contextos | Status | Fonte | 1º visto |",
            "|------|--------|------|------------------|-----------|--------|-------|----------|"]
    for r in rows:
        query = sorted({p for ob in r.get('observations', []) for p in ob.get('query_params', [])})
        roles = sorted({ob.get('access_context', {}).get('role', 'unknown') for ob in r.get('observations', [])})
        body.append(f"| `{r['host']}` | {r['method']} | `{r['path']}` | {', '.join(query)} | {', '.join(roles)} | {r.get('status','')} "
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
    mg.add_argument("program", type=_program)
    mg.add_argument("--input", help="arquivo (default stdin)")
    mg.add_argument("--source", default="recon")
    mg.add_argument("--status", default="")
    mg.add_argument("--data-dir", default=os.environ.get("HIVE_DATA_DIR", ""))
    mg.add_argument("--handle", type=_program, default=os.environ.get("HIVE_HANDLE", "moldret"))
    mg.add_argument("--team", type=_program, default=os.environ.get("HIVE_TEAM_TAG", "delta"))
    ls = sub.add_parser("list", help="conta/mostra o corpus atual")
    ls.add_argument("program", type=_program)
    ls.add_argument("--data-dir", default=os.environ.get("HIVE_DATA_DIR", ""))
    a = ap.parse_args()

    try:
        a.data_dir = str(resolve_data_dir(a.data_dir or None, writer=a.cmd == "merge"))
    except ValueError as exc:
        ap.error(str(exc))
    notes = os.path.join(a.data_dir, "programs", a.program, "notes")
    md_path = os.path.join(notes, f"{a.__dict__.get('handle','moldret')}-excalibull-endpoints-corpus.md")

    if a.cmd == "list":
        cur = load_existing(md_path)
        print(f"{len(cur)} endpoints em {len({k[0] for k in cur})} hosts")
        for (h, m, p) in sorted(cur):
            print(f"  {h:34} {m:7} {p}")
        return 0

    raw = open(a.input, encoding="utf-8").read() if a.input else sys.stdin.read()
    if raw.lstrip().startswith("{"):
        envelope = json.loads(raw)
        if envelope.get("program_id") not in (None, a.program):
            raise ValueError("program_id do input difere do programa selecionado")
    records, bad = read_records(raw)
    # Falha no corpus/input não pode apagar o estado anterior. Serializa escritores.
    with locked_file(Path(md_path)):
        cur = load_existing(md_path)
        added, dup = 0, 0
        for record in records:
            key = record['host'], record['method'], record['path']
            if key in cur:
                dup += 1
            else:
                cur[key] = {"host": key[0], "method": key[1], "path": key[2],
                            "status": a.status, "source": a.source, "first_seen": _stamp()}
                added += 1
            row = cur[key]
            observations = row.setdefault('observations', [])
            if record not in observations:
                observations.append(record)
            row['last_seen'] = _stamp()
        # Método desconhecido permanece: não perder observações ao encontrar outro método.
        atomic_write_text(Path(md_path), render(a.program, list(cur.values()), a.handle, a.team))
    print(f"[+] +{added} novos · {dup} já existentes · {bad} inválidos · total {len(cur)}", file=sys.stderr)
    print(md_path)
    return 0

if __name__ == "__main__":
    sys.exit(main())
