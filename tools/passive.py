#!/usr/bin/env python3
"""passive — agregador de recon PASSIVO (só fontes de terceiros) + diff vs staging local.

Junta subdomínios/hosts de várias fontes que NÃO tocam o alvo, dedupe, filtra por
escopo, sinaliza não-produção, e compara com as observações do staging local (cobertura parcial) pra imprimir só o DELTA novo. Alimenta o `achar o x` sem recibo.

A saída `--json` traz `inventory`: um item por ativo no escopo (prod E não-prod
preservados), com `environment` (rótulo provável pelo nome), `sources`
(proveniência agregada), `in_scope`, `new` (ausente no staging local; None sem
`--diff-program`) e `probe_authorization: pending-per-asset`. Nenhum item autoriza
tráfego: sondar qualquer URL exige `hive_get_context` ao vivo para o ativo exato.

Fontes sem chave: crt.sh, AlienVault OTX, HackerTarget, urlscan.io, Wayback/CDX.
Com chave (env, opcional): VirusTotal (VT_API_KEY), SecurityTrails (STRAILS_API_KEY),
Shodan (SHODAN_API_KEY). Ausência de chave = fonte pulada (nunca hardcode).

Uso:
  python3 tools/passive.py worldcoin.org world.org --diff-program toolsforhumanity \
      --data-dir /caminho/excalibull-outbox
  python3 tools/passive.py exemplo.com          # sem diff, só agrega
"""
import argparse, base64, gzip, hashlib, io, json, os, re, sys, time, urllib.request, urllib.error
import concurrent.futures as _cf
from pathlib import Path
from urllib.parse import urlparse, quote

_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)
from extract import DEFAULT_UA  # noqa: E402  (UA único do projeto)

UA = DEFAULT_UA
NONPROD = re.compile(r'(^|[.\-])(staging|stage|dev|development|test|testing|qa|uat|sandbox|'
                     r'internal|preview|canary|demo|sepolia|devnet|testnet|e2e|local)([.\-]|$)', re.I)
HOSTRE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9\-]{0,62})\.)+[a-z]{2,}$')

# Sinônimos → rótulo canônico de ambiente. Só sinaliza ambiente provável pelo nome;
# não é prova de função real nem autoriza sondar o ativo.
ENV_CANON = {
    "stage": "staging", "staging": "staging",
    "dev": "dev", "development": "dev", "devnet": "dev",
    "test": "test", "testing": "test", "e2e": "test",
    "qa": "qa", "uat": "uat", "sandbox": "sandbox", "internal": "internal",
    "preview": "preview", "canary": "canary", "demo": "demo",
    "sepolia": "testnet", "testnet": "testnet", "local": "local",
}


def classify_env(host):
    """Rótulo de ambiente provável pelo nome do host; 'prod' quando nenhum marcador casa.

    Heurística sobre o hostname, não observação de comportamento. Preserva o
    ambiente no inventário; a decisão de sondar continua por ativo, ao vivo.
    """
    m = NONPROD.search(host or "")
    return ENV_CANON.get(m.group(2).lower(), m.group(2).lower()) if m else "prod"

# Cache entre runs por (fonte, domínio). .hive/ é gitignored (efêmero).
CACHE_DIR = Path(_TOOLS_DIR).parent / ".hive" / "passive-cache"


def _cache_path(name, d):
    key = hashlib.sha1(f"{name}|{d}".encode()).hexdigest()[:16]
    return CACHE_DIR / f"{name}-{key}.json"


def _cache_get(name, d, ttl):
    if ttl <= 0:
        return None
    p = _cache_path(name, d)
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if time.time() - obj.get("ts", 0) > ttl:
        return None
    return obj


def _cache_put(name, d, hosts, urls, status):
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(name, d).write_text(json.dumps({
            "ts": time.time(), "status": status,
            "hosts": sorted(hosts), "urls": sorted(urls),
        }), encoding="utf-8")
    except OSError:
        pass

def fetch(url, timeout=25, headers=None):
    h = {"User-Agent": UA, "Accept-Encoding": "gzip"}
    if headers:
        h.update(headers)
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
            raw = r.read()
            if r.headers.get("Content-Encoding") == "gzip":
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
            return raw.decode("utf-8", "replace")
    except Exception as e:
        return f"__ERR__:{type(e).__name__}"

def clean(host):
    host = (host or "").strip().lower().lstrip("*.").rstrip(".")
    host = host.split("/")[0].split("@")[-1].split(":")[0]
    return host if HOSTRE.match(host) else ""

# ---- fontes (cada uma retorna set de hosts) ----
def src_crtsh(d):
    out = set(); t = fetch(f"https://crt.sh/?q=%25.{d}&output=json", timeout=45)
    if t.startswith("__ERR__"): return out, t
    try:
        for row in json.loads(t):
            for v in str(row.get("name_value", "")).splitlines():
                c = clean(v)
                if c: out.add(c)
    except Exception as e:
        return out, f"parse:{e}"
    return out, "ok"

def src_otx(d):
    out = set(); t = fetch(f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns")
    if t.startswith("__ERR__"): return out, t
    try:
        for r in json.loads(t).get("passive_dns", []):
            c = clean(r.get("hostname", ""))
            if c: out.add(c)
    except Exception as e:
        return out, f"parse:{e}"
    return out, "ok"

def src_hackertarget(d):
    out = set(); t = fetch(f"https://api.hackertarget.com/hostsearch/?q={d}")
    if t.startswith("__ERR__") or "API count exceeded" in t or "error" in t.lower():
        return out, t[:40]
    for line in t.splitlines():
        c = clean(line.split(",")[0])
        if c: out.add(c)
    return out, "ok"

def src_urlscan(d):
    out = set(); urls = set()
    t = fetch(f"https://urlscan.io/api/v1/search/?q=domain:{d}&size=1000")
    if t.startswith("__ERR__"): return out, urls, t
    try:
        for r in json.loads(t).get("results", []):
            c = clean((r.get("page") or {}).get("domain", ""))
            if c: out.add(c)
            u = (r.get("task") or {}).get("url") or (r.get("page") or {}).get("url")
            if u: urls.add(u.split("?")[0])
    except Exception as e:
        return out, urls, f"parse:{e}"
    return out, urls, "ok"

def src_wayback(d):
    out = set(); urls = set()
    t = fetch(f"http://web.archive.org/cdx/search/cdx?url=*.{d}/*&output=json"
              f"&fl=original&collapse=urlkey&limit=2000", timeout=45)
    if t.startswith("__ERR__"): return out, urls, t
    try:
        rows = json.loads(t)
        for row in rows[1:] if rows and rows[0] == ["original"] else rows:
            u = row[0] if isinstance(row, list) else row
            urls.add(u.split("?")[0])
            c = clean(urlparse(u).netloc)
            if c: out.add(c)
    except Exception as e:
        return out, urls, f"parse:{e}"
    return out, urls, "ok"

def src_vt(d):
    key = os.environ.get("VT_API_KEY"); out = set()
    if not key: return out, "sem VT_API_KEY (pulado)"
    t = fetch(f"https://www.virustotal.com/api/v3/domains/{d}/subdomains?limit=1000",
              headers={"x-apikey": key})
    if t.startswith("__ERR__"): return out, t
    try:
        for r in json.loads(t).get("data", []):
            c = clean(r.get("id", ""))
            if c: out.add(c)
    except Exception as e:
        return out, f"parse:{e}"
    return out, "ok"

def src_strails(d):
    key = os.environ.get("STRAILS_API_KEY"); out = set()
    if not key: return out, "sem STRAILS_API_KEY (pulado)"
    t = fetch(f"https://api.securitytrails.com/v1/domain/{d}/subdomains?children_only=false",
              headers={"APIKEY": key})
    if t.startswith("__ERR__"): return out, t
    try:
        for sub in json.loads(t).get("subdomains", []):
            c = clean(f"{sub}.{d}")
            if c: out.add(c)
    except Exception as e:
        return out, f"parse:{e}"
    return out, "ok"

def src_shodan(d):
    key = os.environ.get("SHODAN_API_KEY"); out = set()
    if not key: return out, "sem SHODAN_API_KEY (pulado)"
    t = fetch(f"https://api.shodan.io/dns/domain/{d}?key={key}")
    if t.startswith("__ERR__"): return out, t
    try:
        for r in json.loads(t).get("subdomains", []):
            c = clean(f"{r}.{d}")
            if c: out.add(c)
    except Exception as e:
        return out, f"parse:{e}"
    return out, "ok"

def src_censys(d):
    cid = os.environ.get("CENSYS_API_ID"); csec = os.environ.get("CENSYS_API_SECRET")
    out = set()
    if not (cid and csec):
        return out, "sem CENSYS_API_ID/SECRET (pulado)"
    auth = base64.b64encode(f"{cid}:{csec}".encode()).decode()
    t = fetch(f"https://search.censys.io/api/v2/certificates/search?q=names:{d}&per_page=100",
              headers={"Authorization": f"Basic {auth}", "Accept": "application/json"})
    if t.startswith("__ERR__"): return out, t
    try:
        hits = json.loads(t).get("result", {}).get("hits", [])
        for h in hits:
            for name in h.get("names", []):
                c = clean(name)
                if c and (c == d or c.endswith("." + d)): out.add(c)
    except Exception as e:
        return out, f"parse:{e}"
    return out, "ok"

def known_from_staging(program, data_dir):
    """Extrai hosts do staging local; cobertura remota não é inferida."""
    known = set()
    base = os.path.join(data_dir, "programs", program)
    if not os.path.isdir(base):
        return known, f"programa não achado: {base}"
    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith((".md", ".json")):
                continue
            try:
                txt = open(os.path.join(root, fn), encoding="utf-8").read()
            except OSError:
                continue
            for m in re.findall(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,62})\.)+[a-z]{2,}\b', txt.lower()):
                c = clean(m)
                if c: known.add(c)
    return known, "ok"

# (nome, função, kind) — kind='hosts' devolve (hosts,status); 'urls' devolve (hosts,urls,status)
_HOST_SOURCES = (("crt.sh", src_crtsh), ("otx", src_otx), ("hackertarget", src_hackertarget),
                 ("virustotal", src_vt), ("securitytrails", src_strails), ("shodan", src_shodan),
                 ("censys", src_censys))
_URL_SOURCES = (("urlscan", src_urlscan), ("wayback", src_wayback))


def _run_source(name, fn, d, kind, ttl):
    """Roda uma fonte (com cache) e normaliza p/ (name, d, hosts, urls, status)."""
    cached = _cache_get(name, d, ttl)
    if cached is not None:
        return name, d, set(cached["hosts"]), set(cached.get("urls", [])), cached["status"] + " [cache]"
    if kind == "urls":
        hosts, urls, status = fn(d)
    else:
        hosts, status = fn(d)
        urls = set()
    if status == "ok":  # só cacheia sucesso (erro/transitório não vira cache)
        _cache_put(name, d, hosts, urls, status)
    return name, d, hosts, urls, status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domains", nargs="+", help="domínios base (ex.: worldcoin.org world.org)")
    ap.add_argument("--diff-program", default="", help="program_id p/ diff vs staging local")
    ap.add_argument("--data-dir", default=os.environ.get("EXCALIBULL_OUTBOX_DIR", ""), help="staging local; não representa inventário remoto")
    ap.add_argument("--urls", action="store_true", help="também listar URLs (urlscan+wayback)")
    ap.add_argument("--workers", type=int, default=10, help="fetches paralelos (fontes×domínios)")
    ap.add_argument("--cache-ttl", type=int, default=3600,
                    help="segundos de cache por (fonte,domínio); 0 desliga. Default 1h.")
    ap.add_argument("--json", action="store_true",
                    help="emite resultado estruturado em JSON (consumido pelo saquear.py)")
    a = ap.parse_args()
    if a.diff_program:
        from hive_workspace import _program, resolve_data_dir
        try:
            a.diff_program = _program(a.diff_program)
            a.data_dir = str(resolve_data_dir(a.data_dir or None))
        except ValueError as exc:
            ap.error(str(exc))

    # Monta as tarefas (domínio × fonte) e roda em paralelo — antes era sequencial
    # (~9 fontes × N domínios), o maior gargalo do passive.
    tasks = []
    for d in a.domains:
        for name, fn in _HOST_SOURCES:
            tasks.append((name, fn, d, "hosts"))
        for name, fn in _URL_SOURCES:
            tasks.append((name, fn, d, "urls"))

    all_hosts, all_urls, results = set(), set(), []
    host_sources = {}  # host -> {fontes que o reportaram}; proveniência por ativo
    with _cf.ThreadPoolExecutor(max_workers=max(1, a.workers)) as ex:
        futs = [ex.submit(_run_source, name, fn, d, kind, a.cache_ttl)
                for (name, fn, d, kind) in tasks]
        for fut in _cf.as_completed(futs):
            name, d, hosts, urls, status = fut.result()
            all_hosts |= hosts
            all_urls |= urls
            for h in hosts:
                host_sources.setdefault(h, set()).add(name)
            results.append((d, name, len(hosts), len(urls), status))

    # ordena p/ saída determinística (paralelismo embaralha a ordem de chegada)
    report = [f"  {d:22} {name:14} {nh:5} hosts {nu:5} urls [{st}]"
              for (d, name, nh, nu, st) in sorted(results)]

    # filtra por escopo (só hosts sob os domínios pedidos)
    scoped = {h for h in all_hosts if any(h == d or h.endswith("." + d) for d in a.domains)}
    prod = sorted(h for h in scoped if not NONPROD.search(h))
    nonprod = sorted(h for h in scoped if NONPROD.search(h))

    # calcula delta vs staging local (sem alegar novidade no Hive)
    new_prod, new_nonprod, known_n, known = None, None, None, None
    if a.diff_program and a.data_dir:
        known, st = known_from_staging(a.diff_program, a.data_dir)
        known_n = len(known)
        new_prod = [h for h in prod if h not in known]
        new_nonprod = [h for h in nonprod if h not in known]

    scoped_urls = sorted(u for u in all_urls if any(d in u for d in a.domains))

    # Inventário por ativo: preserva prod E não-prod com ambiente, fontes e escopo.
    # `new` = ausente no staging local (None sem --diff-program); não é novidade no Hive.
    # Nenhum ativo aqui é autorizado a sondar: cada URL exige hive_get_context ao vivo.
    known_set = known
    inventory = [{
        "host": h,
        "environment": classify_env(h),
        "prod": not NONPROD.search(h),
        "sources": sorted(host_sources.get(h, [])),
        "in_scope": True,
        "new": (h not in known_set) if known_set is not None else None,
        "probe_authorization": "pending-per-asset",
    } for h in sorted(scoped)]

    # --- saída JSON (consumida pelo saquear.py) ---
    if a.json:
        print(json.dumps({
            "domains": a.domains,
            "prod": prod,
            "nonprod": nonprod,
            "delta_prod": new_prod,          # None se sem --diff-program
            "delta_nonprod": new_nonprod,
            "known_in_staging": known_n,
            "baseline_coverage": "local-only",
            "inventory": inventory,          # prod+não-prod preservados; sondar exige autz por ativo
            "urls": scoped_urls,
            "sources": [{"domain": d, "source": n, "hosts": nh, "urls": nu, "status": st}
                        for (d, n, nh, nu, st) in sorted(results)],
        }, ensure_ascii=False, indent=2))
        return

    # --- saída texto (uso manual) ---
    print("===== FONTES =====")
    print("\n".join(report))
    print(f"\n===== TOTAL (escopo) ===== {len(scoped)} hosts ({len(prod)} prod / {len(nonprod)} não-prod)")

    if a.diff_program:
        if not a.data_dir:
            print("\n[!] --diff-program precisa de --data-dir (ou EXCALIBULL_OUTBOX_DIR)", file=sys.stderr)
        else:
            print(f"\n[*] Staging '{a.diff_program}': {known_n} hosts conhecidos", file=sys.stderr)
            print(f"\n===== 🆕 DELTA — PROD ausente no staging ({len(new_prod)}) =====")
            for h in new_prod: print(h)
            print(f"\n===== 🆕 DELTA — não-prod ausente no staging ({len(new_nonprod)}) =====")
            for h in new_nonprod[:80]: print(h)
    else:
        print(f"\n===== PROD ({len(prod)}) =====");    [print(h) for h in prod]
        print(f"\n===== NÃO-PROD ({len(nonprod)}) ===="); [print(h) for h in nonprod[:120]]

    if a.urls:
        print(f"\n===== URLs ({len(scoped_urls)}) =====")
        for u in scoped_urls[:400]: print(u)
    print(f"\n[*] {len(all_urls)} URLs totais coletadas (use --urls)", file=sys.stderr)

if __name__ == "__main__":
    sys.exit(main())
