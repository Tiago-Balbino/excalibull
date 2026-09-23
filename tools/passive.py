#!/usr/bin/env python3
"""passive — agregador de recon PASSIVO (só fontes de terceiros) + diff vs Hive.

Junta subdomínios/hosts de várias fontes que NÃO tocam o alvo, dedupe, filtra por
escopo, sinaliza não-produção, e compara com o que o Hive já conhece (notas do
programa) pra imprimir só o DELTA novo. Alimenta o `achar o x` sem recibo.

Fontes sem chave: crt.sh, AlienVault OTX, HackerTarget, urlscan.io, Wayback/CDX.
Com chave (env, opcional): VirusTotal (VT_API_KEY), SecurityTrails (STRAILS_API_KEY),
Shodan (SHODAN_API_KEY). Ausência de chave = fonte pulada (nunca hardcode).

Uso:
  python3 tools/passive.py worldcoin.org world.org --diff-program toolsforhumanity \
      --data-dir /.../hive_instance/data
  python3 tools/passive.py exemplo.com          # sem diff, só agrega
"""
import argparse, base64, gzip, io, json, os, re, sys, urllib.request, urllib.error
from urllib.parse import urlparse, quote

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
NONPROD = re.compile(r'(^|[.\-])(staging|stage|dev|development|test|testing|qa|uat|sandbox|'
                     r'internal|preview|canary|demo|sepolia|devnet|testnet|e2e|local)([.\-]|$)', re.I)
HOSTRE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9\-]{0,62})\.)+[a-z]{2,}$')

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

def known_from_hive(program, data_dir):
    """Extrai hosts já conhecidos das notas+scope.json do programa no Hive."""
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domains", nargs="+", help="domínios base (ex.: worldcoin.org world.org)")
    ap.add_argument("--diff-program", default="", help="program_id p/ diff vs Hive")
    ap.add_argument("--data-dir", default=os.environ.get("HIVE_DATA_DIR", ""), help="dir do Hive")
    ap.add_argument("--urls", action="store_true", help="também listar URLs (urlscan+wayback)")
    a = ap.parse_args()

    all_hosts, all_urls, report = set(), set(), []
    for d in a.domains:
        for name, fn in (("crt.sh", src_crtsh), ("otx", src_otx), ("hackertarget", src_hackertarget),
                         ("virustotal", src_vt), ("securitytrails", src_strails), ("shodan", src_shodan),
                         ("censys", src_censys)):
            hosts, status = fn(d)
            all_hosts |= hosts
            report.append(f"  {d:22} {name:14} {len(hosts):5} hosts  [{status}]")
        for name, fn in (("urlscan", src_urlscan), ("wayback", src_wayback)):
            hosts, urls, status = fn(d)
            all_hosts |= hosts; all_urls |= urls
            report.append(f"  {d:22} {name:14} {len(hosts):5} hosts {len(urls):5} urls [{status}]")

    # filtra por escopo (só hosts sob os domínios pedidos)
    scoped = {h for h in all_hosts if any(h == d or h.endswith("." + d) for d in a.domains)}
    prod = sorted(h for h in scoped if not NONPROD.search(h))
    nonprod = sorted(h for h in scoped if NONPROD.search(h))

    print("===== FONTES =====")
    print("\n".join(report))
    print(f"\n===== TOTAL (escopo) ===== {len(scoped)} hosts ({len(prod)} prod / {len(nonprod)} não-prod)")

    if a.diff_program:
        if not a.data_dir:
            print("\n[!] --diff-program precisa de --data-dir (ou HIVE_DATA_DIR)", file=sys.stderr)
        else:
            known, st = known_from_hive(a.diff_program, a.data_dir)
            print(f"\n[*] Hive '{a.diff_program}': {len(known)} hosts conhecidos [{st}]", file=sys.stderr)
            new_prod = [h for h in prod if h not in known]
            new_nonprod = [h for h in nonprod if h not in known]
            print(f"\n===== 🆕 DELTA — PROD novo no Hive ({len(new_prod)}) =====")
            for h in new_prod: print(h)
            print(f"\n===== 🆕 DELTA — não-prod novo ({len(new_nonprod)}) =====")
            for h in new_nonprod[:80]: print(h)
    else:
        print(f"\n===== PROD ({len(prod)}) =====");    [print(h) for h in prod]
        print(f"\n===== NÃO-PROD ({len(nonprod)}) ===="); [print(h) for h in nonprod[:120]]

    if a.urls:
        su = sorted(u for u in all_urls if any(d in u for d in a.domains))
        print(f"\n===== URLs ({len(su)}) =====")
        for u in su[:400]: print(u)
    print(f"\n[*] {len(all_urls)} URLs totais coletadas (use --urls)", file=sys.stderr)

if __name__ == "__main__":
    sys.exit(main())
