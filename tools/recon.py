#!/usr/bin/env python3
"""
Sword — Recon orquestrado
=========================
Orquestra as principais ferramentas de recon e cai pra Python puro quando alguma falta.
Roda no macOS nativo (rede + tools). Instale tudo com ../setup.sh.

Pipeline:
  subs   = subfinder ∪ amass(passivo) ∪ crt.sh
  resolve= dnsx (senão socket)
  probe  = httpx (senão probe interno)              -> live-hosts.txt
  urls   = gau ∪ waybackurls ∪ katana ∪ gospider     -> urls.txt
  gf     = garimpa urls.txt em buckets (xss/ssrf/...) -> gf/<padrão>.txt
  [opc]  = nuclei (-l live-hosts)                     -> nuclei.txt
  [opc]  = ffuf (content discovery, precisa -w)       -> ffuf.json

Rate limit: --rate (req/s por host, default 5) aplicado a httpx/katana; gospider usa --delay.
Só use em alvos AUTORIZADOS (escopo do programa).
Dependências Python: requests. Ferramentas externas: opcionais (ver setup.sh).
"""
import argparse
import concurrent.futures
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None

class C:
    R="\033[31m"; Y="\033[33m"; G="\033[32m"; B="\033[36m"; DIM="\033[2m"; BOLD="\033[1m"; X="\033[0m"

def log(m):  print(f"{C.DIM}[*]{C.X} {m}", file=sys.stderr)
def ok(m):   print(f"{C.G}[+]{C.X} {m}", file=sys.stderr)
def skip(m): print(f"{C.Y}[skip]{C.X} {m} {C.DIM}(rode setup.sh){C.X}", file=sys.stderr)

def have(tool): return shutil.which(tool) is not None

def run(cmd, timeout=600, stdin_data=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin_data)
        if p.returncode not in (0, None) and not p.stdout:
            log(f"{cmd[0]} rc={p.returncode}: {p.stderr.strip()[:160]}")
        return p.stdout
    except subprocess.TimeoutExpired:
        log(f"{cmd[0]} estourou timeout ({timeout}s)"); return ""
    except Exception as e:
        log(f"{cmd[0]} falhou: {e}"); return ""

def lines(text):
    return [l.strip() for l in text.splitlines() if l.strip()]

URL_RE = re.compile(r"https?://[^\s\"'<>\]\)]+")

# ---------------- subdomínios ----------------
def subs_subfinder(domain):
    if not have("subfinder"): skip("subfinder"); return set()
    s = set(lines(run(["subfinder", "-silent", "-d", domain], timeout=300))); ok(f"subfinder: {len(s)}"); return s

def subs_amass(domain):
    if not have("amass"): skip("amass"); return set()
    out = run(["amass", "enum", "-passive", "-nocolor", "-d", domain], timeout=400)
    s = {l for l in lines(out) if l.endswith(domain) and re.match(r"^[a-z0-9._-]+$", l)}
    ok(f"amass (passivo): {len(s)}"); return s

def subs_crtsh(domain, timeout):
    if not requests: return set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=timeout,
                         headers={"User-Agent": "Sword-Recon/3.0"})
        s = set()
        if r.status_code == 200:
            for e in r.json():
                for n in e.get("name_value", "").split("\n"):
                    n = n.strip().lstrip("*.").lower()
                    if n.endswith(domain) and re.match(r"^[a-z0-9._-]+$", n): s.add(n)
        ok(f"crt.sh: {len(s)}"); return s
    except Exception as e:
        log(f"crt.sh: {e}"); return set()

# ---------------- resolução ----------------
def resolve_dnsx(hosts):
    return set(lines(run(["dnsx", "-silent"], timeout=300, stdin_data="\n".join(hosts) + "\n")))

def resolve_socket(hosts, workers):
    def r(h):
        try: socket.gethostbyname(h); return h
        except socket.gaierror: return None
    resolved = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for h in ex.map(r, hosts):
            if h: resolved.add(h)
    return resolved

# ---------------- probe ----------------
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

def probe_httpx(hosts, rate):
    out = run(["httpx", "-silent", "-json", "-title", "-status-code", "-tech-detect",
               "-web-server", "-rl", str(rate)], timeout=600, stdin_data="\n".join(hosts) + "\n")
    live = []
    for ln in lines(out):
        try: j = json.loads(ln)
        except json.JSONDecodeError: continue
        live.append({"host": j.get("input") or j.get("host", ""), "url": j.get("url", ""),
                     "status": j.get("status_code") or j.get("status-code"),
                     "server": j.get("webserver", ""), "title": j.get("title", ""), "tech": j.get("tech", [])})
    ok(f"httpx: {len(live)} vivos"); return live

def probe_builtin(hosts, timeout, workers):
    if not requests: return []
    def p(h):
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{h}", timeout=timeout, verify=False,
                                 allow_redirects=True, headers={"User-Agent": "Sword-Recon/3.0"})
            except requests.RequestException: continue
            m = TITLE_RE.search(r.text or "")
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:80] if m else ""
            return {"host": h, "url": r.url, "status": r.status_code,
                    "server": r.headers.get("Server", ""), "title": title, "tech": []}
        return None
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(p, hosts):
            if res: live.append(res)
    ok(f"probe interno: {len(live)} vivos"); return live

# ---------------- URLs (passivo + crawl) ----------------
def urls_gau(domain):
    if not have("gau"): skip("gau"); return set()
    s = set(lines(run(["gau", "--subs", domain], timeout=300))); ok(f"gau: {len(s)} URLs"); return s

def urls_waybackurls(domain):
    if not have("waybackurls"): skip("waybackurls"); return set()
    s = set(lines(run(["waybackurls"], timeout=300, stdin_data=domain + "\n"))); ok(f"waybackurls: {len(s)} URLs"); return s

def urls_katana(seeds, depth, rate):
    if not have("katana"): skip("katana"); return set()
    out = run(["katana", "-silent", "-jc", "-d", str(depth), "-rl", str(rate), "-list", "-"],
              timeout=600, stdin_data="\n".join(seeds) + "\n")
    s = set(lines(out)); ok(f"katana: {len(s)} URLs (crawl)"); return s

def urls_gospider(seeds, rate):
    if not have("gospider"): skip("gospider"); return set()
    delay = max(1, math.ceil(1.0 / max(rate, 1)))  # segundos entre requests
    s = set()
    for seed in seeds[:20]:  # não explodir: primeiros 20 hosts vivos
        out = run(["gospider", "-s", seed, "-q", "-d", "2", "--delay", str(delay), "-t", "3"], timeout=300)
        for ln in out.splitlines():
            for m in URL_RE.findall(ln):
                s.add(m)
    ok(f"gospider: {len(s)} URLs (crawl)"); return s

# ---------------- gf (garimpo) ----------------
GF_PATTERNS = ["xss", "ssrf", "idor", "redirect", "ssti", "sqli", "lfi", "rce", "interestingparams", "debug_logic"]

def gf_buckets(urls, outdir):
    if not have("gf") or not urls:
        if not have("gf"): skip("gf")
        return {}
    gfdir = os.path.join(outdir, "gf"); os.makedirs(gfdir, exist_ok=True)
    blob = "\n".join(urls) + "\n"; found = {}
    for pat in GF_PATTERNS:
        out = run(["gf", pat], timeout=120, stdin_data=blob)
        hits = lines(out)
        if hits:
            write_lines(os.path.join(gfdir, f"{pat}.txt"), sorted(set(hits)))
            found[pat] = len(set(hits))
    if found:
        ok("gf: " + ", ".join(f"{k}={v}" for k, v in found.items()))
    return found

# ---------------- opcionais ----------------
def run_nuclei(live_urls, outfile, rate):
    if not have("nuclei"): skip("nuclei"); return None
    log("nuclei rodando (pode demorar)...")
    run(["nuclei", "-silent", "-rl", str(rate), "-l", "-", "-o", outfile], timeout=1800,
        stdin_data="\n".join(live_urls) + "\n")
    n = len(lines(open(outfile).read())) if os.path.exists(outfile) else 0
    ok(f"nuclei: {n} achados -> {outfile}"); return n

def run_ffuf(base_url, wordlist, outfile, rate):
    if not have("ffuf"): skip("ffuf"); return None
    target = base_url.rstrip("/") + "/FUZZ"
    run(["ffuf", "-u", target, "-w", wordlist, "-mc", "200,204,301,302,307,401,403",
         "-rate", str(rate), "-of", "json", "-o", outfile, "-s"], timeout=1200)
    ok(f"ffuf: -> {outfile}"); return outfile

# ---------------- pipeline ----------------
def pipeline(domain, a):
    tools = [t for t in ["subfinder","amass","dnsx","httpx","gau","waybackurls","katana","gospider","gf","nuclei","ffuf"] if have(t)]
    log(f"alvo: {domain}  |  rate: {a.rate}/s  |  tools: " + (", ".join(tools) or "(nenhuma externa — Python puro)"))

    subs = subs_subfinder(domain) | subs_amass(domain) | subs_crtsh(domain, a.timeout)
    subs.add(domain); subs = sorted(subs)
    log(f"subdomínios candidatos: {len(subs)}")

    resolved = sorted(resolve_dnsx(subs) if have("dnsx") else resolve_socket(subs, a.workers))
    ok(f"resolvem DNS: {len(resolved)}")

    live = []
    if a.probe or a.crawl or a.nuclei or a.all:
        live = probe_httpx(resolved, a.rate) if have("httpx") else probe_builtin(resolved, a.timeout, a.workers)
    live_urls = sorted({l["url"] for l in live if l.get("url")})

    urls = set()
    if a.urls or a.all:
        urls |= urls_gau(domain) | urls_waybackurls(domain)
    if a.crawl or a.all:
        seeds = live_urls or [f"https://{domain}"]
        urls |= urls_katana(seeds, a.depth, a.rate) | urls_gospider(seeds, a.rate)
    urls = sorted(urls)

    outdir = a.out or f"recon_{domain}"; os.makedirs(outdir, exist_ok=True)
    write_lines(os.path.join(outdir, "subdomains.txt"), resolved)
    if live_urls: write_lines(os.path.join(outdir, "live-hosts.txt"), live_urls)
    if urls:      write_lines(os.path.join(outdir, "urls.txt"), urls)

    gf_found = {}
    if (a.gf or a.all) and urls:
        gf_found = gf_buckets(urls, outdir)

    result = {"domain": domain, "subdomains": resolved, "live": live,
              "urls_count": len(urls), "gf": gf_found}

    if (a.nuclei or a.all) and live_urls:
        result["nuclei_findings"] = run_nuclei(live_urls, os.path.join(outdir, "nuclei.txt"), a.rate)
    if a.ffuf and live_urls:
        run_ffuf(live_urls[0], a.ffuf, os.path.join(outdir, "ffuf.json"), a.rate)

    with open(os.path.join(outdir, "recon.json"), "w") as fh:
        json.dump({"scanned_at": datetime.now(timezone.utc).isoformat(), **result}, fh, indent=2, ensure_ascii=False)

    print(f"\n{C.BOLD}── Recon {domain} ──{C.X}  subs:{len(resolved)}  vivos:{len(live_urls)}  urls:{len(urls)}"
          + (f"  gf:[{', '.join(f'{k}={v}' for k,v in gf_found.items())}]" if gf_found else ""))
    print(f"{C.G}Salvo em {outdir}/{C.X}")
    if live_urls:
        print(f"{C.DIM}→ python3 cors_headers_scan.py -f {outdir}/live-hosts.txt --json {outdir}/cors.json{C.X}")
    return result

def write_lines(path, items):
    with open(path, "w") as fh:
        fh.write("\n".join(items) + ("\n" if items else ""))

def main():
    ap = argparse.ArgumentParser(description="Sword — Recon orquestrado")
    ap.add_argument("domain")
    ap.add_argument("--all", action="store_true", help="probe + urls + crawl + gf (+nuclei se pedido)")
    ap.add_argument("--probe", action="store_true", help="detectar hosts vivos (httpx/interno)")
    ap.add_argument("--urls", action="store_true", help="URLs históricas (gau/waybackurls)")
    ap.add_argument("--crawl", action="store_true", help="crawl ativo (katana + gospider)")
    ap.add_argument("--gf", action="store_true", help="garimpar urls.txt em buckets (gf)")
    ap.add_argument("--nuclei", action="store_true", help="rodar nuclei nos hosts vivos")
    ap.add_argument("--ffuf", metavar="WORDLIST", help="content discovery ffuf no 1º host vivo")
    ap.add_argument("--depth", type=int, default=3, help="profundidade do katana")
    ap.add_argument("--rate", type=int, default=5, help="req/s por host (httpx/katana/nuclei/ffuf); gospider vira --delay")
    ap.add_argument("--out", help="pasta de saída (default recon_<domain>)")
    ap.add_argument("-t", "--timeout", type=float, default=12)
    ap.add_argument("--workers", type=int, default=30)
    a = ap.parse_args()
    a.domain = a.domain.lower().strip().replace("https://", "").replace("http://", "").strip("/")
    pipeline(a.domain, a)

if __name__ == "__main__":
    main()
