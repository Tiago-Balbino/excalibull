#!/usr/bin/env python3
"""
resolve_doh.py — resolução em massa via DNS-over-HTTPS (dns.google + cloudflare).
Aprendido do recon externo do Yahoo (recon-benchmarks/): pega o que o resolver local
não pega e fura rate-limit. Complementa (não substitui) dnsx/socket.

Uso:
  python3 tools/resolve_doh.py -i subs.txt -o resolved_doh.txt [-t 64]
Saída: linhas "host<TAB>ip1,ip2<TAB>cname1,cname2" (só quem resolveu A/CNAME).
Requer: pip install curl_cffi  (cai pro requests se faltar, sem impersonation).
"""
import argparse, concurrent.futures as cf, sys
try:
    from curl_cffi import requests as cr
    SESS = cr.Session(impersonate="chrome"); IMP=True
except Exception:
    import requests as _r; SESS=_r.Session(); IMP=False

def q(n):
    for url in (f"https://dns.google/resolve?name={n}&type=A",
                f"https://cloudflare-dns.com/dns-query?name={n}&type=A"):
        try:
            d = SESS.get(url, headers={"accept":"application/dns-json"}, timeout=15).json()
            if d.get("Status")==0:
                ips=[a["data"] for a in d.get("Answer",[]) if a.get("type")==1]
                cn =[a["data"] for a in d.get("Answer",[]) if a.get("type")==5]
                if ips or cn: return n,ips,cn
            if d.get("Status")==3: return n,[],[]   # NXDOMAIN
        except Exception: continue
    return n,None,None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("-i","--input",required=True); ap.add_argument("-o","--output",required=True)
    ap.add_argument("-t","--threads",type=int,default=64)
    a=ap.parse_args()
    names=sorted({l.strip() for l in open(a.input) if l.strip()})
    print(f"[*] {len(names)} nomes · DoH impersonate={IMP} · {a.threads} threads",file=sys.stderr)
    ok=0
    with open(a.output,"w") as f, cf.ThreadPoolExecutor(max_workers=a.threads) as ex:
        for i,(n,ips,cn) in enumerate(ex.map(q,names,chunksize=10)):
            if ips:
                ok+=1; f.write(f"{n}\t{','.join(ips)}\t{','.join(cn or [])}\n"); f.flush()
            if i and i%4000==0: print(f"[*] {i}/{len(names)} · {ok} resolvidos",file=sys.stderr)
    print(f"[+] FIM: {ok}/{len(names)} resolveram → {a.output}",file=sys.stderr)

if __name__=="__main__": main()
