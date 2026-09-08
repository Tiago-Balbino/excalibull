#!/usr/bin/env python3
"""
Sword — CORS & Security Headers Scanner
=======================================
Audita headers de segurança e testa configurações de CORS mal-configuradas
em um ou mais alvos.

Uso:
    python3 cors_headers_scan.py https://alvo.com
    python3 cors_headers_scan.py -f urls.txt --json relatorio.json
    python3 cors_headers_scan.py https://a.com https://b.com --insecure

Só testa alvos que você está AUTORIZADO a testar (escopo de bug bounty/pentest).
Dependências: requests  (pip install requests)
"""
import argparse
import concurrent.futures
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("Falta a lib 'requests'. Instale com: pip install requests")

# ---------- cores de terminal ----------
class C:
    R = "\033[31m"; Y = "\033[33m"; G = "\033[32m"; B = "\033[36m"
    DIM = "\033[2m"; BOLD = "\033[1m"; X = "\033[0m"

def sev_tag(sev):
    return {"HIGH": f"{C.R}{C.BOLD}[ALTO]{C.X}",
            "MED":  f"{C.Y}[MÉDIO]{C.X}",
            "LOW":  f"{C.B}[BAIXO]{C.X}",
            "INFO": f"{C.DIM}[INFO]{C.X}",
            "OK":   f"{C.G}[OK]{C.X}"}[sev]

# ---------- auditoria de security headers ----------
# nome_normalizado -> (severidade se ausente, dica)
SEC_HEADERS = {
    "strict-transport-security": ("MED",  "HSTS ausente — permite downgrade p/ HTTP e ataques MITM."),
    "content-security-policy":   ("MED",  "CSP ausente — sem mitigação de XSS/injeção de conteúdo."),
    "x-frame-options":           ("MED",  "X-Frame-Options ausente — risco de clickjacking (checar se CSP frame-ancestors cobre)."),
    "x-content-type-options":    ("LOW",  "X-Content-Type-Options ausente — navegador pode fazer MIME sniffing."),
    "referrer-policy":           ("LOW",  "Referrer-Policy ausente — pode vazar URLs em requisições cross-origin."),
    "permissions-policy":        ("INFO", "Permissions-Policy ausente — sem restrição de APIs do navegador."),
}
INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]

def audit_headers(headers):
    findings = []
    lower = {k.lower(): v for k, v in headers.items()}

    for h, (sev, tip) in SEC_HEADERS.items():
        if h not in lower:
            findings.append({"sev": sev, "check": h, "msg": tip})
        else:
            findings.append({"sev": "OK", "check": h, "msg": f"presente: {lower[h][:80]}"})

    # HSTS fraco
    hsts = lower.get("strict-transport-security", "")
    if hsts:
        if "max-age=0" in hsts.replace(" ", ""):
            findings.append({"sev": "MED", "check": "hsts-max-age", "msg": "HSTS com max-age=0 (desabilitado)."})
        elif "includesubdomains" not in hsts.lower():
            findings.append({"sev": "LOW", "check": "hsts-subdomains", "msg": "HSTS sem includeSubDomains."})

    # info disclosure
    for h in INFO_LEAK_HEADERS:
        if h in lower and lower[h].strip():
            findings.append({"sev": "INFO", "check": f"info-leak:{h}", "msg": f"expõe versão/stack: {lower[h][:80]}"})

    # cookies
    raw_cookies = headers.get("set-cookie") or headers.get("Set-Cookie")
    if raw_cookies:
        cl = raw_cookies.lower()
        if "secure" not in cl:
            findings.append({"sev": "MED", "check": "cookie-secure", "msg": "Set-Cookie sem flag Secure."})
        if "httponly" not in cl:
            findings.append({"sev": "MED", "check": "cookie-httponly", "msg": "Set-Cookie sem flag HttpOnly (acessível via JS)."})
        if "samesite" not in cl:
            findings.append({"sev": "LOW", "check": "cookie-samesite", "msg": "Set-Cookie sem SameSite (risco de CSRF)."})
    return findings

# ---------- testes de CORS ----------
def cors_probes(target):
    """Gera origins de teste a partir do host do alvo."""
    host = urlparse(target).hostname or ""
    reg = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    return [
        ("origin-refletido", "https://evil-sword-test.example"),
        ("null-origin",      "null"),
        ("subdominio-forjado", f"https://sword-attacker.{host}") if host else ("subdominio-forjado", "https://x.evil.example"),
        ("sufixo-bypass",    f"https://{reg}.evil-sword.example") if reg else ("sufixo-bypass", "https://x.evil.example"),
        ("prefixo-bypass",   f"https://evil{reg}") if reg else ("prefixo-bypass", "https://xevil.example"),
    ]

def test_cors(session, target, timeout, verify):
    findings = []
    for label, origin in cors_probes(target):
        try:
            r = session.get(target, headers={"Origin": origin}, timeout=timeout,
                            verify=verify, allow_redirects=True)
        except requests.RequestException:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            sev = "MED"
            msg = f"ACAO='*' (wildcard). Origin testado='{origin}'."
            if acac == "true":
                sev = "HIGH"  # spec proíbe, mas alguns servers/proxies fazem; vale reportar
                msg += " + Allow-Credentials:true (configuração inválida e perigosa)."
            findings.append({"sev": sev, "check": f"cors:{label}", "msg": msg})
        elif acao and origin != "null" and (origin in acao):
            sev = "HIGH" if acac == "true" else "MED"
            msg = f"ACAO reflete o Origin atacante ('{acao}')."
            if acac == "true":
                msg += " + Allow-Credentials:true → leitura autenticada cross-origin. CRÍTICO."
            findings.append({"sev": sev, "check": f"cors:{label}", "msg": msg})
        elif acao == "null" and origin == "null":
            sev = "HIGH" if acac == "true" else "MED"
            msg = "ACAO='null' aceito — explorável via iframe sandbox/data:."
            if acac == "true":
                msg += " + Allow-Credentials:true. CRÍTICO."
            findings.append({"sev": sev, "check": f"cors:{label}", "msg": msg})
    if not findings:
        findings.append({"sev": "OK", "check": "cors", "msg": "Nenhuma reflexão de Origin insegura detectada."})
    return findings

# ---------- scan de um alvo ----------
def scan(target, timeout, verify):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    result = {"target": target, "ok": False, "status": None, "findings": []}
    session = requests.Session()
    session.headers.update({"User-Agent": "Sword-Scanner/1.0 (+bug-bounty-recon)"})
    try:
        r = session.get(target, timeout=timeout, verify=verify, allow_redirects=True)
    except requests.RequestException as e:
        result["error"] = str(e)
        return result
    result["ok"] = True
    result["status"] = r.status_code
    result["final_url"] = r.url
    result["findings"] = audit_headers(r.headers) + test_cors(session, target, timeout, verify)
    return result

# ---------- saída ----------
ORDER = {"HIGH": 0, "MED": 1, "LOW": 2, "INFO": 3, "OK": 4}

def print_result(res):
    print(f"\n{C.BOLD}══ {res['target']}{C.X}")
    if not res.get("ok"):
        print(f"  {C.R}erro:{C.X} {res.get('error', 'sem resposta')}")
        return
    print(f"  {C.DIM}status {res['status']}  →  {res.get('final_url')}{C.X}")
    for f in sorted(res["findings"], key=lambda x: ORDER.get(x["sev"], 9)):
        if f["sev"] == "OK":
            print(f"  {sev_tag('OK')} {C.DIM}{f['check']}{C.X}")
        else:
            print(f"  {sev_tag(f['sev'])} {C.BOLD}{f['check']}{C.X} — {f['msg']}")

def summary(results):
    counts = {"HIGH": 0, "MED": 0, "LOW": 0}
    for res in results:
        for f in res.get("findings", []):
            if f["sev"] in counts:
                counts[f["sev"]] += 1
    print(f"\n{C.BOLD}── Resumo ──{C.X}  "
          f"{C.R}ALTO: {counts['HIGH']}{C.X}  "
          f"{C.Y}MÉDIO: {counts['MED']}{C.X}  "
          f"{C.B}BAIXO: {counts['LOW']}{C.X}  "
          f"({len(results)} alvo(s))")

def main():
    ap = argparse.ArgumentParser(description="Sword — CORS & Security Headers Scanner")
    ap.add_argument("targets", nargs="*", help="URLs/hosts a testar")
    ap.add_argument("-f", "--file", help="arquivo com uma URL por linha")
    ap.add_argument("-t", "--timeout", type=float, default=12, help="timeout por requisição (s)")
    ap.add_argument("-w", "--workers", type=int, default=8, help="alvos em paralelo")
    ap.add_argument("--json", help="salvar relatório JSON neste caminho")
    ap.add_argument("--insecure", action="store_true", help="ignorar erros de certificado TLS")
    args = ap.parse_args()

    targets = list(args.targets)
    if args.file:
        with open(args.file) as fh:
            targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    targets = list(dict.fromkeys(targets))  # dedup preservando ordem
    if not targets:
        ap.error("informe ao menos um alvo (arg ou -f)")

    verify = not args.insecure
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(scan, t, args.timeout, verify): t for t in targets}
        for fut in concurrent.futures.as_completed(futs):
            res = fut.result()
            results.append(res)
            print_result(res)

    summary(results)
    if args.json:
        report = {"scanned_at": datetime.now(timezone.utc).isoformat(),
                  "count": len(results), "results": results}
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        print(f"\n{C.G}Relatório salvo em {args.json}{C.X}")

if __name__ == "__main__":
    main()
