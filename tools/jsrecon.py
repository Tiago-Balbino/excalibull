#!/usr/bin/env python3
"""jsrecon — minerador de superfície a partir de SPA/Next.js (stdlib pura).

Dado um URL autorizado, baixa o HTML + todos os bundles JS referenciados
(inclui o buildManifest do Next), e extrai de forma passiva-de-conteúdo:
  - rotas/endpoints de API ("/api/...", "/v1/...", "/graphql", etc.)
  - URLs absolutas para hosts do alvo
  - nomes de operação GraphQL e chamadas fetch/axios
  - flags/config NEXT_PUBLIC_* e chaves de env expostas no client
  - possíveis segredos (MASCARADOS — nunca imprime o valor cru inteiro)
  - source maps (.map) expostos → recuperação de fonte

Gentil por padrão: sequencial, timeout curto, UA de browser. NÃO faz fuzz.
O host precisa de recibo do Hive (o scope_hook do Bash valida na chamada).

Uso:
  python3 tools/jsrecon.py https://developer.world.org [--max-js 40] [--scope world.org,worldcoin.org]
"""
import argparse, gzip, io, json, os, re, sys, urllib.request, urllib.error
from urllib.parse import urljoin, urlparse

_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)
from extract import mask, in_scope, PATTERNS_TEXT, DEFAULT_UA  # noqa: E402
from netcommon import RateLimiter, http_get  # noqa: E402

UA = DEFAULT_UA

# Rate-limit compartilhado (reentrante, thread-safe). 0 = sem limite. Ajustado
# por --rate no main(). Alvos manual-only (ex.: NBA --rate 3) EXIGEM throttle:
# o BFS de bundles senão vira scanner automatizado.
_LIMITER = RateLimiter(0.0)

def fetch(url, timeout=15):
    # Delega ao GET compartilhado (gzip + retry/backoff + throttle).
    return http_get(url, timeout=timeout, limiter=_LIMITER)

# ---- regexes de extração ----
RE_SCRIPT   = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
RE_NEXTBUILD= re.compile(r'/_next/static/([^/"\']+)/_(?:buildManifest|ssgManifest)\.js')
# RE_PATH e RE_URL vêm de extract.py (fonte única; keyword-set é a UNIÃO).
RE_PATH     = PATTERNS_TEXT.api_path
RE_ABSPATH  = re.compile(r'["\'\x60](/[A-Za-z0-9_\-]{1,40}(?:/[A-Za-z0-9_\-.:{}$]{1,40}){1,6})["\'\x60]')
RE_URL      = PATTERNS_TEXT.url
RE_GQL      = re.compile(r'(?:operationName["\']?\s*[:=]\s*["\']([A-Za-z0-9_]+)|(?:query|mutation|subscription)\s+([A-Za-z][A-Za-z0-9_]+)\s*[\({])')
RE_ENV      = re.compile(r'(NEXT_PUBLIC_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+)["\']?\s*[:=]\s*["\']([^"\']{0,80})')
RE_JSPATH   = re.compile(r'["\'\x60](/[A-Za-z0-9_\-./]+?\.m?js)["\'\x60]')
RE_SOURCEMAP= re.compile(r'//[#@]\s*sourceMappingURL=(\S+)')
RE_NEXTDATA = re.compile(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.S)
# fingerprint de stack -> (nome, playbook de teste DIRIGIDO)
FINGERPRINTS = [
    (r'query_root|no_queries_available|x-hasura|hasura', "Hasura GraphQL",
     "introspection unauth + x-hasura-role override + BAC row-level (2 contas) por tipo query/mutation"),
    (r'passwordless/start|/mfa/associate|/passkey/|oob_channels|mergeScopes', "Auth0-like IdP",
     "OTP passwordless brute/reuse · passkey enrollment binding cross-account · MFA associate/downgrade · redirect_uri"),
    (r'tryretool|retool\.com|/api/organization/preAuthData|assets_vjs', "Retool",
     "preAuthData (orgId/SSO) · SAML/OAuth SSO bypass · versão→CVE · /api/* BAC"),
    (r'firebaseio\.com|firebaseapp\.com|"apiKey":"AIza', "Firebase",
     "regras DB abertas (REST .json) · buckets storage públicos · signup self-service"),
    (r'openid-configuration|/authorize|/oauth/token|id_token token|device_authorization', "OIDC/OAuth",
     "redirect_uri bypass · implicit token leak · PKCE downgrade · state/nonce · alg confusion (jwks)"),
    (r'_next/static|__NEXT_DATA__', "Next.js",
     "rotas /api/* server-side · __NEXT_DATA__ props/flags · _buildManifest p/ rotas ocultas"),
]
# Segredos + google-key de extract.py (fonte única). mask/in_scope idem.
RE_SECRET   = PATTERNS_TEXT.secret
RE_GKEY     = PATTERNS_TEXT.gkey

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--max-js", type=int, default=40)
    ap.add_argument("--scope", default="", help="csv de domínios base p/ marcar in-scope")
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--context", default="", help="csv de keywords: dump de ~90 chars ao redor de cada ocorrência")
    ap.add_argument("--save", default="", help="dir p/ salvar os bundles baixados (grep offline)")
    ap.add_argument("--json", action="store_true",
                    help="emite resultado estruturado em JSON (consumido pelo saquear.py)")
    ap.add_argument("--rate", type=float, default=0.0,
                    help="máx req/s (throttle antes de cada fetch). 0 = sem limite. "
                         "Alvos manual-only exigem (ex.: NBA --rate 3).")
    a = ap.parse_args()
    _LIMITER.set_rate(a.rate)
    scopes = [s.strip() for s in a.scope.split(",") if s.strip()]
    base = f"{urlparse(a.url).scheme}://{urlparse(a.url).netloc}"

    html, st = fetch(a.url, a.timeout)
    print(f"[*] {a.url} -> {st} ({len(html)} bytes html)", file=sys.stderr)
    js_urls = set()
    for m in RE_SCRIPT.finditer(html):
        js_urls.add(urljoin(a.url, m.group(1)))
    for bid in set(RE_NEXTBUILD.findall(html)):
        for name in ("_buildManifest.js", "_ssgManifest.js"):
            js_urls.add(f"{base}/_next/static/{bid}/{name}")
    # também: qualquer .js same-origin citado no HTML (Vite/module/preload)
    for m in RE_JSPATH.finditer(html):
        ju = urljoin(a.url, m.group(1))
        if urlparse(ju).netloc == urlparse(a.url).netloc:
            js_urls.add(ju)
    # BFS limitado: baixa bundles e segue chunks .js same-origin citados neles
    corpus = {a.url: html}
    queue = list(js_urls)
    seen = set()
    origin = urlparse(a.url).netloc
    while queue and len(seen) < a.max_js:
        ju = queue.pop(0)
        if ju in seen:
            continue
        seen.add(ju)
        body, jst = fetch(ju, a.timeout)
        if not body:
            continue
        corpus[ju] = body
        if a.save:
            try:
                os.makedirs(a.save, exist_ok=True)
                with open(os.path.join(a.save, os.path.basename(urlparse(ju).path) or "bundle.js"), "w") as f:
                    f.write(body)
            except OSError:
                pass
        for m in RE_JSPATH.finditer(body):
            nxt = urljoin(base, m.group(1))
            if urlparse(nxt).netloc == origin and nxt not in seen:
                queue.append(nxt)
    print(f"[*] baixados {len(corpus)-1} bundles JS", file=sys.stderr)

    paths, urls, gqls, envs, secrets, smaps, hosts = set(), set(), set(), set(), set(), set(), set()
    for src, text in corpus.items():
        for m in RE_PATH.finditer(text):   paths.add(m.group(1))
        for m in RE_ABSPATH.finditer(text): paths.add(m.group(1))
        for u in RE_URL.findall(text):
            h = urlparse(u).netloc.split(":")[0]
            hosts.add(h); urls.add(u.split("?")[0])
        for a1, b1 in RE_GQL.findall(text):
            g = a1 or b1
            if g and g not in ("query", "mutation"): gqls.add(g)
        for k, v in RE_ENV.findall(text):  envs.add(f"{k}={v}")
        for sm in RE_SOURCEMAP.findall(text): smaps.add(urljoin(src, sm))
        for s in RE_SECRET.findall(text):  secrets.add(mask(s))
        for g in RE_GKEY.findall(text):    secrets.add(mask(g))

    # --- computa tudo primeiro (a saída — texto ou JSON — só formata isto) ---
    tgt_hosts = {h for h in hosts if (not scopes or in_scope(h, scopes))}
    api_paths = sorted(p for p in paths if re.search(r'/(api|v1|v2|v3|graphql|gql|auth|oauth|oidc|token|verify|device|pay|wallet|admin|internal|me|account|session)(/|$|\?)', p))
    other_paths = sorted(set(paths) - set(api_paths))

    # __NEXT_DATA__ (SSR): vaza runtimeConfig/env/apiUrl/flags
    nd = set()
    for m in RE_NEXTDATA.finditer(html):
        blob = m.group(1)
        for k, v in re.findall(r'"([A-Za-z0-9_]*(?:url|Url|URL|api|API|endpoint|host|Host|env|baseUrl|clientId|domain|audience)[A-Za-z0-9_]*)"\s*:\s*"([^"]{1,120})"', blob):
            nd.add(f"{k} = {v}")

    # SOURCE MAPS: valida de verdade (fetch) — .map real começa com {"version":3
    real_maps = set()
    for sm in sorted(smaps)[:20]:
        body, st = fetch(sm, a.timeout)
        if body.lstrip()[:60].find('"version"') != -1 and body.lstrip().startswith("{"):
            real_maps.add(f"{sm}  [HTTP {st}] ★ MAP REAL (fonte recuperável)")
        else:
            real_maps.add(f"{sm}  [HTTP {st}] (fallback/não-map)")

    # FINGERPRINT DE STACK -> PLAYBOOK dirigido
    joined = "\n".join(corpus.values())
    fingerprints = [{"name": name, "playbook": playbook}
                    for pat, name, playbook in FINGERPRINTS if re.search(pat, joined, re.I)]

    # --- saída JSON (consumida pelo saquear.py) ---
    if a.json:
        print(json.dumps({
            "url": a.url,
            "api_endpoints": api_paths,
            "other_paths": other_paths,
            "hosts": sorted(tgt_hosts),
            "graphql_ops": sorted(gqls),
            "env_config": sorted(envs),
            "next_data": sorted(nd),
            "source_maps": sorted(real_maps),
            "fingerprints": fingerprints,
            "secrets_masked": sorted(secrets),
        }, ensure_ascii=False, indent=2))
        return

    # --- saída texto (uso manual) ---
    def dump(title, items, limit=250):
        items = sorted(items)
        print(f"\n===== {title} ({len(items)}) =====")
        for x in items[:limit]: print(x)

    dump("API ENDPOINTS (alto valor)", api_paths)
    dump("OUTRAS ROTAS", other_paths, 200)
    dump("HOSTS (in-scope)" if scopes else "HOSTS", tgt_hosts)
    dump("GRAPHQL OPS", gqls)
    dump("ENV/CONFIG expostos", envs)
    dump("__NEXT_DATA__ (config/URLs SSR)", nd, 60)
    dump("SOURCE MAPS (validados)", real_maps)

    print("\n===== STACK FINGERPRINT -> PLAYBOOK =====")
    if fingerprints:
        for fp in fingerprints:
            print(f"  ● {fp['name']}\n      → {fp['playbook']}")
    else:
        print("  (nenhuma assinatura conhecida — inspecione ENV/rotas manualmente)")

    if secrets:
        dump("⚠ POSSÍVEIS SEGREDOS (mascarados — NUNCA gravar no Hive)", secrets)

    kws = [k.strip() for k in a.context.split(",") if k.strip()]
    if kws:
        for kw in kws:
            snips = set()
            for text in corpus.values():
                for m in re.finditer(re.escape(kw), text):
                    s = max(0, m.start() - 90); e = m.end() + 90
                    snips.add(text[s:e].replace("\n", " "))
            dump(f"CONTEXTO '{kw}'", snips, 40)

if __name__ == "__main__":
    sys.exit(main())
