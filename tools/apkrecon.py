#!/usr/bin/env python3
"""apkrecon — mineração estática de superfície a partir de um APK/XAPK/APKS.

Passivo (não toca o alvo): analisa o binário do app já baixado. Extrai hosts,
endpoints de API, URLs, esquemas de deep-link, cert-pins, config
(Firebase/Google/flags) e possíveis segredos (MASCARADOS). Foco especial no
bundle React Native (assets/*.bundle / index.android.bundle) = app inteiro em JS.

Stdlib-first: zipfile + regex, com fallback puro-Python p/ `strings`. Usa
`aapt`/`aapt2`/`apkanalyzer` p/ o AndroidManifest binário SE existirem.
Aceita .apk, .xapk/.apks/.zip (split APKs aninhados são analisados em conjunto).

Uso:
  python3 tools/apkrecon.py caminho/World.apk [--scope worldcoin.org,world.org,world.app]
  python3 tools/apkrecon.py app.xapk --save /scratch/apk_extract --min-str 6

Não versione o APK nem o dump: são dados crus de alvo (CLAUDE.md). Use scratch.
"""
import argparse, os, re, shutil, subprocess, sys, tempfile, zipfile
from urllib.parse import urlparse

# ---- regexes ----
# Padrões compartilhados vêm de extract.py (fonte única, variante BYTES). O
# RE_HOST agora é GENÉRICO (sem alvo hardcoded) — o filtro de escopo (--scope,
# ver main) decide o que é in-scope. Antes só casava domínios worldcoin.
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)
from extract import mask, in_scope, patterns  # noqa: E402

_P = patterns(as_bytes=True)
RE_URL   = _P.url
RE_HOST  = _P.host           # genérico; filtragem por escopo é feita em main()
RE_PATH  = _P.api_path
RE_SCHEME = _P.scheme
RE_FIRE  = _P.firebase
RE_GKEY  = _P.gkey
RE_SECRET = _P.secret
RE_PIN   = re.compile(rb'sha256/[A-Za-z0-9+/]{43}=')  # cert pins (específico do apkrecon)
TEXT_ASSET = re.compile(r'\.(bundle|js|json|jsbundle|txt|xml|env|cfg|properties|graphql|proto)$', re.I)
COMMON_SCHEMES = {b'http', b'https', b'content', b'file', b'android', b'market', b'tel',
                  b'mailto', b'sms', b'geo', b'data', b'javascript', b'about', b'ftp'}

def py_strings(data, minlen):
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen: out.append(bytes(cur))
            cur = bytearray()
    if len(cur) >= minlen: out.append(bytes(cur))
    return out

def strings_of(path, minlen):
    if shutil.which("strings"):
        try:
            r = subprocess.run(["strings", "-n", str(minlen), path],
                               capture_output=True, timeout=120)
            return r.stdout
        except Exception:
            pass
    with open(path, "rb") as f:
        return b"\n".join(py_strings(f.read(), minlen))

def manifest_dump(apk):
    for tool, args in (("aapt", ["dump", "xmltree", apk, "AndroidManifest.xml"]),
                       ("aapt2", ["dump", "xmltree", "--file", "AndroidManifest.xml", apk]),
                       ("apkanalyzer", ["manifest", "print", apk])):
        if shutil.which(tool):
            try:
                r = subprocess.run([tool, *args], capture_output=True, timeout=60)
                if r.returncode == 0 and r.stdout:
                    return r.stdout.decode("utf-8", "replace")
            except Exception:
                pass
    return ""

def collect_apks(path, workdir):
    """Retorna lista de .apk (extrai xapk/apks/zip)."""
    if path.lower().endswith(".apk"):
        return [path]
    apks = []
    try:
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.lower().endswith(".apk"):
                    z.extract(n, workdir); apks.append(os.path.join(workdir, n))
    except zipfile.BadZipFile:
        pass
    return apks or [path]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk", help="caminho .apk/.xapk/.apks/.zip")
    ap.add_argument("--scope", default="", help="csv de domínios base p/ marcar in-scope")
    ap.add_argument("--save", default="", help="dir p/ salvar assets de texto extraídos (scratch)")
    ap.add_argument("--min-str", type=int, default=6)
    a = ap.parse_args()
    if not os.path.exists(a.apk):
        print(f"ERRO: não achei {a.apk}", file=sys.stderr); return 2
    scopes = [s.strip() for s in a.scope.split(",") if s.strip()]

    urls, hosts, paths, schemes, fire, gkeys, secrets, pins = (set() for _ in range(8))
    corpus = bytearray()
    tmp = tempfile.mkdtemp(prefix="apkrecon_")
    try:
        for apk in collect_apks(a.apk, tmp):
            print(f"[*] APK: {os.path.basename(apk)}", file=sys.stderr)
            # 1) AndroidManifest (pkg, schemes, hosts, exported)
            man = manifest_dump(apk)
            if man:
                corpus += man.encode()
                print(f"    manifest: {len(man)} bytes (parseado)", file=sys.stderr)
            else:
                print("    manifest: binário (instale aapt/apkanalyzer p/ deep-links)", file=sys.stderr)
            # 2) entradas do zip
            try:
                z = zipfile.ZipFile(apk)
            except zipfile.BadZipFile:
                print("    (não é zip válido)", file=sys.stderr); continue
            for info in z.infolist():
                n = info.filename
                low = n.lower()
                if low.endswith(".dex"):
                    p = z.extract(info, tmp)
                    corpus += strings_of(p, a.min_str)
                    print(f"    dex {n}: strings extraídas", file=sys.stderr)
                elif "network_security_config" in low or (low.startswith("res/xml/") and low.endswith(".xml")):
                    corpus += z.read(info)
                elif TEXT_ASSET.search(low) or "assets/" in low:
                    try:
                        data = z.read(info)
                    except Exception:
                        continue
                    corpus += data
                    if low.endswith((".bundle", ".jsbundle")) or "index.android.bundle" in low:
                        print(f"    ★ RN bundle {n}: {len(data)} bytes", file=sys.stderr)
                    if a.save and (TEXT_ASSET.search(low)):
                        os.makedirs(a.save, exist_ok=True)
                        outp = os.path.join(a.save, os.path.basename(n))
                        try:
                            with open(outp, "wb") as f: f.write(data)
                        except Exception:
                            pass
    finally:
        blob = bytes(corpus)
        # ---- extração ----
        for u in RE_URL.findall(blob):
            urls.add(u.split(b"?")[0].decode("utf-8", "replace"))
            hosts.add(urlparse(u.decode("utf-8", "replace")).netloc.split(":")[0])
        for h in RE_HOST.findall(blob): hosts.add(h.decode().lower())
        for p in RE_PATH.findall(blob): paths.add(p.decode("utf-8", "replace"))
        for s in RE_SCHEME.findall(blob):
            if s.lower() not in COMMON_SCHEMES and len(s) <= 24: schemes.add(s.decode())
        for f in RE_FIRE.findall(blob): fire.add(f.decode("utf-8", "replace"))
        for g in RE_GKEY.findall(blob): gkeys.add(mask(g))
        for s in RE_SECRET.findall(blob): secrets.add(mask(s))
        for p in RE_PIN.findall(blob): pins.add(p.decode())
        shutil.rmtree(tmp, ignore_errors=True)

    def dump(title, items, limit=400):
        items = sorted(x for x in items if x)
        print(f"\n===== {title} ({len(items)}) =====")
        for x in items[:limit]: print(x)

    tgt = {h for h in hosts if h and (not scopes or in_scope(h, scopes))}
    api = sorted(p for p in paths if re.search(r'/(api|v1|v2|v3|graphql|gql|auth|oauth|oidc|rpc|token|verify|device|pay|wallet|tx|transfer|balance|nullifier|proof|me|account|session)(/|$|\?|\b)', p))
    dump("HOSTS (in-scope)" if scopes else "HOSTS", tgt)
    if scopes: dump("HOSTS (fora do escopo / 3rd-party)", hosts - tgt, 120)
    dump("API ENDPOINTS (alto valor)", api)
    dump("OUTRAS ROTAS", set(paths) - set(api), 200)
    dump("DEEP-LINK SCHEMES (surface exported)", schemes)
    dump("FIREBASE/STORAGE", fire)
    dump("CERT PINS (sha256)", pins)
    if gkeys: dump("Google API keys (mascaradas)", gkeys)
    if secrets: dump("⚠ POSSÍVEIS SEGREDOS (mascarados — NUNCA gravar no Hive)", secrets)
    print(f"\n[*] URLs totais únicas: {len(urls)} (use --save p/ grep offline)", file=sys.stderr)

if __name__ == "__main__":
    sys.exit(main())
