#!/usr/bin/env python3
"""extract.py — primitivas de extração compartilhadas do Excalibull.

Fonte única dos regexes de recon (URL / API-path / secret / google-key / host),
do mascaramento de segredos e do filtro de escopo. Antes isto vivia duplicado em
jsrecon.py (texto/str) e apkrecon.py (bytes) e podia divergir. Aqui o SOURCE do
padrão é um só; compilamos para str ou bytes conforme o consumidor.

Uso (texto):     from extract import PATTERNS_TEXT as P; P.api_path.finditer(js)
Uso (bytes):     from extract import patterns; P = patterns(as_bytes=True)
Escopo/mask:     from extract import mask, in_scope
"""

from __future__ import annotations

import re
from types import SimpleNamespace

# User-Agent padrão do projeto (também reexportado por netcommon quando existir).
DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

# Keywords de path de API — UNIÃO das listas que jsrecon e apkrecon mantinham
# separadas (cada tool agora enxerga o superset).
API_KEYWORDS = (
    "api|v1|v2|v3|graphql|gql|auth|oauth2?|oidc|admin|internal|rpc|mobile|"
    "user|users|me|account|wallet|pay|payment|transaction|transfer|tx|device|"
    "token|verify|session|balance|nullifier|proof|attestation|_next/data"
)

# --- SOURCES dos padrões (str). Compilados p/ str ou bytes em patterns(). ---
_API_PATH_SRC = r'["\'\x60](/(?:' + API_KEYWORDS + r')[A-Za-z0-9_\-./:{}$]*)'
_URL_SRC = r'https?://[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?:/[A-Za-z0-9_\-./:{}$?=&%~]*)?'
# Segredos de alto valor. AIza (google key) fica separado em _GKEY_SRC.
_SECRET_SRC = (
    r'AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{20,}|'
    r'xox[baprs]-[0-9A-Za-z\-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|'
    r'eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}'
)
_GKEY_SRC = r'AIza[0-9A-Za-z_\-]{35}'
# Host genérico (sem alvo hardcoded — o filtro de escopo decide o que interessa).
_HOST_SRC = r'(?:[a-z0-9](?:[a-z0-9\-]{0,62})\.)+[a-z]{2,63}'
# Firebase / GCS buckets (útil em recon mobile).
_FIRE_SRC = r'[a-z0-9\-]+\.(?:firebaseio\.com|firebaseapp\.com|appspot\.com)|gs://[a-z0-9._\-]+'
# Deep-link / custom URL schemes.
_SCHEME_SRC = r'\b([a-z][a-z0-9+.\-]{2,30})://'

_SOURCES = {
    "url": (_URL_SRC, 0),
    "api_path": (_API_PATH_SRC, 0),
    "secret": (_SECRET_SRC, 0),
    "gkey": (_GKEY_SRC, 0),
    "host": (_HOST_SRC, re.IGNORECASE),
    "firebase": (_FIRE_SRC, re.IGNORECASE),
    "scheme": (_SCHEME_SRC, 0),
}

# Schemes comuns que NÃO são deep-link interessante.
COMMON_SCHEMES = {"http", "https", "content", "file", "android", "market", "tel",
                  "mailto", "sms", "geo", "data", "javascript", "about", "ftp"}


def patterns(as_bytes: bool = False) -> SimpleNamespace:
    """Devolve um namespace de padrões compilados (str por padrão, bytes se pedido)."""
    ns = {}
    for name, (src, flags) in _SOURCES.items():
        if as_bytes:
            ns[name] = re.compile(src.encode("latin-1"), flags)
        else:
            ns[name] = re.compile(src, flags)
    return SimpleNamespace(**ns)


# Conjunto pré-compilado para consumidores de texto (jsrecon).
PATTERNS_TEXT = patterns(as_bytes=False)


def mask(s) -> str:
    """Mascara um segredo p/ log/nota. Aceita str ou bytes; nunca revela o valor todo."""
    if isinstance(s, bytes):
        s = s.decode("utf-8", "replace")
    return s[:6] + "…" + s[-4:] if len(s) > 14 else s[:4] + "…"


def in_scope(host: str, scopes) -> bool:
    """True se host == escopo ou é subdomínio de um escopo (endsWith .escopo)."""
    if isinstance(host, bytes):
        host = host.decode("utf-8", "replace")
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in scopes)


def split_scopes(csv: str) -> list[str]:
    """Normaliza uma CSV de escopos ('a.com, *.b.com') → ['a.com','b.com']."""
    out = []
    for raw in (csv or "").split(","):
        s = raw.strip().lower().lstrip("*.").rstrip(".")
        if s:
            out.append(s)
    return out
