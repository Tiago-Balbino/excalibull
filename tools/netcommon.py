#!/usr/bin/env python3
"""netcommon.py — HTTP compartilhado (stdlib puro) do Excalibull.

Fonte única do User-Agent, do throttle (rate-limit) e de um GET com gzip +
retry/backoff. Antes cada fetcher tinha seu próprio UA e o jsrecon carregava um
throttle via estado GLOBAL de módulo (não-reentrante se importado). Aqui o
throttle é um objeto thread-safe e reentrante.

Mantém-se stdlib-only de propósito: jsrecon é "stdlib pura" e adota isto sem
puxar dependência. Tools baseadas em `requests`/`curl_cffi` (cors_headers_scan,
resolve_doh) podem usar só o UA e o RateLimiter.

Uso:
    from netcommon import RateLimiter, http_get, DEFAULT_UA
    lim = RateLimiter(3)          # 3 req/s
    text, status = http_get(url, timeout=15, limiter=lim)
"""

from __future__ import annotations

import gzip
import io
import threading
import time
import urllib.error
import urllib.request

try:
    from extract import DEFAULT_UA  # fonte única do UA
except Exception:  # pragma: no cover - fallback se extract mudar de lugar
    DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

# Códigos HTTP que valem retry (transitórios).
_RETRY_CODES = {429, 500, 502, 503, 504}


class RateLimiter:
    """Throttle reentrante e thread-safe: no máximo `rate` req/s no total.

    rate<=0 → sem limite (wait() é no-op). Compartilhe UMA instância entre
    threads pra ter um teto GLOBAL de req/s (importante em alvos manual-only).
    """

    def __init__(self, rate: float = 0.0):
        self._lock = threading.Lock()
        self._last = 0.0
        self.set_rate(rate)

    def set_rate(self, rate: float) -> None:
        self.min_interval = (1.0 / rate) if rate and rate > 0 else 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delay = self.min_interval - (now - self._last)
            if delay > 0:
                time.sleep(delay)
            self._last = time.monotonic()


def http_get(url: str, timeout: float = 15, limiter: "RateLimiter | None" = None,
             headers: dict | None = None, retries: int = 2, backoff: float = 0.5,
             ua: str = DEFAULT_UA, authorize=None) -> tuple[str, int]:
    """GET stdlib com descompressão gzip + retry/backoff em erro transitório.

    Retorna (texto, status). status <= 0 indica erro de rede após os retries;
    um 4xx (exceto 429) volta imediatamente (repetir não ajuda).
    """
    h = {"User-Agent": ua, "Accept-Encoding": "gzip"}
    if headers:
        h.update(headers)
    opener = None
    if authorize:
        class CheckedRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                if limiter:
                    limiter.wait()
                authorize(newurl)
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        opener = urllib.request.build_opener(CheckedRedirect())
    attempt = 0
    while True:
        if limiter:
            limiter.wait()
        try:
            if authorize:
                authorize(url)
            req = urllib.request.Request(url, headers=h)
            with (opener.open(req, timeout=timeout) if opener else urllib.request.urlopen(req, timeout=timeout)) as r:
                raw = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
                return raw.decode("utf-8", "replace"), r.status
        except PermissionError:
            raise
        except urllib.error.HTTPError as e:
            if e.code in _RETRY_CODES and attempt < retries:
                attempt += 1
                time.sleep(backoff * attempt)
                continue
            return "", e.code
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt < retries:
                attempt += 1
                time.sleep(backoff * attempt)
                continue
            return "", -1
