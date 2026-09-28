#!/usr/bin/env python3
"""Recon web médio/completo: crawl limitado por URL/recibo, sem scanners implícitos."""
import argparse
import json
import sys
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urldefrag

from browser_recon import authorized
from hive_workspace import _program
from netcommon import RateLimiter, http_get
from recon_records import request_record, safe_path


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = set()
    def handle_starttag(self, tag, attrs):
        if tag in {"a", "link", "iframe"}:
            for key, value in attrs:
                if key in {"href", "src"} and value:
                    self.urls.add(value)


def crawl(program, url, *, max_pages=20, depth=2, rate=1):
    queue, seen, records, pages, blocked = deque([(url, 0)]), set(), [], [], set()
    limiter = RateLimiter(rate)
    origin = (urlsplit(url).scheme, urlsplit(url).netloc)
    def gate(target):
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or not authorized(target, program):
            raise PermissionError("sem recibo vigente")
    while queue and len(seen) < max_pages:
        target, level = queue.popleft()
        if target in seen:
            continue
        seen.add(target)
        label = f"{urlsplit(target).hostname}{safe_path(urlsplit(target).path)}"
        try:
            body, status = http_get(target, limiter=limiter, authorize=gate, retries=0)
        except PermissionError:
            blocked.add(label)
            pages.append({"asset": label, "status": "blocked"})
            continue
        pages.append({"asset": label, "http_status": status, "status": "observed" if status > 0 else "failed"})
        records.append(request_record(target, "GET", source="active-recon", status=status))
        if status <= 0 or status >= 400:
            continue
        parser = Links()
        parser.feed(body)
        for link in sorted(parser.urls):
            child = urldefrag(urljoin(target, link))[0]
            parsed = urlsplit(child)
            if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
                continue
            records.append(request_record(child, source="crawl-link"))
            # Somente links do mesmo origin; cada um é revalidado antes do GET.
            if (parsed.scheme, parsed.netloc) != origin or level >= depth:
                continue
            if any(part in parsed.path.lower().split('/') for part in
                   ("logout", "delete", "remove", "reset", "unsubscribe", "purchase", "refund")):
                continue
            if child not in seen:
                queue.append((child, level + 1))
    pending = len({u for u, _ in queue} - seen)
    partial = bool(pending or blocked or any(p["status"] == "failed" for p in pages))
    return {"program_id": program, "records": records, "pages": pages,
            "coverage": {"status": "partial" if partial else "collected", "pages_attempted": len(seen),
                         "page_limit": max_pages, "depth_limit": depth, "pages_pending": pending,
                         "blocked": sorted(blocked), "interpretation": "crawl limitado; não comprova superfície completa"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program", type=_program)
    parser.add_argument("url")
    parser.add_argument("--level", choices=("medium", "full"), default="medium")
    parser.add_argument("--max-pages", type=int)
    parser.add_argument("--rate", type=float, default=1)
    args = parser.parse_args()
    pages = args.max_pages if args.max_pages is not None else (60 if args.level == "full" else 20)
    if pages < 1 or args.rate <= 0:
        parser.error("max-pages >=1 e rate >0")
    data = crawl(args.program, args.url, max_pages=pages, depth=4 if args.level == "full" else 2, rate=args.rate)
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 1 if data["coverage"]["status"] == "partial" else 0


if __name__ == "__main__":
    sys.exit(main())
