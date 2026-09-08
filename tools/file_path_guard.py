#!/usr/bin/env python3
"""
file_path_guard.py — hook PreToolUse (Write/Edit) do Excalibull.

Bloqueia Write/Edit em arquivos de report que referenciam paths locais
(screenshots, PoCs, evidências) que NÃO existem no disco. Respalda a regra
"nunca alucine arquivos" (CLAUDE.md / mistakes.md) com enforcement real.

Stdin: JSON do evento. Stdout: vazio (permite) ou {"decision":"block"}.
Exit code: sempre 0.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_EXTENSIONS = (
    "html|htm|png|jpg|jpeg|gif|svg|webp|mp4|mov|webm|pdf|txt|json|yaml|yml|"
    "py|sh|js|har|pcap|log"
)
_PATH_RE = re.compile(
    rf"`([^`\s]+?\.(?:{_EXTENSIONS}))`"
    rf"|!\[[^\]]*\]\(([^)\s]+?)\)"
    rf"|\[[^\]]*\]\(([^)\s]+?\.(?:{_EXTENSIONS}))\)"
)

# Alvos de report que este hook guarda. Inclui reports/, findings/, poc/,
# report.md, -report.md, e o padrão do sword targets/<alvo>/report-*.md.
_REPORT_MARKERS = ("reports/", "findings/", "poc/", "/report.md", "-report.md", "/report-")


def extract_paths(content: str) -> list[str]:
    paths: list[str] = []
    for match in _PATH_RE.finditer(content):
        for group in match.groups():
            if group:
                paths.append(group)
    return paths


def is_local_path(path: str) -> bool:
    if path.startswith(("http://", "https://", "//", "mailto:", "tel:", "#")):
        return False
    if path.startswith("/") and not path.startswith(
        ("/poc", "/reports", "/evidence", "/recon", "/scans", "/findings")
    ):
        return False
    return True


def is_report_target(file_path: str) -> bool:
    return any(marker in file_path for marker in _REPORT_MARKERS)


def read_payload() -> dict | None:
    try:
        raw = sys.stdin.read()
    except Exception:
        return None
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def main() -> int:
    payload = read_payload()
    if not payload:
        return 0

    if payload.get("tool_name") not in ("Write", "Edit"):
        return 0

    tool_input = payload.get("tool_input") or {}
    target = tool_input.get("file_path", "")
    if not is_report_target(target):
        return 0

    content = tool_input.get("content") or tool_input.get("new_string") or ""
    if not content:
        return 0

    cwd = Path.cwd()
    missing: list[str] = []
    for path in extract_paths(content):
        if not is_local_path(path):
            continue
        resolved = (cwd / path.lstrip("/")).resolve() if path.startswith("/") else (cwd / path).resolve()
        if not resolved.exists() and path not in missing:
            missing.append(path)

    if missing:
        preview = ", ".join(missing[:5])
        more = "" if len(missing) <= 5 else f" (+{len(missing) - 5} outros)"
        reason = (
            f"BLOQUEADO: o report referencia arquivos locais inexistentes: {preview}{more}. "
            "Pela regra 'nunca alucine arquivos', todo artefato citado precisa existir no "
            "disco antes de entrar num report. Crie os arquivos agora (Write da PoC/screenshot) "
            "ou remova as referências."
        )
        sys.stdout.write(json.dumps({"decision": "block", "reason": reason}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
