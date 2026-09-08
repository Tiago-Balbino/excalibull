#!/usr/bin/env python3
"""
cvss_version_guard.py — hook PreToolUse (Write/Edit) do Excalibull.

Bloqueia Write/Edit em report que usa vetor CVSS:4.0 quando a plataforma do
alvo é HackerOne (H1 não aceita CVSS 4.0 e rejeita o form). Política: H1 → 3.1;
Bugcrowd/Intigriti/Immunefi/YesWeHack → 4.0.

A plataforma é lida do `target.yml` do alvo cuja pasta contém o report
(`targets/<slug>/...`); fallback pra `platform:` de um scope.yaml na raiz.
Plataforma ausente/desconhecida → permite (não bloqueia workspace non-H1).

Stdin: JSON do evento. Stdout: vazio (permite) ou {"decision":"block"}.
Exit code: sempre 0.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_CVSS_4_RE = re.compile(r"CVSS:4\.0/", re.IGNORECASE)
_PLATFORM_RE = re.compile(r"^platform:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_PLATAFORMA_RE = re.compile(r"^plataforma:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)

_REPORT_MARKERS = ("reports/", "findings/", "/report.md", "-report.md", "/report-")

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def is_report_target(file_path: str) -> bool:
    return any(marker in file_path for marker in _REPORT_MARKERS)


def _platform_from_yaml_line(text: str) -> str | None:
    for rx in (_PLATAFORMA_RE, _PLATFORM_RE):
        m = rx.search(text)
        if m:
            return m.group(1).strip().strip('"').strip("'").split("#", 1)[0].strip().lower()
    return None


def platform_for_report(file_path: str) -> str | None:
    """Descobre a plataforma do alvo dono do report.

    1) Se o path está sob targets/<slug>/, lê targets/<slug>/target.yml.
    2) Senão, tenta platform: de um scope.yaml na raiz do projeto.
    """
    p = Path(file_path)
    parts = p.parts
    if "targets" in parts:
        i = parts.index("targets")
        if i + 1 < len(parts):
            slug = parts[i + 1]
            yml = PROJECT_ROOT / "targets" / slug / "target.yml"
            if yml.exists():
                try:
                    return _platform_from_yaml_line(yml.read_text())
                except OSError:
                    pass
    root_scope = PROJECT_ROOT / "scope.yaml"
    if root_scope.exists():
        try:
            return _platform_from_yaml_line(root_scope.read_text())
        except OSError:
            pass
    return None


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
    if not _CVSS_4_RE.search(content):
        return 0

    platform = platform_for_report(target)
    if platform != "hackerone":
        return 0

    reason = (
        "BLOQUEADO: HackerOne não aceita vetores CVSS 4.0. Por política, reports de H1 "
        "usam CVSS:3.1/... Recalcule com CVSS 3.1 (tire AT/VC/VI/VA/SC/SI/SA; use S:U ou "
        "S:C e C:/I:/A:) antes de escrever este report."
    )
    sys.stdout.write(json.dumps({"decision": "block", "reason": reason}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
