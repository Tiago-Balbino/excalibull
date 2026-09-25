#!/usr/bin/env python3
"""
cvss_version_guard.py — hook PreToolUse (Write/Edit/MultiEdit) do Excalibull.

Bloqueia Write/Edit em report que usa a versão de CVSS ERRADA para a plataforma
do alvo. Política (rules/mistakes.md #7):
  - HackerOne  → CVSS 3.1  (H1 rejeita o form com vetor 4.0)
  - Bugcrowd / Intigriti / Immunefi / YesWeHack → CVSS 4.0

Bloqueia nos dois sentidos: vetor 4.0 num alvo H1 E vetor 3.x num alvo 4.0-only.

A plataforma é lida do `target.yml` do alvo cuja pasta contém o report
(`targets/<slug>/...`); fallback pra `platform:`/`plataforma:` de um scope.yaml na
raiz. Parse YAML real (PyYAML) com fallback pra regex de linha. Plataforma
ausente/desconhecida → permite (não bloqueia workspace de outra plataforma).

Stdin: JSON do evento. Stdout: vazio (permite) ou {"decision":"block"}.
Exit code: sempre 0.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_CVSS_4_RE = re.compile(r"CVSS:4\.0/", re.IGNORECASE)
_CVSS_3_RE = re.compile(r"CVSS:3\.[01]/", re.IGNORECASE)
_PLATFORM_RE = re.compile(r"^\s*platform:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_PLATAFORMA_RE = re.compile(r"^\s*plataforma:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)

_REPORT_MARKERS = ("reports/", "findings/", "/report.md", "-report.md", "/report-",
                   "/draft", "finding.md")

# Versão de CVSS exigida por plataforma.
PLATFORM_CVSS: dict[str, str] = {
    "hackerone": "3.1",
    "h1": "3.1",
    "bugcrowd": "4.0",
    "intigriti": "4.0",
    "immunefi": "4.0",
    "yeswehack": "4.0",
    "ywh": "4.0",
}

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def is_report_target(file_path: str) -> bool:
    return any(marker in file_path for marker in _REPORT_MARKERS)


def _normalize_platform(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().strip('"').strip("'").split("#", 1)[0].strip().lower() or None


def _platform_from_text(text: str) -> str | None:
    # 1) YAML real, quando disponível.
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            for key in ("plataforma", "platform"):
                if key in data:
                    return _normalize_platform(str(data[key]))
    except Exception:
        pass
    # 2) Fallback regex de linha.
    for rx in (_PLATAFORMA_RE, _PLATFORM_RE):
        m = rx.search(text)
        if m:
            return _normalize_platform(m.group(1))
    return None


def platform_for_report(file_path: str) -> str | None:
    """Descobre a plataforma do alvo dono do report."""
    p = Path(file_path)
    parts = p.parts
    if "targets" in parts:
        i = parts.index("targets")
        if i + 1 < len(parts):
            slug = parts[i + 1]
            yml = PROJECT_ROOT / "targets" / slug / "target.yml"
            if yml.exists():
                try:
                    return _platform_from_text(yml.read_text())
                except OSError:
                    pass
    root_scope = PROJECT_ROOT / "scope.yaml"
    if root_scope.exists():
        try:
            return _platform_from_text(root_scope.read_text())
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


def _content_of(payload: dict) -> str:
    tool = payload.get("tool_name")
    inp = payload.get("tool_input") or {}
    if tool == "MultiEdit":
        return "\n".join(str(e.get("new_string", "")) for e in (inp.get("edits") or []))
    return str(inp.get("content") or inp.get("new_string") or "")


def _block(reason: str) -> int:
    sys.stdout.write(json.dumps({"decision": "block", "reason": reason}))
    return 0


def main() -> int:
    payload = read_payload()
    if not payload:
        return 0
    if payload.get("tool_name") not in ("Write", "Edit", "MultiEdit"):
        return 0

    tool_input = payload.get("tool_input") or {}
    target = tool_input.get("file_path", "")
    if not is_report_target(target):
        return 0

    content = _content_of(payload)
    has4 = bool(_CVSS_4_RE.search(content))
    has3 = bool(_CVSS_3_RE.search(content))
    if not (has3 or has4):
        return 0

    required = PLATFORM_CVSS.get(platform_for_report(target) or "")
    if required is None:
        return 0  # plataforma desconhecida → não bloqueia (fail-open por design)

    if required == "3.1" and has4:
        return _block(
            "BLOQUEADO: HackerOne exige CVSS 3.1 e rejeita o form com vetor 4.0. "
            "Recalcule com CVSS:3.1/... (tire AT/VC/VI/VA/SC/SI/SA; use S:U ou S:C e "
            "C:/I:/A:) antes de escrever este report."
        )
    if required == "4.0" and has3:
        return _block(
            "BLOQUEADO: esta plataforma usa CVSS 4.0 (Bugcrowd/Intigriti/Immunefi/"
            "YesWeHack), mas o report tem vetor 3.x. Recalcule com CVSS:4.0/... antes "
            "de escrever este report."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
