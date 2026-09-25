#!/usr/bin/env python3
"""
file_path_guard.py — hook PreToolUse (Write/Edit/MultiEdit) do Excalibull.

Bloqueia Write/Edit em arquivos de report que referenciam paths locais
(screenshots, PoCs, evidências) que NÃO existem no disco. Respalda a regra
"nunca alucine arquivos" (CLAUDE.md / mistakes.md) com enforcement real.

Resolve cada path relativo contra a pasta do próprio report, a raiz do projeto
E o CWD (existir em qualquer uma basta); paths absolutos são checados como estão,
sem allowlist de prefixo.

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
# Referências HTML embutidas no markdown (src=/href= com extensão de artefato).
_HTML_RE = re.compile(
    rf'(?:src|href)\s*=\s*["\']([^"\']+?\.(?:{_EXTENSIONS}))["\']',
    re.IGNORECASE,
)

# Alvos de report que este hook guarda.
_REPORT_MARKERS = ("reports/", "findings/", "poc/", "/report.md", "-report.md",
                   "/report-", "/draft", "finding.md")

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def extract_paths(content: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for rx in (_PATH_RE, _HTML_RE):
        for match in rx.finditer(content):
            for group in match.groups():
                if group and group not in seen:
                    seen.add(group)
                    paths.append(group)
    return paths


def is_local_path(path: str) -> bool:
    return not path.startswith(
        ("http://", "https://", "//", "mailto:", "tel:", "#", "data:")
    )


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


def _content_of(payload: dict) -> str:
    tool = payload.get("tool_name")
    inp = payload.get("tool_input") or {}
    if tool == "MultiEdit":
        return "\n".join(str(e.get("new_string", "")) for e in (inp.get("edits") or []))
    return str(inp.get("content") or inp.get("new_string") or "")


def _report_dir(target: str) -> Path:
    tp = Path(target)
    if tp.is_absolute():
        return tp.parent
    return (PROJECT_ROOT / tp).parent


def _exists_anywhere(path: str, bases: list[Path]) -> bool:
    p = Path(path)
    if p.is_absolute():
        try:
            return p.exists()
        except OSError:
            return False
    rel = path.lstrip("./")
    for base in bases:
        try:
            if (base / rel).exists():
                return True
        except OSError:
            continue
    return False


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
    if not content:
        return 0

    bases = [_report_dir(target), PROJECT_ROOT, Path.cwd()]
    missing: list[str] = []
    for path in extract_paths(content):
        if not is_local_path(path):
            continue
        if not _exists_anywhere(path, bases) and path not in missing:
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
