#!/usr/bin/env python3
"""Cria handoffs validos no workspace canonico do Hive Mind.

Consultas devem usar as ferramentas MCP. Este utilitario cobre somente o lado
writer: catalogo local, criacao de notas e execucao opcional da CLI de ingestao.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROGRAM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SLUG_RE = re.compile(r"[^a-z0-9_-]+")
DOCUMENT_TYPES = {"note", "evidence", "asset", "endpoint"}
CLASSIFICATIONS = {"internal", "restricted"}
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def resolve_data_dir(value: str | None = None) -> Path:
    raw = value or os.environ.get("HIVE_DATA_DIR")
    if raw:
        return Path(raw).expanduser().resolve()
    sibling = PROJECT_ROOT.parent / "hive_mind" / "hive-data"
    if sibling.is_dir():
        return sibling.resolve()
    raise ValueError("defina HIVE_DATA_DIR ou passe --data-dir")


def _program(value: str) -> str:
    if not PROGRAM_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("program_id invalido")
    return value


def _slug(value: str) -> str:
    cleaned = SLUG_RE.sub("-", value.lower()).strip("-_")
    if not cleaned:
        raise ValueError("slug vazio")
    return cleaned[:80]


def _yaml_list(values: list[str]) -> str:
    return json.dumps(values, ensure_ascii=False)


def cmd_catalog(args: argparse.Namespace) -> int:
    programs = resolve_data_dir(args.data_dir) / "programs"
    if not programs.is_dir():
        print(f"ERRO: catalogo Hive ausente em {programs}", file=sys.stderr)
        return 2
    for item in sorted(programs.iterdir()):
        if item.is_dir() and PROGRAM_RE.fullmatch(item.name):
            print(item.name)
    return 0


def cmd_note(args: argparse.Namespace) -> int:
    data_dir = resolve_data_dir(args.data_dir)
    team = args.team or os.environ.get("HIVE_TEAM_TAG")
    handle = args.handle or os.environ.get("HIVE_HANDLE")
    if not team or not handle:
        raise ValueError("informe --team/--handle ou HIVE_TEAM_TAG/HIVE_HANDLE")
    body = Path(args.input).read_text(encoding="utf-8") if args.input else sys.stdin.read()
    if not body.strip():
        raise ValueError("a nota nao pode estar vazia")
    forbidden = re.compile(r"(?i)(authorization:\s*bearer|set-cookie:|private key|session[_ -]?cookie|password\s*[=:])")
    if forbidden.search(body):
        raise ValueError("possivel segredo/credencial detectado; higienize a nota antes de publicar")

    folder = "evidence" if args.document_type == "evidence" else "notes"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    date = stamp[:10]
    filename = f"{_slug(handle)}-excalibull-{_slug(args.slug)}-{date}.md"
    target = data_dir / "programs" / args.program / folder / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not args.replace:
        raise ValueError(f"nota ja existe: {target}; use --replace para atualizar o handoff do dia")
    tags = sorted({_slug(team), _slug(handle), "excalibull", *(_slug(tag) for tag in args.tag)})
    assets = sorted(set(args.asset))
    frontmatter = (
        "---\n"
        f"program_id: {args.program}\n"
        f"document_type: {args.document_type}\n"
        f"classification: {args.classification}\n"
        "source: excalibull\n"
        f"collected_at: {stamp}\n"
        f"tags: {_yaml_list(tags)}\n"
        f"asset_refs: {_yaml_list(assets)}\n"
        "---\n"
    )
    target.write_text(frontmatter + body.rstrip() + "\n", encoding="utf-8")
    print(target)
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    hive_bin = args.hive_bin or os.environ.get("HIVE_BIN")
    if not hive_bin:
        sibling = PROJECT_ROOT.parent / "hive_mind" / "bin" / "hive-mind"
        hive_bin = str(sibling) if sibling.is_file() else None
    if not hive_bin:
        raise ValueError("defina HIVE_BIN ou passe --hive-bin; no agente, prefira ingest_workspace")
    completed = subprocess.run([str(Path(hive_bin).expanduser()), "ingest"], check=False)
    return completed.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Workspace writer do Hive para o Excalibull")
    sub = parser.add_subparsers(dest="command", required=True)
    catalog = sub.add_parser("catalog", help="lista program_id locais do writer")
    catalog.add_argument("--data-dir")
    catalog.set_defaults(func=cmd_catalog)
    note = sub.add_parser("note", help="cria nota/handoff canonico")
    note.add_argument("program", type=_program)
    note.add_argument("slug", help="assunto curto usado no nome do arquivo")
    note.add_argument("--input", help="Markdown sem front matter; omita para stdin")
    note.add_argument("--document-type", choices=sorted(DOCUMENT_TYPES), default="note")
    note.add_argument("--classification", choices=sorted(CLASSIFICATIONS), default="internal")
    note.add_argument("--asset", action="append", default=[], required=True)
    note.add_argument("--tag", action="append", default=[])
    note.add_argument("--team")
    note.add_argument("--handle")
    note.add_argument("--data-dir")
    note.add_argument("--replace", action="store_true")
    note.set_defaults(func=cmd_note)
    ingest = sub.add_parser("ingest", help="executa a CLI writer; prefira MCP ingest_workspace")
    ingest.add_argument("--hive-bin")
    ingest.set_defaults(func=cmd_ingest)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
