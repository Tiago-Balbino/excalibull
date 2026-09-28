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
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from file_safety import atomic_write_text
from hive_instance import resolve_data_dir, workspace

PROGRAM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SLUG_RE = re.compile(r"[^a-z0-9_-]+")
DOCUMENT_TYPES = {"note", "evidence", "asset", "endpoint"}
CLASSIFICATIONS = {"internal", "restricted"}
PROJECT_ROOT = Path(__file__).resolve().parent.parent


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
    info = workspace(args.data_dir, getattr(args, "instance", None))
    programs = Path(info["programs_dir"])
    if getattr(args, "json", False):
        print(json.dumps({"source": "local-writer-directories", "remote_completeness": "unknown",
                          "instance_root": info["instance_root"],
                          "program_ids": sorted(p.name for p in programs.iterdir() if p.is_dir() and PROGRAM_RE.fullmatch(p.name))
                          if programs.is_dir() else []}))
        return 0
    if not programs.is_dir():
        print(f"ERRO: catalogo Hive ausente em {programs}", file=sys.stderr)
        return 2
    for item in sorted(programs.iterdir()):
        if item.is_dir() and PROGRAM_RE.fullmatch(item.name):
            print(item.name)
    return 0


def cmd_note(args: argparse.Namespace) -> int:
    data_dir = resolve_data_dir(args.data_dir, getattr(args, "instance", None), writer=True)
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
    atomic_write_text(target, frontmatter + body.rstrip() + "\n")
    print(target)
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    info = workspace(getattr(args, "data_dir", None), getattr(args, "instance", None), writer=True)
    launcher = Path(info["ingest_launcher"]).resolve()
    override = args.hive_bin or os.environ.get("HIVE_BIN")
    if override and Path(override).expanduser().resolve() != launcher:
        raise ValueError("hive-bin diverge do launcher da instância selecionada")
    if not launcher.is_file():
        raise ValueError("launcher da instância ausente; instale/configure o Hive")
    completed = subprocess.run([str(launcher), "ingest"], cwd=info["instance_root"], check=False)
    return completed.returncode


def cmd_workspace(args):
    print(json.dumps(workspace(args.data_dir, args.instance), ensure_ascii=False, indent=2))
    return 0


def program_id(name):
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    result = _slug(ascii_name)[:64]
    return _program(result)


def cmd_create_program(args):
    data_dir = resolve_data_dir(args.data_dir, args.instance, writer=True)
    pid = program_id(args.name)
    handle = _slug(args.handle)
    team = _slug(args.team or os.environ.get("HIVE_TEAM_TAG") or "excalibull")
    body = Path(args.input).read_text(encoding="utf-8") if args.input else sys.stdin.read()
    if not body.strip():
        raise ValueError("aguarde o conteúdo fornecido pelo operador antes de criar a ficha")
    forbidden = re.compile(r"(?i)(authorization:\s*bearer|set-cookie:|private key|session[_ -]?cookie|password\s*[=:])")
    if forbidden.search(body):
        raise ValueError("possível credencial: revise/higienize o conteúdo antes de criar a ficha")
    folder = data_dir / "programs" / pid
    folder.parent.mkdir(parents=True, exist_ok=True)
    # mkdir exclusivo: colisões nunca sobrescrevem um programa existente.
    folder.mkdir(exist_ok=False)
    (folder / "notes").mkdir()
    (folder / "evidence").mkdir()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    name = args.name.replace('\n', ' ').strip()
    platform = args.platform.replace('\n', ' ').strip()
    text = (f"---\nprogram_id: {pid}\ndocument_type: note\nclassification: internal\nsource: excalibull\n"
            f"collected_at: {stamp}\ntags: {_yaml_list([team, handle, 'excalibull', 'program-profile'])}\n"
            f"asset_refs: {_yaml_list(sorted(set(args.asset)))}\n---\n# {name}\n\n"
            f"- Program ID: `{pid}`\n- Plataforma: {platform}\n- Inserido por: {_slug(args.handle)}\n\n"
            "## Informações fornecidas\n\n" + body.rstrip() + "\n\n"
            "## Lacunas e autorização\n\nInformações ausentes permanecem desconhecidas. "
            "Escopo fornecido é observação: esta ficha não aprova ativos nem altera scope.json/rules.md.\n")
    target = folder / "notes" / f"{_slug(args.handle)}-excalibull-ficha-{stamp[:10]}.md"
    atomic_write_text(target, text)
    print(json.dumps({"program_id": pid, "directory": str(folder), "files": [str(target)],
                      "publication": "pending-ingest-idle-readback"}, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Workspace writer do Hive para o Excalibull")
    sub = parser.add_subparsers(dest="command", required=True)
    meta = sub.add_parser("workspace", help="metadados da instância, sem tokens/configuração completa")
    meta.add_argument("--instance")
    meta.add_argument("--data-dir")
    meta.set_defaults(func=cmd_workspace)
    catalog = sub.add_parser("catalog", help="lista program_id locais do writer")
    catalog.add_argument("--data-dir")
    catalog.add_argument("--instance")
    catalog.add_argument("--json", action="store_true")
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
    note.add_argument("--instance")
    note.add_argument("--replace", action="store_true")
    note.set_defaults(func=cmd_note)
    ingest = sub.add_parser("ingest", help="executa a CLI writer; prefira MCP ingest_workspace")
    ingest.add_argument("--hive-bin")
    ingest.add_argument("--instance")
    ingest.add_argument("--data-dir")
    ingest.set_defaults(func=cmd_ingest)
    create = sub.add_parser("create-program", help="auxiliar casa nova; cria ficha sem aprovar escopo")
    create.add_argument("--name", required=True)
    create.add_argument("--platform", required=True)
    create.add_argument("--handle", required=True)
    create.add_argument("--team")
    create.add_argument("--input")
    create.add_argument("--asset", action="append", default=[])
    create.add_argument("--instance")
    create.add_argument("--data-dir")
    create.set_defaults(func=cmd_create_program)
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
