#!/usr/bin/env python3
"""Consulta o catálogo remoto e prepara contribuições locais para um writer.

Preparação/exportação não equivale a publicação. O cliente oficial hive cuida
do MCP e da autenticação; arquivos locais não concedem escopo.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import hashlib
import io
import tarfile
import sys
import unicodedata
from pathlib import Path
from hive_paths import resolve_data_dir, workspace
from hive_gateway import HiveClient
from hive_documents import document, identity
from hive_outbox import Outbox, prepare, safe_path

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


def cmd_catalog(args):
    arguments = {"offset": args.offset, "limit": args.limit, "order": args.order}
    if args.program:
        arguments["program_id"] = args.program
    with HiveClient() as client:
        result = client.catalog(**arguments)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for target in result.get("targets", []):
            print(f"{target['program_id']}\t{target['platform']}\t{target['target_name']}\t{target['scope']['status']}")
        if result.get("next_offset") is not None:
            print(f"Próxima página: --offset {result['next_offset']}", file=sys.stderr)
        for warning in result.get("warnings", []):
            print(f"Catálogo: {warning}", file=sys.stderr)
        if result.get("truncated"):
            print("Catálogo parcial; não inferir completude.", file=sys.stderr)
    return 0


def cmd_note(args: argparse.Namespace) -> int:
    data_dir = resolve_data_dir(args.data_dir)
    body = Path(args.input).read_text(encoding="utf-8") if args.input else sys.stdin.read()
    queue = Outbox(data_dir)
    entry = queue.enqueue(args.program, _slug(args.slug)[:64], body,
                     session=getattr(args, "session", None), replace=args.replace,
                     handle=args.handle, team=args.team, assets=args.asset, tags=args.tag,
                     document_type=args.document_type, classification=args.classification,
                     platform=getattr(args, "platform", None), target_name=getattr(args, "target_name", None),
                     result=getattr(args, "result", "observation"))
    target = safe_path(queue.root, entry["path"])
    if _slug(args.slug) == "handoff":
        from brain import get_brain_dir
        scratch = PROJECT_ROOT / "targets" / args.program / "a-cacada-ate-aqui.md"
        wal = get_brain_dir() / "targets" / f"{args.program}.md"
        if scratch.is_file() and wal.is_file():
            queue.bind_handoff(args.program, target, scratch, wal, entry["session_id"])
    print(target)
    return 0


def cmd_export_legacy(args):
    data = resolve_data_dir(args.data_dir)
    base = data / "programs" / args.program
    if not base.is_dir() or base.is_symlink():
        raise ValueError("programa sem contribuições locais válidas")
    files = sorted(p for p in base.rglob("*") if p.suffix in {".md", ".json", ".txt"})
    if not files:
        raise ValueError("não há documentos para exportar")
    prepared = []
    total = 0
    for path in files:
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(base.resolve()):
            raise ValueError("exportação não aceita symlinks ou caminhos externos")
        if path.name in {"scope.json", "rules.md"}:
            raise ValueError("scope.json/rules.md não são contribuições de sessão")
        with path.open("rb") as source:
            content = source.read(5 * 1024 * 1024 + 1)
        total += len(content)
        if len(content) > 5 * 1024 * 1024 or total > 50 * 1024 * 1024:
            raise ValueError("divida contribuições: limite 5 MiB/arquivo e 50 MiB/pacote")
        if re.search(rb"(?i)(authorization:\s*bearer|set-cookie:|private key|session[_ -]?cookie|password\s*[=:])", content):
            raise ValueError("possível segredo: higienize os documentos antes de exportar")
        prepared.append((path.relative_to(data).as_posix(), content))
    manifest = {"schema_version": 1, "program_id": args.program, "publication": "pending-writer",
                "files": [{"path": name, "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
                          for name, content in prepared]}
    destination = Path(args.output).expanduser().resolve()
    if destination.is_relative_to(base.resolve()):
        raise ValueError("destino do pacote deve ficar fora do programa exportado")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # O_EXCL preserva pacotes anteriores. Nenhuma chamada de rede é feita.
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            for name, content in prepared + [("manifest.json", json.dumps(manifest, indent=2).encode())]:
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode = len(content), 0o600
                archive.addfile(entry, io.BytesIO(content))
    print(json.dumps({"package": str(destination), **manifest}, ensure_ascii=False, indent=2))
    return 0


def cmd_export(args):
    if getattr(args, "legacy_files", False):
        print("Exportação legada sem sessão rastreada; não satisfaz o Selo.", file=sys.stderr)
        return cmd_export_legacy(args)
    result = Outbox(args.data_dir).export(args.program, args.output, getattr(args, "session", None))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_workspace(args):
    print(json.dumps(workspace(args.data_dir), ensure_ascii=False, indent=2))
    return 0


def program_id(name):
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    result = _slug(ascii_name)[:64]
    return _program(result)


def cmd_create_program(args):
    data_dir = resolve_data_dir(args.data_dir)
    pid = program_id(args.name)
    handle, team = identity(args.handle, args.team)
    body = Path(args.input).read_text(encoding="utf-8") if args.input else sys.stdin.read()
    if not body.strip():
        raise ValueError("aguarde o conteúdo fornecido pelo operador antes de criar a ficha")
    forbidden = re.compile(r"(?i)(authorization:\s*bearer|set-cookie:|private key|session[_ -]?cookie|password\s*[=:])")
    if forbidden.search(body):
        raise ValueError("possível credencial: revise/higienize o conteúdo antes de criar a ficha")
    document(pid, body, handle=handle, team=team, assets=args.asset,
             platform=args.platform, target_name=args.name)
    folder = data_dir / "programs" / pid
    folder.parent.mkdir(parents=True, exist_ok=True)
    # mkdir exclusivo: colisões nunca sobrescrevem um programa existente.
    folder.mkdir(exist_ok=False)
    (folder / "notes").mkdir()
    (folder / "evidence").mkdir()
    name = args.name.replace('\n', ' ').strip()
    platform = args.platform.replace('\n', ' ').strip()
    text = (f"# {name}\n\n"
            f"- Program ID: `{pid}`\n- Plataforma: {platform}\n- Inserido por: {_slug(args.handle)}\n\n"
            "## Informações fornecidas\n\n" + body.rstrip() + "\n\n"
            "## Lacunas e autorização\n\nInformações ausentes permanecem desconhecidas. "
            "Escopo fornecido é observação: esta ficha não aprova ativos nem altera scope.json/rules.md.\n")
    target = prepare(pid, "ficha", text, data_dir=data_dir, session=getattr(args, "session", None),
                     handle=handle, team=team, assets=args.asset, platform=platform,
                     target_name=name, tags=["program-profile"])
    print(json.dumps({"program_id": pid, "directory": str(folder), "files": [str(target)],
                      "publication": "pending-writer"}, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    meta = sub.add_parser("workspace", help="metadados do staging local, sem credenciais")
    meta.add_argument("--data-dir")
    meta.set_defaults(func=cmd_workspace)
    catalog = sub.add_parser("catalog", help="catálogo remoto paginado de projetos")
    catalog.add_argument("--program", type=_program)
    catalog.add_argument("--offset", type=int, default=0)
    catalog.add_argument("--limit", type=int, default=10)
    catalog.add_argument("--order", choices=["balanced", "most_documented", "needs_recon"], default="balanced")
    catalog.add_argument("--json", action="store_true")
    catalog.set_defaults(func=cmd_catalog)
    note = sub.add_parser("note", help="prepara nota/handoff pendente de writer")
    note.add_argument("program", type=_program)
    note.add_argument("slug", help="assunto curto usado no nome do arquivo")
    note.add_argument("--input", help="Markdown sem front matter; omita para stdin")
    note.add_argument("--document-type", choices=sorted(DOCUMENT_TYPES), default="note")
    note.add_argument("--classification", choices=sorted(CLASSIFICATIONS), default="internal")
    note.add_argument("--asset", action="append", default=[], required=True)
    note.add_argument("--tag", action="append", default=[])
    note.add_argument("--platform", type=_program)
    note.add_argument("--target-name")
    note.add_argument("--team")
    note.add_argument("--handle")
    note.add_argument("--data-dir")
    note.add_argument("--replace", action="store_true", help="conteúdo alterado cria uma nova revisão imutável")
    note.add_argument("--session")
    note.add_argument("--result", choices=["observation", "hypothesis", "confirmed", "discarded", "inconclusive"], default="observation")
    note.set_defaults(func=cmd_note)
    export = sub.add_parser("export", help="empacota contribuições para entrega a writer; não publica")
    export.add_argument("program", type=_program)
    export.add_argument("--data-dir")
    export.add_argument("--output", required=True)
    export.add_argument("--session")
    export.add_argument("--legacy-files", action="store_true", help="inventário legado explícito; não satisfaz o Selo")
    export.set_defaults(func=cmd_export)
    create = sub.add_parser("create-program", help="casa nova: prepara ficha sem aprovar escopo ou publicar")
    create.add_argument("--name", required=True)
    create.add_argument("--platform", type=_program, required=True)
    create.add_argument("--handle", required=True)
    create.add_argument("--team")
    create.add_argument("--input")
    create.add_argument("--asset", action="append", default=[])
    create.add_argument("--data-dir")
    create.add_argument("--session")
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
