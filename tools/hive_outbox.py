#!/usr/bin/env python3
"""Fila durável por sessão. Exportação e entrega não confirmam publicação."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import uuid

from file_safety import locked_file
from hive_documents import identifier, document, render, now, MAX_DOCUMENT_BYTES
from hive_paths import resolve_data_dir

SCHEMA_VERSION = 1


def safe_path(root, relative):
    root = Path(root).resolve()
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in {".", ".."} for p in parts) or "\\" in str(relative):
        raise ValueError("path relativo inválido")
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("outbox/workspace não aceita symlink")
    if not path.resolve().is_relative_to(root):
        raise ValueError("path fora do diretório selecionado")
    return path


def private_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as output:
        temporary = Path(output.name)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    try:
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def session_identifier(value):
    identifier(value)
    if value.startswith("active-"):
        raise ValueError("prefixo active- reservado aos ponteiros de sessão")
    return value


class Outbox:
    def __init__(self, data_dir=None):
        self.root = resolve_data_dir(data_dir)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)

    def manifest_path(self, session):
        return safe_path(self.root, f"sessions/{session_identifier(session)}.json")

    def load(self, session, program=None):
        path = self.manifest_path(session)
        try:
            state = json.loads(path.read_text())
        except (OSError, ValueError):
            raise ValueError("manifesto ausente/corrompido; preserve os arquivos e recupere a sessão") from None
        if not isinstance(state, dict) or type(state.get("schema_version")) is not int or state.get("schema_version") != SCHEMA_VERSION or state.get("session_id") != session or not isinstance(state.get("contributions"), dict) or not isinstance(state.get("expected"), dict):
            raise ValueError("contrato de manifesto inválido")
        identifier(state.get("program_id"))
        if program is not None and state["program_id"] != program:
            raise ValueError("sessão pertence a outro programa")
        for cid, revision in state["expected"].items():
            contribution = state["contributions"].get(cid)
            if not isinstance(contribution, dict) or contribution.get("current_revision") != revision or type(revision) is not int or revision < 1 or len(contribution.get("revisions", [])) != revision:
                raise ValueError("conjunto esperado diverge do manifesto")
            for number, entry in enumerate(contribution['revisions'], 1):
                if not isinstance(entry, dict) or entry.get('id') != cid or entry.get('revision') != number or type(entry.get('bytes')) is not int or not isinstance(entry.get('path'), str) or not isinstance(entry.get('sha256'), str) or not isinstance(entry.get('content_sha256'), str) or not isinstance(entry.get('attempts'), list):
                    raise ValueError("revisão inválida no manifesto")
        if set(state["expected"]) != set(state["contributions"]):
            raise ValueError("contribuição fora do conjunto esperado")
        return state

    def _save(self, state):
        state["updated_at"] = now()
        private_write(self.manifest_path(state["session_id"]), json.dumps(state, ensure_ascii=False, indent=2) + "\n")

    @contextmanager
    def edit(self, session, program=None):
        with locked_file(self.manifest_path(session)):
            state = self.load(session, program)
            yield state
            self._save(state)

    def start(self, program, session=None, *, reuse_active=False):
        identifier(program)
        session = session_identifier(session or uuid.uuid4().hex)
        pointer = safe_path(self.root, f"sessions/active-{program}.json")
        with locked_file(pointer):
            if reuse_active and pointer.exists():
                session = session_identifier(json.loads(pointer.read_text())["session_id"])
                self.load(session, program)
                return session
            with locked_file(self.manifest_path(session)):
                if self.manifest_path(session).exists():
                    state = self.load(session, program)
                else:
                    state = {"schema_version": SCHEMA_VERSION, "session_id": session, "program_id": program,
                             "created_at": now(), "status": "open", "expected": {}, "contributions": {},
                             "exports": [], "ingestion_ok": False, "verification": None}
                    self._save(state)
                private_write(pointer, json.dumps({"session_id": session}))
        return session

    def session(self, program, requested=None, *, create=False):
        identifier(program)
        requested = requested or os.environ.get("EXCALIBULL_SESSION_ID")
        if requested:
            requested = session_identifier(requested)
            if not self.manifest_path(requested).exists() and create:
                return self.start(program, requested)
            self.load(requested, program)
            return requested
        pointer = safe_path(self.root, f"sessions/active-{program}.json")
        with locked_file(pointer):
            if pointer.exists():
                try:
                    session = session_identifier(json.loads(pointer.read_text())["session_id"])
                except (ValueError, KeyError, TypeError):
                    raise ValueError("ponteiro de sessão corrompido; não iniciar silenciosamente outra sessão") from None
                self.load(session, program)
                return session
        if create:
            return self.start(program, reuse_active=True)
        raise ValueError("nenhuma sessão ativa; use hive_outbox.py start <program>")

    @staticmethod
    def current(state):
        return [state["contributions"][cid]["revisions"][revision - 1]
                for cid, revision in sorted(state["expected"].items())]

    def bytes_for(self, state, entry):
        path = entry.get("path", "")
        if not path.startswith(f"programs/{state['program_id']}/") or Path(path).name in {"scope.json", "rules.md"}:
            raise ValueError("contribuição fora do programa ou documento de escopo")
        with safe_path(self.root, path).open("rb") as source:
            content = source.read(MAX_DOCUMENT_BYTES + 1)
        if len(content) > MAX_DOCUMENT_BYTES or len(content) != entry["bytes"] or hashlib.sha256(content).hexdigest() != entry["sha256"]:
            raise ValueError("arquivo preparado diverge do hash; prepare uma nova revisão")
        return content

    def enqueue(self, program, subject, body, *, session=None, replace=True, **metadata):
        identifier(subject)
        prepared = document(program, body, **metadata)
        session = self.session(program, session, create=True)
        # Autores e projetos diferentes nunca substituem a mesma contribuição.
        logical = [session, subject, prepared["metadata"]["handle"],
                   prepared["metadata"].get("platform"), prepared["metadata"].get("target_name")]
        cid = hashlib.sha256(json.dumps(logical, ensure_ascii=False).encode()).hexdigest()[:24]
        with self.edit(session, program) as state:
            contribution = state["contributions"].get(cid)
            if contribution:
                previous = contribution["revisions"][-1]
                if previous["content_sha256"] == prepared["content_sha256"]:
                    self.bytes_for(state, previous)
                    return previous
                if not replace:
                    raise ValueError("contribuição já preparada; use --replace para criar uma nova revisão")
            else:
                contribution = {"id": cid, "subject": subject, "handle": prepared["metadata"]["handle"],
                                "team": prepared["metadata"]["team"], "assets": prepared["assets"],
                                "classification": prepared["metadata"]["classification"],
                                "document_type": prepared["metadata"]["document_type"],
                                "project": {k: prepared["metadata"].get(k) for k in ("platform", "target_name")}, "revisions": []}
                state["contributions"][cid] = contribution
            revision = len(contribution["revisions"]) + 1
            text, marker, witness = render(prepared, session, cid, revision)
            folder = "evidence" if prepared["metadata"]["document_type"] == "evidence" else "notes"
            name = f"{prepared['metadata']['handle']}-excalibull-{subject}-{session}-{cid}-r{revision}.md"
            relative = f"programs/{program}/{folder}/{name}"
            path = safe_path(self.root, relative)
            # Um crash após escrever a nota pode ser retomado; conteúdo diferente
            # jamais substitui um arquivo imutável existente.
            if path.exists():
                existing = path.read_text()
                # Recupera nota escrita antes de uma queda no commit do
                # manifesto; somente a data automática pode diferir.
                comparable = lambda value: "\n".join(line for line in value.splitlines() if not line.startswith("collected_at:"))
                if comparable(existing) != comparable(text):
                    raise ValueError("revisão já existe com outro conteúdo; preserve o arquivo")
                text = existing
            else:
                private_write(path, text)
            entry = {"id": cid, "session_id": session, "revision": revision, "path": relative, "bytes": len(text.encode()),
                     "sha256": hashlib.sha256(text.encode()).hexdigest(), "content_sha256": prepared["content_sha256"],
                     "marker": marker, "witness": witness, "prepared_at": now(), "state": "pending-writer",
                     "attempts": [], "delivery": None, "verification": None}
            contribution["revisions"].append(entry)
            contribution.update(current_revision=revision, assets=prepared["assets"])
            state["expected"][cid] = revision
            state.update(status="open", ingestion_ok=False, verification=None)
            return entry

    def export(self, program, output, session=None):
        session = self.session(program, session)
        with self.edit(session, program) as state:
            entries = self.current(state)
            if not entries:
                raise ValueError("sessão sem contribuições; pacote vazio não confirma publicação")
            prepared = [(e["path"], self.bytes_for(state, e)) for e in entries]
            if sum(len(b) for _, b in prepared) > 50 * 1024 * 1024:
                raise ValueError("pacote supera 50 MiB; divida a sessão")
            manifest = {"schema_version": SCHEMA_VERSION, "program_id": program, "session_id": session,
                        "publication": "pending-writer", "expected": state["expected"],
                        "files": [{k: e[k] for k in ("id", "revision", "path", "sha256", "bytes", "marker")} for e in entries]}
            destination = Path(output).expanduser().resolve()
            if destination.is_relative_to(self.root):
                raise ValueError("pacote deve ficar fora da outbox")
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                    for name, content in prepared + [("manifest.json", json.dumps(manifest, indent=2).encode())]:
                        entry = tarfile.TarInfo(name)
                        entry.size, entry.mode = len(content), 0o600
                        archive.addfile(entry, io.BytesIO(content))
            state["exports"].append({"at": now(), "expected": state["expected"].copy(),
                                     "package_sha256": hashlib.sha256(destination.read_bytes()).hexdigest()})
            return {"package": str(destination), **manifest}

    def bind_handoff(self, program, path, scratch, wal, session=None):
        """Vincula o handoff ao estado local consolidado, sem apagar o WAL."""
        session = self.session(program, session)
        relative = Path(path).relative_to(self.root).as_posix()
        with self.edit(session, program) as state:
            entry = next((e for e in self.current(state) if e["path"] == relative), None)
            if not entry:
                raise ValueError("handoff não é contribuição atual desta sessão")
            state["handoff"] = {"id": entry["id"], "revision": entry["revision"], "expected": state["expected"].copy(),
                                "scratch_sha256": hashlib.sha256(Path(scratch).read_bytes()).hexdigest(),
                                "wal_sha256": hashlib.sha256(Path(wal).read_bytes()).hexdigest()}


def prepare(program, subject, body, *, data_dir=None, **metadata):
    queue = Outbox(data_dir)
    entry = queue.enqueue(program, subject, body, **metadata)
    return safe_path(queue.root, entry["path"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("start", "status", "export", "publish", "deliver", "ingest", "verify"):
        item = sub.add_parser(name)
        item.add_argument("program", type=identifier)
        item.add_argument("--session", type=session_identifier)
        item.add_argument("--data-dir")
        if name == "export":
            item.add_argument("--output", required=True)
        if name in {"deliver", "ingest"}:
            item.add_argument("--writer-workspace", required=True)
        if name == "ingest":
            item.add_argument("--writer-config", required=True)
    args = parser.parse_args(argv)
    try:
        queue = Outbox(args.data_dir)
        if args.command == "start":
            session = queue.start(args.program, args.session)
            result = queue.load(session)
        elif args.command == "export":
            result = queue.export(args.program, args.output, args.session)
        else:
            session = queue.session(args.program, args.session)
            if args.command == "status":
                result = queue.load(session)
            else:
                from hive_publication import deliver, ingest, ingest_remote, verify
                if args.command == "deliver":
                    result = deliver(queue, session, args.program, args.writer_workspace)
                elif args.command == "ingest":
                    result = ingest(queue, session, args.program, args.writer_workspace, args.writer_config)
                elif args.command == "publish":
                    # Ingestão remota direta seguida de read-back; sem workspace de writer.
                    result = ingest_remote(queue, session, args.program)
                    if result.get("ok"):
                        result = verify(queue, session, args.program)
                else:
                    result = verify(queue, session, args.program)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if result.get("ok") is False else 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
