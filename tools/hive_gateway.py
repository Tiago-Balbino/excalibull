#!/usr/bin/env python3
"""Consulta o MCP oficial por stdio. Login, HTTPS e tokens pertencem ao hive."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time

MAX_MESSAGE_BYTES = 2 * 1024 * 1024


class HiveError(ValueError):
    pass


class HiveClient:
    def __init__(self, *, command=None, timeout=30, writer_config=None, writer_workspace=None):
        self.timeout = timeout
        self.messages = queue.Queue(maxsize=64)
        self.sequence = 0
        self.process = None
        try:
            if bool(writer_config) != bool(writer_workspace):
                raise HiveError("writer exige configuração e workspace explícitos")
            invocation = ["hive", "mind"]
            if writer_config:
                config, workspace = Path(writer_config).expanduser().resolve(), Path(writer_workspace).expanduser().resolve()
                if not config.is_file() or not workspace.is_dir() or config.is_relative_to(workspace):
                    raise HiveError("configuração do writer deve existir fora do workspace")
                invocation += ["--config", str(config), "--data-dir", str(workspace), "--role", "writer"]
            env = os.environ.copy()
            # O adaptador operacional usa modo remoto; configuração de servidor
            # herdada de outro shell não pode trocar silenciosamente o backend.
            for key in ("HIVE_ID", "QDRANT_URL", "HIVE_DATA_DIR", "HIVE_ROLE"):
                env.pop(key, None)
            self.process = subprocess.Popen(command or invocation, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
            threading.Thread(target=self._read, daemon=True).start()
            self._rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                      "clientInfo": {"name": "excalibull", "version": "1"}})
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            result = self._rpc("tools/list", {})
            self.tools = {item["name"] for item in result.get("tools", []) if isinstance(item, dict)
                          and isinstance(item.get("name"), str)}
        except (OSError, HiveError, ValueError, TypeError, AttributeError):
            self.close()
            raise HiveError("MCP Hive indisponível; confira hive install mind, hive login e hive doctor") from None

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(MAX_MESSAGE_BYTES + 1)
                if not line or len(line) > MAX_MESSAGE_BYTES:
                    self.messages.put(None)
                    return
                message = json.loads(line)
                if not isinstance(message, dict):
                    self.messages.put(None)
                    return
                self.messages.put(message)
        except (OSError, ValueError):
            self.messages.put(None)

    def _send(self, message):
        encoded = (json.dumps(message) + "\n").encode()
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise HiveError("requisição MCP excede o limite")
        try:
            self.process.stdin.write(encoded)
            self.process.stdin.flush()
        except (OSError, ValueError):
            raise HiveError("MCP Hive encerrou a conexão") from None

    def _rpc(self, method, params):
        self.sequence += 1
        ident = self.sequence
        self._send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HiveError("tempo limite na consulta ao Hive")
            try:
                response = self.messages.get(timeout=remaining)
            except queue.Empty:
                raise HiveError("tempo limite na consulta ao Hive") from None
            if response is None:
                raise HiveError("resposta MCP ausente ou inválida")
            if response.get("id") != ident:
                continue
            if "error" in response or not isinstance(response.get("result"), dict):
                raise HiveError("consulta Hive rejeitada; confira argumentos, login e diagnóstico")
            return response["result"]

    def call(self, name, arguments, *, accept_ingestion_error=False):
        if name not in self.tools:
            raise HiveError(f"capacidade {name} não anunciada pelo MCP")
        try:
            result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        except HiveError:
            from hive_scope_cache import invalidate
            invalidate()
            raise
        if result.get("isError") and not (name == "ingest_workspace" and accept_ingestion_error):
            from hive_scope_cache import invalidate
            invalidate()
            raise HiveError(f"operação {name} falhou; publicação não confirmada")
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return {**structured, "_mcp_is_error": result.get("isError") is True} if name == "ingest_workspace" else structured
        text = "\n".join(item.get("text", "") for item in result.get("content", [])
                         if isinstance(item, dict) and item.get("type") == "text")
        if name == "get_sync_status":
            match = re.search(r"\*\*Status:\*\*\s*`([a-z_]+)`", text)
            status = match.group(1) if match else "unknown"
            if status == "unknown":
                from hive_scope_cache import invalidate
                invalidate()
            return {"status": status, "queue_confirmed": status == "idle"}
        mcp_is_error = result.get("isError") is True
        try:
            result = json.loads(text)
        except ValueError:
            raise HiveError("Hive não retornou conteúdo estruturado") from None
        if not isinstance(result, dict):
            raise HiveError("contrato Hive inválido")
        return {**result, "_mcp_is_error": mcp_is_error} if name == "ingest_workspace" else result

    def ingest_report(self):
        # Falhas de lote vêm em content[].text com isError; é preciso
        # preservar os outcomes, inclusive publicação seguida de falha.
        return self.call("ingest_workspace", {}, accept_ingestion_error=True)

    def catalog(self, **arguments):
        return self.call("hive_list_targets", arguments)

    def context(self, program, asset, question):
        result = self.call("hive_get_context", {"program_id": program, "asset": asset, "question": question})
        from hive_scope_cache import normalize_asset
        if result.get("program_id") != program or normalize_asset(result.get("asset")) != normalize_asset(asset):
            from hive_scope_cache import invalidate
            invalidate()
            raise HiveError("resposta de contexto não corresponde ao programa/ativo solicitado")
        scope = result.get("scope", {})
        if not isinstance(scope, dict) or scope.get("confirmed") is not True or scope.get("action_allowed") is not True:
            from hive_scope_cache import invalidate
            invalidate()
        return result

    def close(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        for pipe in (self.process.stdin, self.process.stdout):
            if pipe:
                pipe.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("capabilities")
    catalog = sub.add_parser("catalog")
    catalog.add_argument("--program")
    catalog.add_argument("--offset", type=int, default=0)
    catalog.add_argument("--limit", type=int, default=10)
    catalog.add_argument("--order", choices=["balanced", "most_documented", "needs_recon"], default="balanced")
    search = sub.add_parser("search")
    search.add_argument("program")
    search.add_argument("query")
    context = sub.add_parser("context")
    context.add_argument("program")
    context.add_argument("asset")
    context.add_argument("question")
    context.add_argument("--type", choices=["host", "ip", "url_prefix"], default="url_prefix")
    context.add_argument("--record", action="store_true", help="materializa veredito e seleciona programa")
    args = parser.parse_args(argv)
    try:
        with HiveClient() as client:
            if args.command == "capabilities":
                result = {"tools": sorted(client.tools), "local_upload": False}
            elif args.command == "status":
                result = client.call("get_sync_status", {})
            elif args.command == "catalog":
                arguments = {"offset": args.offset, "limit": args.limit, "order": args.order}
                if args.program:
                    arguments["program_id"] = args.program
                result = client.catalog(**arguments)
            elif args.command == "search":
                result = client.call("hive_search", {"program_id": args.program, "query": args.query})
            else:
                result = client.context(args.program, {"type": args.type, "value": args.asset}, args.question)
                if args.record:
                    from hive_scope_cache import record_context
                    record_context(result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if args.command == "status" and result.get("status") == "unknown" else 0
    except (HiveError, ValueError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
