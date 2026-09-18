#!/usr/bin/env python3
"""Diagnóstico MCP legado.

Mantido para compatibilidade com o teste v0.0.1. O fluxo normal deve usar as
ferramentas MCP do agente. Não há launcher, programa ou ativo hardcoded.
"""

from __future__ import annotations

import argparse
import json
import os
import selectors
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Cliente diagnóstico stdio do Hive MCP")
    parser.add_argument("--launcher", default=os.environ.get("HIVE_MCP_LAUNCHER"))
    parser.add_argument("--list-tools", action="store_true")
    args = parser.parse_args()
    if not args.launcher:
        print("ERRO: defina HIVE_MCP_LAUNCHER ou passe --launcher", file=sys.stderr)
        return 2

    process = subprocess.Popen(
        [args.launcher], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1,
    )
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    request_id = 0

    def send(method: str, params: dict, wants_reply: bool = True):
        nonlocal request_id
        request_id += 1
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        if wants_reply:
            message["id"] = request_id
        assert process.stdin is not None
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
        if not wants_reply:
            return None
        if not selector.select(timeout=30):
            raise RuntimeError(f"timeout: {method}")
        assert process.stdout is not None
        response = json.loads(process.stdout.readline())
        if response.get("id") != request_id or "error" in response:
            raise RuntimeError(json.dumps(response, ensure_ascii=False))
        return response["result"]

    try:
        initialized = send("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "excalibull-hive-diagnostic", "version": "1.0"},
        })
        send("notifications/initialized", {}, wants_reply=False)
        output = {"serverInfo": initialized.get("serverInfo")}
        if args.list_tools:
            output["tools"] = send("tools/list", {}).get("tools", [])
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0
    finally:
        selector.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    raise SystemExit(main())
