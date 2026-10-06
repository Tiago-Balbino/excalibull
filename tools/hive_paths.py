"""Arquivos locais preparados para entrega ao writer; nunca autoridade do Hive."""
from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def resolve_data_dir(value=None):
    """--data-dir é um staging local; não lê configuração ou credenciais do servidor."""
    return Path(value or os.environ.get("EXCALIBULL_OUTBOX_DIR")
                or PROJECT_ROOT / ".hive" / "outbox").expanduser().resolve()


def workspace(data_dir=None):
    data = resolve_data_dir(data_dir)
    return {"schema_version": 2, "mode": "remote", "data_dir": str(data),
            "programs_dir": str(data / "programs"), "source": "excalibull-local-outbox",
            "publication": "pending-writer", "mcp_command": ["hive", "mind"]}
