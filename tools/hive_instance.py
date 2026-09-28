"""Resolve apenas metadados públicos do workspace de uma instância Hive.

Lê config/hive.toml sem exportar valores arbitrários ou carregar writer.jwt.
Escrita e ingestão usam a mesma instância; overrides divergentes são recusados.
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

DEFAULT_INSTANCE = Path(__file__).resolve().parents[2] / "hive_instance"


def workspace(data_dir=None, instance=None, *, writer=False):
    root = Path(instance or os.environ.get("HIVE_INSTANCE_DIR") or DEFAULT_INSTANCE).expanduser().resolve()
    try:
        values = tomllib.loads((root / "config" / "hive.toml").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("config/hive.toml da instância indisponível/inválida; configure HIVE_INSTANCE_DIR") from exc
    configured = values.get("HIVE_DATA_DIR")
    if not isinstance(configured, str) or not configured.strip():
        raise ValueError("instância sem HIVE_DATA_DIR válido")
    data = Path(configured).expanduser()
    data = (data if data.is_absolute() else root / data).resolve()
    override = data_dir or os.environ.get("HIVE_DATA_DIR")
    if override and Path(override).expanduser().resolve() != data:
        raise ValueError("data-dir diverge da instância selecionada; selecione a instância correta")
    role = values.get("HIVE_ROLE")
    if role not in {"reader", "writer"}:
        raise ValueError("HIVE_ROLE da instância deve ser reader ou writer")
    if writer and role != "writer":
        raise ValueError("instância reader: prepare handoff em scratch e entregue a um writer")
    launcher = root / "bin" / "hive-teste"
    if not launcher.is_file():
        launcher = root / "scripts" / "hive-teste"
    return {"schema_version": 1, "instance_root": str(root), "data_dir": str(data),
            "programs_dir": str(data / "programs"), "role": role,
            "ingest_launcher": str(launcher), "source": "hive_instance/config/hive.toml"}


def resolve_data_dir(value=None, instance=None, *, writer=False):
    return Path(workspace(value, instance, writer=writer)["data_dir"])
