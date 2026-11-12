"""Jobs locais em segundo plano, compartilhados pelo Carrasco e pelo Vigia (stdlib).

Um job é um diretório privado `<raiz>/<job_id>/` com o snapshot da entrada, o
journal (`result.json`), o log do worker e `job.json` (pid/criação). Este módulo
só gerencia o ciclo de vida local: nunca emite tráfego, nunca reinicia um
worker morto e nunca lê credenciais.

- Liveness: `worker_state` distingue worker vivo, encerrado e **morto com journal
  não terminal** (`dead`), para que `wait` não espere para sempre.
- Cancelamento cooperativo: `request_cancel` grava um arquivo-sinal que o worker
  consulta entre passos. O worker decide o que é interrompível (ex.: a
  restauração obrigatória do Carrasco nunca é).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

from hive_documents import now
from hive_outbox import private_write

JOB_ID = re.compile(r"[a-f0-9]{32}")
CANCEL_FILE = "cancel"


def job_directory(root: Path, job: str) -> Path:
    if not isinstance(job, str) or not JOB_ID.fullmatch(job):
        raise ValueError("ID de job inválido")
    return Path(root) / job


def spawn(script: Path, argv: list[str], directory: Path, job: str, cwd: Path) -> int:
    """Lança o worker destacado (sessão própria, sem stdin, sem shell) e registra o pid."""
    with (directory / "worker.log").open("wb") as output:
        os.chmod(directory / "worker.log", 0o600)
        process = subprocess.Popen([sys.executable, str(Path(script).resolve()), *argv],
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                   cwd=cwd, start_new_session=True)
    private_write(directory / "job.json", json.dumps({"job_id": job, "pid": process.pid, "created_at": now()}))
    return process.pid


def pid_alive(pid) -> bool | None:
    """True/False quando determinável; None quando não há como saber."""
    if type(pid) is not int or pid <= 0:
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # Existe, mas pertence a outro usuário (pid reciclado é possível).
    except OSError:
        return None
    # Zumbi conta como morto: o processo terminou e só aguarda o pai coletá-lo.
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        if fields and fields[0] == "Z":
            return False
    except (OSError, IndexError):
        pass
    return True


def worker_state(directory: Path, terminal: bool) -> str:
    """`alive`, `exited` (terminou), `dead` (morreu sem journal terminal) ou `unknown`."""
    try:
        pid = json.loads((Path(directory) / "job.json").read_text()).get("pid")
    except (OSError, ValueError, AttributeError):
        return "unknown"
    alive = pid_alive(pid)
    if alive is None:
        return "unknown"
    if alive:
        return "alive"
    return "exited" if terminal else "dead"


def request_cancel(directory: Path) -> bool:
    """Grava o sinal de cancelamento. Retorna False se já havia sido pedido."""
    path = Path(directory) / CANCEL_FILE
    if path.exists():
        return False
    private_write(path, json.dumps({"requested_at": now()}))
    return True


def cancel_requested(directory: Path) -> bool:
    return (Path(directory) / CANCEL_FILE).exists()


def list_jobs(root: Path) -> list[str]:
    """IDs de job sob a raiz, do mais recente ao mais antigo."""
    root = Path(root)
    if not root.is_dir():
        return []
    found = [p for p in root.iterdir() if p.is_dir() and JOB_ID.fullmatch(p.name) and (p / "result.json").exists()]
    found.sort(key=lambda p: (p / "result.json").stat().st_mtime, reverse=True)
    return [p.name for p in found]
