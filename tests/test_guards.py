#!/usr/bin/env python3
"""Testes dos guards de enforcement do Excalibull.

Cobre scope_hook, validity_guard, cvss_version_guard, file_path_guard e o
recibos exatos em hive_scope_cache. Os hooks são exercitados como
o harness os chama (stdin JSON → stdout JSON); a lógica de biblioteca é importada
direto. Rode com: python3 -m pytest tests/test_guards.py -q
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))


def run_hook(tool: str, payload: dict, cwd: Path | None = None) -> str:
    """Roda um hook via subprocess (como o harness) e devolve o stdout."""
    proc = subprocess.run(
        [sys.executable, str(TOOLS / tool)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=str(cwd or ROOT),
    )
    return proc.stdout


def is_block(out: str) -> bool:
    return '"decision": "block"' in out or '"decision":"block"' in out


def is_deny(out: str) -> bool:
    return '"permissionDecision": "deny"' in out or '"permissionDecision":"deny"' in out


# ---------------------------------------------------------------- scope_hook
UNAUTH = "nao-autorizado-teste.example"  # host que nunca terá recibo


def _bash(cmd: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


def test_scope_hook_blocks_url_without_receipt():
    assert is_block(run_hook("scope_hook.py", _bash(f"curl -s https://{UNAUTH}/x")))


def test_scope_hook_blocks_webfetch_without_receipt():
    out = run_hook("scope_hook.py",
                   {"tool_name": "WebFetch", "tool_input": {"url": f"https://{UNAUTH}/y"}})
    assert is_block(out)


def test_scope_hook_blocks_bare_host_with_fetch_cmd():
    assert is_block(run_hook("scope_hook.py", _bash(f"curl -s {UNAUTH}")))


def test_scope_hook_allows_local_script():
    # setup.sh existe na raiz → não é host
    assert run_hook("scope_hook.py", _bash("bash setup.sh")).strip() == ""


def test_scope_hook_allows_non_network_command():
    assert run_hook("scope_hook.py", _bash("ls -la")).strip() == ""


def test_scope_hook_allows_python_module():
    assert run_hook("scope_hook.py", _bash("python3 -m json.tool")).strip() == ""


def test_scope_hook_collision_file_does_not_bypass_when_fetch_present(tmp_path):
    # arquivo local com nome de host NÃO pode liberar tráfego quando há curl
    (tmp_path / UNAUTH).write_text("x")
    assert is_block(run_hook("scope_hook.py", _bash(f"curl -s {UNAUTH}"), cwd=tmp_path))


def test_scope_hook_fail_closed_on_backend_unavailable(monkeypatch):
    import scope_hook
    monkeypatch.setattr(scope_hook, "authorization_for", None)
    monkeypatch.setattr(scope_hook, "_IMPORT_ERR", RuntimeError("boom"))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(_bash(f"curl https://{UNAUTH}"))))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    scope_hook.main()
    assert is_block(out.getvalue())


def test_scope_hook_fail_closed_on_backend_exception(monkeypatch):
    import scope_hook

    def boom(_host):
        raise RuntimeError("consulta quebrou")

    monkeypatch.setattr(scope_hook, "authorization_for", boom)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(_bash(f"curl https://{UNAUTH}"))))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    scope_hook.main()
    assert is_block(out.getvalue())


def test_scope_hook_backend_error_does_not_block_hostless_command(monkeypatch):
    import scope_hook
    monkeypatch.setattr(scope_hook, "authorization_for", None)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(_bash("ls -la"))))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    scope_hook.main()
    assert out.getvalue().strip() == ""


# ------------------------------------------------------------- validity_guard
def _write(path: str, content: str) -> dict:
    return {"tool_name": "Write", "tool_input": {"file_path": path, "content": content}}


def test_validity_denies_signal_without_chain():
    out = run_hook("validity_guard.py",
                   _write("reports/finding.md", "Achei um open redirect no returnTo."))
    assert is_deny(out)


def test_validity_allows_signal_chained_nearby():
    out = run_hook("validity_guard.py",
                   _write("reports/finding.md",
                          "open redirect chaineado com roubo de code OAuth, leva a ATO."))
    assert out.strip() == ""


def test_validity_denies_when_chain_far_from_signal():
    body = "Achei um open redirect no returnTo.\n" + ("linha\n" * 8) + \
           "Noutra secao menciono account takeover de bug diferente."
    assert is_deny(run_hook("validity_guard.py", _write("reports/finding.md", body)))


def test_validity_ignores_non_report():
    assert run_hook("validity_guard.py",
                    _write("docs/notes.md", "open redirect sozinho")).strip() == ""


def test_validity_covers_non_md_report():
    assert is_deny(run_hook("validity_guard.py",
                            _write("targets/x/report-draft.txt", "achei self-xss no nome")))


def test_validity_killlist_parity_with_markdown():
    """Toda entrada da kill-list de never-submit.md vira sinal (sem drift)."""
    import validity_guard as v
    signals = v.load_killlist_signals()
    assert len(signals) >= 15
    # frases-chave que precisam existir vindas do .md
    for expected in ("open redirect", "cors wildcard", "self-xss", "clickjacking"):
        assert expected in signals


# --------------------------------------------------------- cvss_version_guard
def test_cvss_blocks_v4_on_hackerone():
    out = run_hook("cvss_version_guard.py",
                   _write("targets/coinspot/report-x.md", "CVSS:4.0/AV:N/AC:L"))
    assert is_block(out)


def test_cvss_allows_v31_on_hackerone():
    out = run_hook("cvss_version_guard.py",
                   _write("targets/coinspot/report-x.md", "CVSS:3.1/AV:N/AC:L"))
    assert out.strip() == ""


def test_cvss_blocks_v31_on_bugcrowd_reverse():
    out = run_hook("cvss_version_guard.py",
                   _write("targets/etoro/report-x.md", "CVSS:3.1/AV:N/AC:L"))
    assert is_block(out)


def test_cvss_allows_unknown_platform():
    out = run_hook("cvss_version_guard.py",
                   _write("reports/generic.md", "CVSS:4.0/AV:N/AC:L"))
    assert out.strip() == ""


# ----------------------------------------------------------- file_path_guard
def test_fpg_blocks_missing_relative_artifact():
    out = run_hook("file_path_guard.py",
                   _write("reports/finding.md", "PoC: ![s](evidence/nao-existe-xyz.png)"))
    assert is_block(out)


def test_fpg_allows_existing_artifact():
    out = run_hook("file_path_guard.py",
                   _write("reports/finding.md", "veja `setup.sh` na raiz"))
    assert out.strip() == ""


def test_fpg_blocks_missing_absolute_in_ref():
    out = run_hook("file_path_guard.py",
                   _write("reports/finding.md", "![s](/tmp/nao-existe-xyz-poc.png)"))
    assert is_block(out)


def test_fpg_blocks_html_src():
    out = run_hook("file_path_guard.py",
                   _write("reports/finding.md", '<img src="shots/missing-xyz.png">'))
    assert is_block(out)


def test_fpg_ignores_non_report():
    out = run_hook("file_path_guard.py",
                   _write("docs/notes.md", "![s](evidence/whatever.png)"))
    assert out.strip() == ""


def test_fpg_handles_multiedit():
    payload = {"tool_name": "MultiEdit", "tool_input": {
        "file_path": "reports/finding.md",
        "edits": [{"new_string": "![x](evidence/faltando-xyz.png)"}]}}
    assert is_block(run_hook("file_path_guard.py", payload))


# A CLI de recibos não admite aprovação por documento local.
def test_local_scope_command_is_not_available():
    import hive_scope_cache as cache
    with pytest.raises(SystemExit) as error:
        cache.main(["record-scope", "example", "--revision", "a" * 64])
    assert error.value.code == 2


# ------------------------------------- preflight de escopo (recon/cors #14)
def test_preflight_loopback_ok_and_unknown_blocked(monkeypatch, tmp_path):
    import hive_scope_cache as h
    monkeypatch.setattr(h, "CACHE_PATH", tmp_path / "cache.json")  # cache vazio
    res = {host: ok for host, ok, _ in h.preflight(["127.0.0.1", "nada.example"])}
    assert res["127.0.0.1"] is True   # loopback isento
    assert res["nada.example"] is False


def test_require_authorized_exits_fail_closed(monkeypatch, tmp_path):
    import hive_scope_cache as h
    monkeypatch.setattr(h, "CACHE_PATH", tmp_path / "cache.json")
    with pytest.raises(SystemExit) as ei:
        h.require_authorized(["nada.example"], "recon.py")
    assert ei.value.code == 2


def test_require_authorized_passes_for_loopback(monkeypatch, tmp_path):
    import hive_scope_cache as h
    monkeypatch.setattr(h, "CACHE_PATH", tmp_path / "cache.json")
    h.require_authorized(["localhost"], "recon.py")  # não deve levantar


if __name__ == "__main__":
    raise SystemExit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-q"]))
