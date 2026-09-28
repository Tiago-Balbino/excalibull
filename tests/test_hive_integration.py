from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import sys

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import hive_scope_cache as cache  # noqa: E402
import hive_workspace as workspace  # noqa: E402
import scope_hook  # noqa: E402


class HiveScopeCacheTests(unittest.TestCase):
    def test_authorized_context_is_cached_and_matches_exact_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "scope-cache.json"
            context = {
                "program_id": "demo",
                "asset": {"type": "host", "value": "api.example.com"},
                "scope": {
                    "status": "authorized",
                    "confirmed": True,
                    "action_allowed": True,
                    "scope_revision": "abc123",
                    "matched_rules": [],
                },
            }
            with patch.object(cache, "CACHE_PATH", cache_path):
                cache.record_context(context)
                self.assertTrue(cache.authorization_for("api.example.com")["action_allowed"])
                self.assertIsNone(cache.authorization_for("evil.example.com"))

    def test_expired_receipt_is_not_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "scope-cache.json"
            cache_path.write_text(json.dumps({
                "schema_version": 1,
                "receipts": [{
                    "program_id": "demo",
                    "asset": {"type": "host", "value": "api.example.com"},
                    "status": "authorized",
                    "confirmed": True,
                    "action_allowed": True,
                    "scope_revision": "abc",
                    "expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                }],
            }))
            with patch.object(cache, "CACHE_PATH", cache_path):
                self.assertIsNone(cache.authorization_for("api.example.com"))

    def test_inconsistent_authorization_is_rejected(self) -> None:
        context = {
            "program_id": "demo",
            "asset": {"type": "host", "value": "api.example.com"},
            "scope": {"status": "unknown", "confirmed": False, "action_allowed": True},
        }
        with self.assertRaises(ValueError):
            cache.record_context(context)


class HiveWorkspaceTests(unittest.TestCase):
    def test_note_has_required_hive_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config"
            config.mkdir()
            (config / "hive.toml").write_text(f'HIVE_DATA_DIR = {json.dumps(tmp)}\nHIVE_ROLE = "writer"\n')
            body = Path(tmp) / "body.md"
            body.write_text("# Handoff\n\n## Status\ndiscarded — sem impacto.\n")
            args = argparse.Namespace(
                data_dir=tmp,
                instance=tmp,
                team="team-a",
                handle="alice",
                input=str(body),
                document_type="note",
                classification="internal",
                program="demo",
                slug="handoff",
                tag=["authz"],
                asset=["api.example.com"],
                replace=False,
            )
            self.assertEqual(workspace.cmd_note(args), 0)
            notes = list((Path(tmp) / "programs" / "demo" / "notes").glob("*.md"))
            self.assertEqual(len(notes), 1)
            text = notes[0].read_text()
            self.assertIn("program_id: demo", text)
            self.assertIn("source: excalibull", text)
            self.assertIn('asset_refs: ["api.example.com"]', text)
            self.assertIn("discarded", text)


class ScopeHookTests(unittest.TestCase):
    def test_extracts_urls_and_bare_hosts_but_not_paths(self) -> None:
        hosts = scope_hook.extract_hosts(
            "python3 tools/recon.py api.example.com --url=https://www.example.com/a README.md"
        )
        self.assertEqual(hosts, ["www.example.com", "api.example.com"])

    def test_loopback_is_exempt(self) -> None:
        self.assertTrue(scope_hook._is_loopback("127.0.0.1"))
        self.assertTrue(scope_hook._is_loopback("localhost"))
        self.assertFalse(scope_hook._is_loopback("example.com"))

    def test_missing_hive_receipt_fails_closed(self) -> None:
        payload = {"tool_name": "Bash", "tool_input": {"command": "curl https://api.example.com"}}
        output = io.StringIO()
        with patch.object(scope_hook, "read_payload", return_value=payload), \
                patch.object(scope_hook, "authorization_for", return_value=None), \
                contextlib.redirect_stdout(output):
            self.assertEqual(scope_hook.main(), 0)
        decision = json.loads(output.getvalue())
        self.assertEqual(decision["decision"], "block")
        self.assertIn("Hive fail-closed", decision["reason"])


if __name__ == "__main__":
    unittest.main()
