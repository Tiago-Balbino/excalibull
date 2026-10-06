"""Regressões de autorização: sem rede ou acervo real."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import hive_scope_cache as cache
import scope_hook
import jsrecon


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, 'CACHE_PATH', tmp_path / 'cache.json')
    monkeypatch.delenv('EXCALIBULL_PROGRAM_ID', raising=False)


def context(value='https://api.example.com/api', program='demo', kind='url_prefix', allowed=True, revision='revision-1'):
    return {'program_id': program, 'asset': {'type': kind, 'value': value},
            'scope': {'confirmed': allowed, 'status': 'authorized' if allowed else 'out_of_scope',
                      'action_allowed': allowed, 'scope_revision': revision}}


def test_wildcard_excludes_apex_and_receipts_do_not_expand():
    asset = {'type': 'wildcard_domain', 'value': '*.example.com'}
    assert cache._asset_matches(asset, 'api.example.com')
    assert not cache._asset_matches(asset, 'example.com')
    cache.record_context(context('*.example.com', kind='wildcard_domain'))
    assert cache.authorization_for('api.example.com') is None


def test_url_rule_uses_path_boundary_and_normalized_origin():
    asset = {'type': 'url_prefix', 'value': 'https://api.example.com:443/api'}
    assert cache._asset_matches(asset, 'https://api.example.com/api/child')
    assert not cache._asset_matches(asset, 'https://api.example.com/apiary')
    assert not cache._asset_matches(asset, 'http://api.example.com/api')
    assert not cache._asset_matches(asset, 'https://api.example.com:8443/api')


def test_permissions_require_exact_url_and_do_not_expand_host():
    cache.record_context(context('api.example.com', kind='host'))
    assert cache.authorization_for('api.example.com')['action_allowed']
    assert cache.authorization_for('https://api.example.com/api') is None
    cache.record_context(context())
    assert cache.authorization_for('https://api.example.com/api')['action_allowed']
    assert cache.authorization_for('https://api.example.com/api?cursor=123')['action_allowed']
    assert cache.authorization_for('https://api.example.com/api/child') is None
    assert cache.authorization_for('https://api.example.com/apiary') is None


def test_url_exclusion_wins_and_host_command_cannot_hide_it():
    cache.record_context(context('api.example.com', kind='host'))
    cache.record_context(context('https://api.example.com/admin', allowed=False))
    assert not cache.authorization_for('api.example.com')['action_allowed']
    assert not cache.authorization_for('https://api.example.com/admin/settings')['action_allowed']


def test_hook_checks_full_url(monkeypatch, capsys):
    cache.record_context(context())
    cache.record_context(context('https://api.example.com/admin', allowed=False))
    monkeypatch.setattr(scope_hook, 'read_payload', lambda: {
        'tool_name': 'Bash', 'tool_input': {'command': 'curl https://api.example.com/admin'}})
    assert scope_hook.main() == 0
    assert json.loads(capsys.readouterr().out)['decision'] == 'block'
    assert scope_hook.extract_targets('curl https://api.example.com/admin') == ['https://api.example.com/admin']


@pytest.mark.parametrize('ending', [';', ',', ')', '}'])
def test_hook_preserves_quoted_path_punctuation(ending):
    url = 'https://api.example.com/api' + ending
    cache.record_context(context())
    assert scope_hook.extract_targets(f"curl '{url}'") == [url]
    assert cache.authorization_for(url) is None


def test_program_switch_invalidates_previous_session():
    first = cache.record_context(context())
    assert cache.authorization_for(context()['asset']['value'], program_id='other') is None
    second = cache.record_context(context(program='other', allowed=False))
    assert first['session_id'] != second['session_id']
    assert cache.authorization_for(context()['asset']['value'], program_id='demo') is None
    assert not cache.authorization_for(context()['asset']['value'], program_id='other')['action_allowed']


def test_scope_revision_change_discards_other_permissions():
    cache.record_context(context())
    cache.record_context(context('https://api.example.com/other', revision='revision-2'))
    assert cache.authorization_for(context()['asset']['value']) is None


def test_client_boundary_change_invalidates_cache(monkeypatch):
    cache.record_context(context())
    monkeypatch.setenv('HIVE_MIND_URL', 'https://other.example/mind')
    assert cache.authorization_for(context()['asset']['value']) is None


@pytest.mark.parametrize('value', [{}, [], {'schema_version': 1, 'receipts': []}, None])
def test_invalid_or_legacy_cache_fails_closed(value):
    cache.CACHE_PATH.write_text(json.dumps(value))
    assert cache.authorization_for('api.example.com') is None


@pytest.mark.parametrize('ttl', [0, -1, 8, float('nan'), float('inf'), True])
def test_invalid_ttl_is_rejected(ttl):
    with pytest.raises(ValueError):
        cache.record_context(context(), ttl)


def test_mcp_error_cannot_be_cached():
    with pytest.raises(ValueError):
        cache.record_context({'result': {'isError': True, 'structuredContent': context()}})
    assert not cache.CACHE_PATH.exists()


@pytest.mark.parametrize('path', ['/api/../admin', '/api/%2e%2e/admin', '/api/%252e%252e/admin'])
def test_ambiguous_paths_are_not_authorized(path):
    cache.record_context(context())
    assert cache.authorization_for('https://api.example.com' + path) is None


def test_preflight_preserves_url_and_explicit_program():
    cache.record_context(context())
    url = context()['asset']['value']
    assert cache.preflight([url], program_id='demo') == [(url, True, 'ok')]
    assert cache.preflight([url], program_id='other')[0][1] is False


def test_jsrecon_without_program_still_requires_receipt(monkeypatch):
    monkeypatch.setattr(jsrecon, '_PROGRAM', None)
    def fake_get(url, **kwargs):
        kwargs['authorize'](url)
        pytest.fail('request without receipt')
    monkeypatch.setattr(jsrecon, 'http_get', fake_get)
    assert jsrecon.fetch('https://api.example.com/api') == ('', -2)
