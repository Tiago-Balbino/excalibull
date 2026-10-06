"""Contrato MCP com subprocesso sintético: handshake, erros e capacidades."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from hive_gateway import HiveClient, HiveError


@pytest.fixture(autouse=True)
def isolated_receipts(tmp_path, monkeypatch):
    import hive_scope_cache
    monkeypatch.setattr(hive_scope_cache, 'CACHE_PATH', tmp_path / 'scope-cache.json')


@pytest.fixture
def command(tmp_path):
    script = tmp_path / 'fake_mcp.py'
    script.write_text('''import json,sys,os
for line in sys.stdin:
    request=json.loads(line)
    if 'id' not in request: continue
    method=request['method']
    if method=='initialize': result={'protocolVersion':'2024-11-05'}
    elif method=='tools/list': result={'tools':[{'name':n} for n in ['hive_list_targets','hive_get_context','hive_search','get_sync_status']]}
    else:
        name=request['params']['name']; args=request['params']['arguments']
        if name=='hive_list_targets': result={'structuredContent':{'targets':[], 'next_offset':args.get('offset',0)+10,'truncated':True},'content':[{'type':'text','text':'summary only'}]}
        elif name=='get_sync_status': result={'content':[{'type':'text','text':'**Status:** `unknown`'}]}
        elif name=='hive_search':
            print(json.dumps({'id':request['id'],'error':{'code':-32603,'message':'SECRET_PROVIDER_ERROR'}}),flush=True); continue
        else: result={'structuredContent':{'program_id':args['program_id'],'asset':args['asset'],'scope':{'confirmed':False,'status':'unknown','action_allowed':False,'scope_revision':'unapproved'}}}
    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}),flush=True)
''')
    return [sys.executable, str(script)]


def test_handshake_capabilities_and_structured_catalog(command):
    with HiveClient(command=command) as client:
        assert 'hive_list_targets' in client.tools
        assert 'ingest_workspace' not in client.tools
        result = client.catalog(offset=20)
        assert result['next_offset'] == 30 and result['truncated']
    assert client.process.poll() is not None


def test_mutation_not_announced_is_rejected(command):
    with HiveClient(command=command) as client:
        with pytest.raises(HiveError, match='não anunciada'):
            client.call('ingest_workspace', {})


def test_unknown_sync_is_not_empty_queue(command):
    with HiveClient(command=command) as client:
        assert client.call('get_sync_status', {}) == {'status': 'unknown', 'queue_confirmed': False}


def test_context_is_bound_to_requested_asset(command):
    with HiveClient(command=command) as client:
        result = client.context('demo', {'type': 'host', 'value': 'api.example.com'}, 'policy')
        assert result['scope']['confirmed'] is False


def test_service_failure_invalidates_previous_permissions(command):
    import hive_scope_cache as cache
    cache.record_context({'program_id': 'demo', 'asset': {'type': 'host', 'value': 'api.example.com'},
                          'scope': {'confirmed': True, 'status': 'authorized', 'action_allowed': True,
                                    'scope_revision': 'revision-1'}})
    with HiveClient(command=command) as client:
        assert cache.authorization_for('api.example.com')
        with pytest.raises(HiveError):
            client.call('hive_search', {'program_id': 'demo', 'query': 'topic'})
    assert cache.authorization_for('api.example.com') is None


def test_provider_errors_are_sanitized(command):
    with HiveClient(command=command) as client:
        with pytest.raises(HiveError) as error:
            client.call('hive_search', {'program_id': 'demo', 'query': 'topic'})
        assert 'SECRET' not in str(error.value)


def test_handshake_timeout_closes_child(tmp_path):
    script = tmp_path / 'slow.py'
    script.write_text('import time; time.sleep(10)')
    with pytest.raises(HiveError, match='indisponível'):
        HiveClient(command=[sys.executable, str(script)], timeout=.05)


def test_writer_is_explicit_uses_official_launcher_and_discovers_mutation(tmp_path, monkeypatch):
    import subprocess
    import hive_gateway
    config = tmp_path / 'writer.toml'
    config.write_text('# synthetic configuration')
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    script = tmp_path / 'writer_mcp.py'
    script.write_text('''import json,sys
for line in sys.stdin:
    request=json.loads(line)
    if 'id' not in request: continue
    if request['method']=='initialize': result={}
    elif request['method']=='tools/list': result={'tools':[{'name':'ingest_workspace'}]}
    else:
        report={'schema_version':1,'ok':False,'exit_code':15,'summary':{'results':[{'path':'programs/demo/notes/a.md','outcome':'failed','published':True,'reason_code':'cleanup_pending'}]}}
        result={'isError':True,'content':[{'type':'text','text':json.dumps(report)}]}
    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}),flush=True)
''')
    real_popen = subprocess.Popen
    calls = []
    def spawn(command, **kwargs):
        calls.append((command, kwargs['env']))
        return real_popen([sys.executable, str(script)], **kwargs)
    monkeypatch.setattr(hive_gateway.subprocess, 'Popen', spawn)
    monkeypatch.setenv('HIVE_ROLE', 'reader')
    monkeypatch.setenv('HIVE_DATA_DIR', '/unexpected')
    with HiveClient(writer_config=config, writer_workspace=workspace) as client:
        result = client.ingest_report()
    assert calls[0][0] == ['hive', 'mind', '--config', str(config), '--data-dir', str(workspace), '--role', 'writer']
    assert 'HIVE_ROLE' not in calls[0][1] and 'HIVE_DATA_DIR' not in calls[0][1]
    assert result['ok'] is False and result['_mcp_is_error'] is True
    assert result['summary']['results'][0]['published'] is True


def test_writer_requires_config_outside_workspace(tmp_path):
    config = tmp_path / 'writer.toml'
    config.write_text('# synthetic')
    with pytest.raises(HiveError):
        HiveClient(writer_config=config)
    with pytest.raises(HiveError):
        HiveClient(writer_config=config, writer_workspace=tmp_path)
