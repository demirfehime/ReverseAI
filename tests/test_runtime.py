import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from server import create_server, audit_valid
from integrations import defaults, validate
from provider_runtime import Provider, endpoint, RuntimeErrorSafe
from mcp_runtime import MCP
from credentials import Vault
import skill_runtime


class FakeService(BaseHTTPRequestHandler):
    calls = []
    def log_message(self, *args):
        pass
    def reply(self, body, status=200, headers=None):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)
    def do_DELETE(self):
        self.reply({})
    def do_GET(self):
        self.calls.append(('GET', self.path, None, dict(self.headers)))
        self.reply({'data': [{'id': 'fixture-model'}]})
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.calls.append(('POST', self.path, body, dict(self.headers)))
        if self.path == '/v1/chat/completions':
            self.reply({'choices': [{'message': {'content': 'fixture completion'}}]})
        elif self.path == '/v1/responses':
            self.reply({'output': [{'type': 'message', 'content': [{'type': 'output_text', 'text': 'fixture response'}]}]})
        elif self.path == '/v1/messages':
            self.reply({'content': [{'type': 'text', 'text': 'fixture anthropic'}]})
        elif self.path == '/mcp':
            method = body['method']
            if method == 'notifications/initialized':
                self.reply({}, 202)
                return
            if method == 'initialize':
                result = {'protocolVersion': '2025-03-26', 'capabilities': {'tools': {}}, 'serverInfo': {'name': 'fixture', 'version': '1'}}
            elif method == 'tools/list':
                result = {'tools': [{'name': 'list_functions', 'inputSchema': {'type': 'object'}}]}
            else:
                result = {'content': [{'type': 'text', 'text': 'fixture function'}]}
            self.reply({'jsonrpc': '2.0', 'id': body['id'], 'result': result}, headers={'Mcp-Session-Id': 'fixture-session'})
        else:
            self.reply({'error': 'secret-echo'}, 401)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = create_server(port=0, data_path=Path(self.temp.name)/'state.json')
        self.rt = self.server.runtime
        self.remote = ThreadingHTTPServer(('127.0.0.1', 0), FakeService)
        self.thread = threading.Thread(target=self.remote.serve_forever, daemon=True)
        self.thread.start()
        FakeService.calls = []
        self.base = f'http://127.0.0.1:{self.remote.server_port}'
        self.config = defaults()
        self.config['providers'] = [{'id': 'fixture', 'protocol': 'chat_completions', 'base_url': self.base+'/v1', 'credential_env': '', 'timeout_seconds': 3, 'model': 'fixture-model', 'enabled': True}]
        self.config['mcp'][0].update(url=self.base+'/mcp', enabled=True, allowed_tools=['list_functions'])
        with self.server.store.lock:
            data = self.server.store.load()
            self.case_id = data['cases'][0]['id']
            data['samples'] = [{'id': 'fixture-sample', 'case_id': self.case_id, 'name': 'metadata', 'demo': False}]
            self.server.store.save(data)
        self.save_config()
    def save_config(self):
        with self.server.store.lock:
            data = self.server.store.load()
            data['settings'] = validate(self.config)
            self.server.store.save(data)
    def tearDown(self):
        for event in list(self.rt.cancel.values()):
            event.set()
        self.rt.pool.shutdown(wait=True, cancel_futures=True)
        self.remote.shutdown()
        self.remote.server_close()
        self.server.server_close()
        self.temp.cleanup()
    def test_protocol_mappings_and_endpoint_join(self):
        p = self.config['providers'][0]
        for protocol, expected in [('chat_completions','fixture completion'),('responses','fixture response'),('anthropic_messages','fixture anthropic')]:
            client = Provider({**p,'protocol':protocol}, 'fixture-secret')
            self.assertEqual(client.complete('hello','system'), expected)
            call = FakeService.calls[-1]
            self.assertEqual(call[3]['User-Agent'], 'ReverseAI/1.0')
            if protocol == 'anthropic_messages':
                self.assertEqual(call[3]['X-Api-Key'],'fixture-secret')
                self.assertEqual(call[2]['system'],'system')
            else:
                self.assertEqual(call[3]['Authorization'],'Bearer fixture-secret')
        for base in [self.base,self.base+'/v1',self.base+'/v1/chat/completions']:
            self.assertEqual(endpoint(base,'models'),self.base+'/v1/models')
        self.assertEqual(endpoint(self.base+'/proxy/v1/responses','models'),self.base+'/proxy/v1/models')
        with self.assertRaises(RuntimeErrorSafe):
            Provider(p).complete('test',stream=True)

    def test_second_listener_is_rejected(self):
        with self.assertRaises(OSError):
            create_server(port=self.server.server_port,data_path=Path(self.temp.name)/'other.json')
    def test_models_failure_status_and_config_invalidation(self):
        result = self.rt.handle('/api/providers/models', {'id':'fixture'})
        self.assertEqual(result['models'], ['fixture-model'])
        self.config['providers'][0]['model'] = 'changed'
        self.save_config()
        self.assertEqual(self.rt.status()['providers/fixture']['status'],'untested')
        self.config['providers'][0]['base_url'] = self.base+'/invalid'
        self.save_config()
        with self.assertRaisesRegex(RuntimeErrorSafe,'HTTP 401'):
            self.rt.handle('/api/providers/test', {'id':'fixture'})
        self.assertEqual(self.rt.status()['providers/fixture']['status'],'failed')
        self.assertNotIn('secret-echo',self.server.store.path.read_text(encoding='utf-8'))

    def test_connection_test_requires_expected_reply(self):
        with patch.object(Provider, 'complete', return_value='unrelated generated answer'):
            with self.assertRaisesRegex(RuntimeErrorSafe, 'OK'):
                self.rt.handle('/api/providers/test', {'id':'fixture'})
        self.assertEqual(self.rt.status()['providers/fixture']['status'], 'failed')
        with patch.object(Provider, 'complete', return_value=' OK\n'):
            result = self.rt.handle('/api/providers/test', {'id':'fixture'})
        self.assertEqual(result['status'], 'connected')
        self.assertEqual(result['verification'], 'exact_ok_reply')
    def test_credentials_are_not_in_state_and_survive_dpapi_reload(self):
        result=self.rt.handle('/api/credentials', {'group':'providers','id':'fixture','secret':'fixture-secret-value'})
        self.assertTrue(result['configured'])
        self.assertNotIn('fixture-secret-value',self.server.store.path.read_text(encoding='utf-8'))
        if self.rt.vault.path.exists():
            self.assertNotIn(b'fixture-secret-value',self.rt.vault.path.read_bytes())
            self.assertEqual(Vault(self.rt.vault.path).get('providers/fixture'),'fixture-secret-value')
    def test_mcp_handshake_tools_and_fail_closed_calls(self):
        result=self.rt.handle('/api/mcp/test',{'id':'ghidra'})
        self.assertEqual(result['tools'][0]['name'],'list_functions')
        call=next(x for x in FakeService.calls if x[2] and x[2].get('method')=='tools/list')
        self.assertEqual(call[3]['Mcp-Session-Id'],'fixture-session')
        payload={'id':'ghidra','case_id':self.case_id,'sample_id':'fixture-sample','tool':'list_functions','arguments':{}}
        result=self.rt.handle('/api/mcp/call',payload)
        self.assertEqual(result['evidence']['status'],'needs_review')
        for bad in ['run_script_inline','rename_function','attach_process']:
            with self.assertRaises(RuntimeErrorSafe):
                self.rt.handle('/api/mcp/call',{**payload,'tool':bad})
        self.assertTrue(audit_valid(self.server.store.load()['audit']))
    def test_provider_chat_records_model_and_case(self):
        result=self.rt.handle('/api/copilot/complete',{'case_id':self.case_id,'sample_id':'fixture-sample','message':'summarize'})
        self.assertEqual(result['message']['model'],'fixture-model')
        self.assertEqual(result['message']['case_id'],self.case_id)
        self.assertEqual(result['message']['mode'],'provider')
    def wait_parent(self,ident):
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            item=next(x for x in self.server.store.load()['jobs'] if x['id']==ident)
            if item['status'] not in {'queued','running'}:
                return item
            time.sleep(.02)
        self.fail('parent did not terminate')
    def test_agents_results_budget_permissions_and_provenance(self):
        self.config['agents'].update(enabled=True, max_concurrency=2, call_budget=2)
        self.save_config()
        payload={'case_id':self.case_id,'sample_id':'fixture-sample','tasks':['one','two']}
        with self.assertRaises(RuntimeErrorSafe):
            self.rt.handle('/api/agents/run',{**payload,'tasks':['1','2','3']})
        with self.assertRaises(RuntimeErrorSafe):
            self.rt.handle('/api/agents/run',{**payload,'allowed_tools':['execute']})
        parent=self.rt.handle('/api/agents/run',payload)
        self.assertEqual(self.wait_parent(parent['id'])['status'],'completed')
        data=self.server.store.load()
        self.assertEqual(len(data['evidence']),2)
        self.assertTrue(all(x['status']=='needs_review' and x['source']=='agent:fixture' for x in data['evidence']))
        self.assertTrue(audit_valid(data['audit']))
    def test_agents_cancel_discards_late_provider_result(self):
        self.config['agents']['enabled']=True
        self.save_config()
        released=threading.Event()
        with patch.object(Provider,'complete',side_effect=lambda *a,**k: released.wait(2) or 'late'):
            parent=self.rt.handle('/api/agents/run',{'case_id':self.case_id,'sample_id':'fixture-sample','tasks':['one','two']})
            self.rt.handle('/api/agents/cancel',{'id':parent['id'],'case_id':self.case_id})
            released.set()
            time.sleep(.1)
            data=self.server.store.load()
            self.assertFalse(data['evidence'])
            self.assertTrue(all(x['status']=='cancelled' for x in data['jobs']))
    def test_imported_skills_have_locked_content(self):
        entries=skill_runtime.catalog()
        self.assertGreater(len(entries),10)
        skill=skill_runtime.read('reverse-engineering')
        self.assertTrue(skill['verified'])
        self.assertEqual(len(skill['revision']),40)
        with self.assertRaises(ValueError):
            skill_runtime.read('../server.py')

    def test_agent_deadline_and_concurrency_limit(self):
        self.config['agents'].update(enabled=True,max_concurrency=2,call_budget=4,time_budget_seconds=1,model='override-model')
        self.save_config()
        counter={'active':0,'peak':0,'models':[]}
        lock=threading.Lock()
        def delayed(*args,**kwargs):
            with lock:
                counter['active']+=1
                counter['peak']=max(counter['peak'],counter['active'])
                counter['models'].append(kwargs['model'])
            time.sleep(.65)
            with lock:
                counter['active']-=1
            return 'delayed-result'
        with patch.object(Provider,'complete',side_effect=delayed):
            parent=self.rt.handle('/api/agents/run',{'case_id':self.case_id,'sample_id':'fixture-sample','tasks':['a','b','c','d']})
            result=self.wait_parent(parent['id'])
            self.assertEqual(result['status'],'failed')
            self.assertLessEqual(counter['peak'],2)
            self.assertTrue(all(x=='override-model' for x in counter['models']))
            time.sleep(.4)
            self.assertEqual(len(self.server.store.load()['evidence']),2,'late results must not enter evidence')

    def test_restart_recovers_interrupted_jobs_without_replay(self):
        with self.server.store.lock:
            data=self.server.store.load()
            data['jobs'].append({'id':'interrupted','case_id':self.case_id,'type':'agent_parent','status':'running'})
            self.server.store.save(data)
        reopened=create_server(port=0,data_path=self.server.store.path)
        try:
            data=reopened.store.load()
            self.assertEqual(data['jobs'][0]['status'],'failed')
            self.assertEqual(FakeService.calls,[])
            self.assertTrue(audit_valid(data['audit']))
        finally:
            reopened.runtime.pool.shutdown()
            reopened.server_close()

    def auto_config(self, **overrides):
        self.config['agents'].update({'enabled': True, 'delegation_mode': 'auto', 'call_budget': 8,
                                     'max_children': 3, 'max_concurrency': 2, **overrides})
        self.save_config()
        return {'case_id': self.case_id, 'sample_id': 'fixture-sample', 'message': 'Analyze evidence'}

    def test_auto_delegates_then_summarizes_with_model_override(self):
        payload = self.auto_config(model='child-model')
        calls = []
        def complete(prompt, system='', **kwargs):
            body = json.loads(prompt)
            calls.append(kwargs.get('model', 'main'))
            if kwargs.get('model') == 'child-model':
                return 'child finding'
            if not body['child_results']:
                return json.dumps({'action': 'spawn_agents', 'tasks': ['check inputs', 'check gaps']})
            self.assertEqual(len(body['child_results']), 2)
            self.assertTrue(all(x['result'] == 'child finding' for x in body['child_results']))
            return json.dumps({'action': 'finish', 'answer': 'combined findings'})
        with patch.object(Provider, 'complete', side_effect=complete):
            parent = self.rt.handle('/api/copilot/complete', payload)['job']
            result = self.wait_parent(parent['id'])
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['calls_used'], 4)
        self.assertEqual(len(result['children']), 2)
        self.assertEqual(calls.count('child-model'), 2)
        data = self.server.store.load()
        self.assertEqual(data['messages'][-1]['content'], 'combined findings')
        self.assertEqual(len(data['evidence']), 3)
        self.assertTrue(audit_valid(data['audit']))

    def test_auto_enforces_count_and_total_budget(self):
        payload = self.auto_config()
        self.config['agents'].update(max_children=1, call_budget=3)
        self.save_config()
        with patch.object(Provider, 'complete', return_value=json.dumps({'action':'spawn_agents', 'tasks':['a','b']})) as call:
            parent = self.rt.handle('/api/copilot/complete', payload)['job']
            result = self.wait_parent(parent['id'])
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['calls_used'], 3)
        self.assertEqual(call.call_count, 3)
        self.assertEqual(result['children'], [])

    def test_auto_cancel_discards_late_main_response(self):
        payload = self.auto_config()
        entered, release = threading.Event(), threading.Event()
        def complete(*args, **kwargs):
            entered.set()
            release.wait(2)
            return json.dumps({'action':'finish','answer':'late result'})
        with patch.object(Provider, 'complete', side_effect=complete):
            parent = self.rt.handle('/api/copilot/complete', payload)['job']
            self.assertTrue(entered.wait(1))
            self.rt.handle('/api/agents/cancel', {'id':parent['id'], 'case_id':self.case_id})
            release.set()
            deadline = time.monotonic() + 2
            while parent['id'] in self.rt.cancel and time.monotonic() < deadline:
                time.sleep(.01)
        data = self.server.store.load()
        self.assertFalse(data['evidence'])
        self.assertEqual(len(data['messages']), 1)
        self.assertEqual(data['jobs'][0]['status'], 'cancelled')

    def test_auto_disabled_rejects_direct_spawn_and_preserves_chat(self):
        from agent_orchestrator import start
        payload = {'case_id': self.case_id, 'message': 'hello'}
        with self.assertRaises(RuntimeErrorSafe):
            start(self.rt, payload)
        self.assertIn('message', self.rt.handle('/api/copilot/complete', payload))
        self.assertFalse(self.server.store.load()['jobs'])

    def test_agent_settings_migrate_and_validate_references(self):
        for key in ('max_children', 'delegation_mode', 'provider_id'):
            del self.config['agents'][key]
        self.assertEqual(validate(self.config)['agents']['delegation_mode'], 'manual')
        self.config['agents']['provider_id'] = 'missing'
        with self.assertRaises(ValueError):
            validate(self.config)

    def test_auto_child_provider_concurrency_and_budget_reserve(self):
        payload = self.auto_config(provider_id='', model='child-model', max_concurrency=1, call_budget=4)
        self.config['providers'].append({**self.config['providers'][0], 'id': 'children', 'enabled': False})
        self.config['agents']['provider_id'] = 'children'
        self.save_config()
        counts = {'active': 0, 'peak': 0}
        lock = threading.Lock()
        def complete(provider, prompt, system='', **kwargs):
            if provider.config['id'] == 'children':
                self.assertEqual(kwargs['model'], 'child-model')
                with lock:
                    counts['active'] += 1
                    counts['peak'] = max(counts['peak'], counts['active'])
                time.sleep(.05)
                with lock:
                    counts['active'] -= 1
                return 'child result'
            body = json.loads(prompt)
            return json.dumps({'action':'finish','answer':'summary'}) if body['child_results'] else json.dumps({'action':'spawn_agents','tasks':['one','two']})
        with patch.object(Provider, 'complete', new=complete):
            parent = self.rt.handle('/api/copilot/complete', payload)['job']
            result = self.wait_parent(parent['id'])
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['calls_used'], 4)
        self.assertEqual(counts['peak'], 1)

    def test_auto_deadline_discards_late_final_answer(self):
        payload = self.auto_config(time_budget_seconds=1)
        def complete(*args, **kwargs):
            time.sleep(1.1)
            return json.dumps({'action':'finish','answer':'late'})
        with patch.object(Provider, 'complete', side_effect=complete):
            parent = self.rt.handle('/api/copilot/complete', payload)['job']
            self.assertEqual(self.wait_parent(parent['id'])['status'], 'failed')
        self.assertFalse(self.server.store.load()['evidence'])


if __name__=='__main__':
    unittest.main()
