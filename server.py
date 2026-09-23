#!/usr/bin/env python3
"""Loopback workbench with separate APK static workers. Never executes samples."""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import secrets
import socket
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from adapters import default_registry
from integrations import defaults as integration_defaults, validate as validate_integrations
from runtime import Runtime
from apk_jobs import APKJobs
from provider_runtime import RuntimeErrorSafe
import skill_runtime

ROOT = Path(__file__).resolve().parent
COLLECTIONS = ('cases', 'samples', 'jobs', 'evidence', 'messages', 'reports', 'audit')
LOOPBACK_HOSTS = {'127.0.0.1', 'localhost'}
DEFAULT_CONFIG = {
    'mode': 'metadata-only',
    'host': '127.0.0.1',
    'port': 8787,
    'adapters': {
        'ghidra_mcp': {'enabled': False, 'endpoint': '', 'allowlist': ['read_function', 'read_decompiler', 'read_xrefs']},
        'frida': {'enabled': False, 'worker': '', 'network': 'disabled', 'host_mounts': []},
        'llm': {'enabled': False, 'provider': '', 'store_prompts_and_responses': True},
    },
    'write_policy': {
        'default': 'proposal_only',
        'requires_second_confirmation': ['rename', 'comment', 'patch', 'script', 'attach_process', 'execute'],
    },
}


def _copy_default_config():
    return json.loads(json.dumps(DEFAULT_CONFIG, ensure_ascii=False))


def load_config(path=None):
    """Load an explicit JSON config, while keeping safe defaults fail-closed."""
    config = _copy_default_config()
    config_path = path or os.environ.get('REVERSEAI_CONFIG_FILE')
    if not config_path:
        return config
    try:
        supplied = json.loads(Path(config_path).read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f'无法读取 ReverseAI 配置: {config_path}') from exc
    if not isinstance(supplied, dict):
        raise ValueError('ReverseAI 配置必须是 JSON 对象')
    for key, value in supplied.items():
        if key in {'adapters', 'write_policy'} and isinstance(value, dict):
            config[key].update(value)
        else:
            config[key] = value
    return config


def validate_config(config, bind_host=None):
    """Reject unsafe or not-yet-implemented adapter configurations at startup."""
    if not isinstance(config, dict):
        raise ValueError('配置必须是对象')
    if config.get('mode') != 'metadata-only':
        raise ValueError('当前构建只允许 mode=metadata-only')
    if not isinstance(config.get('write_policy'), dict) or config['write_policy'].get('default') != 'proposal_only':
        raise ValueError('write_policy.default 必须为 proposal_only')
    effective_host = bind_host or config.get('host', '127.0.0.1')
    if not isinstance(effective_host, str) or effective_host not in LOOPBACK_HOSTS:
        raise ValueError('ReverseAI 只能绑定 loopback host')
    adapters = config.get('adapters')
    if not isinstance(adapters, dict):
        raise ValueError('adapters 必须是对象')
    for name in ('ghidra_mcp', 'frida', 'llm'):
        options = adapters.get(name, {})
        if not isinstance(options, dict):
            raise ValueError(f'adapters.{name} 必须是对象')
        enabled = options.get('enabled', False)
        if not isinstance(enabled, bool):
            raise ValueError(f'adapters.{name}.enabled 必须是布尔值')
        if not enabled:
            continue
        worker_key = 'provider' if name == 'llm' else 'worker'
        if not isinstance(options.get(worker_key), str) or not options[worker_key].strip():
            raise ValueError(f'启用 {name} 时必须配置 {worker_key}')
        allowlist = options.get('allowlist')
        if not isinstance(allowlist, list) or not allowlist or any(not isinstance(item, str) or not item.strip() for item in allowlist):
            raise ValueError(f'启用 {name} 时必须配置非空 allowlist')
        isolation = options.get('isolation')
        if not isinstance(isolation, (dict, str)) or not isolation:
            raise ValueError(f'启用 {name} 时必须配置 isolation')
        raise ValueError(f'真实 {name} worker 尚未实现；保持 disabled，避免执行工具或样本')
    return config


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def uid(prefix):
    return f'{prefix}_{uuid.uuid4().hex[:16]}'


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


class Problem(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status


def text(payload, key, limit=4000, default=None):
    value = payload.get(key, default)
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise Problem(f'{key} 必须是 1–{limit} 字符的非空字符串')
    return value.strip()


def locate(state, collection, record_id):
    item = next((item for item in state[collection] if item['id'] == record_id), None)
    if item is None:
        raise Problem(f'{collection} 记录不存在', 404)
    return item


def case_sample(state, payload, optional=False):
    case = locate(state, 'cases', text(payload, 'case_id', 100))
    sample_id = payload.get('sample_id')
    if optional and not sample_id:
        return case, None
    sample = locate(state, 'samples', text(payload, 'sample_id', 100))
    if sample['case_id'] != case['id']:
        raise Problem('样本不属于当前 Case', 409)
    return case, sample


def audit(state, case_id, action, target):
    entry = {'id': uid('log'), 'case_id': case_id, 'action': action,
             'target': target, 'created_at': now(),
             'previous_hash': state['audit'][-1]['hash'] if state['audit'] else '0' * 64}
    entry['hash'] = digest(entry)
    state['audit'].append(entry)


def audit_valid(entries):
    previous = '0' * 64
    for item in entries:
        entry = dict(item)
        hashed = entry.pop('hash', None)
        if entry.get('previous_hash') != previous or digest(entry) != hashed:
            return False
        previous = hashed
    return True


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            state = {key: [] for key in COLLECTIONS}
            state.update(schema_version=3, cases=[{'id': uid('case'), 'name': '我的逆向工作区',
                'authorization': '待确认授权范围', 'created_at': now(), 'status': 'active'}])
            self.save(state)
        else:
            state = self.load()
            if state.get('schema_version', 0) < 3:
                # Preserve old prototype records, but never present fabricated activity as live.
                for collection in ('samples', 'jobs', 'evidence'):
                    for item in state[collection]:
                        if '_demo_' in item.get('id', ''):
                            item['demo'] = True
                            if collection == 'jobs':
                                item.update(status='blocked', progress=0, reason='旧版演示任务；未运行分析工具')
                            if collection == 'evidence':
                                item['source'] = 'demo_fixture'
                for item in state['messages']:
                    item.setdefault('case_id', None)
                state.pop('toolchain', None)
                state['schema_version'] = 3
                self.path.with_suffix('.v2-backup.json').write_bytes(self.path.read_bytes())
                self.save(state)

    def load(self):
        # Corrupt state is an error, not permission to silently overwrite user data.
        # Readers must not race atomic replacement on Windows. RLock permits
        # existing read-modify-write transactions to keep using the same lock.
        with self.lock:
            state = json.loads(self.path.read_text(encoding='utf-8'))
        if not isinstance(state, dict):
            raise ValueError('state must be an object')
        for key in COLLECTIONS:
            state.setdefault(key, [])
            if not isinstance(state[key], list):
                raise ValueError(f'invalid collection: {key}')
        return state

    def save(self, state):
        with self.lock:
            temp = self.path.with_suffix('.tmp')
            with temp.open('wb') as file:
                file.write(encoded(state))
                file.flush()
                os.fsync(file.fileno())
            temp.replace(self.path)


def make_report(state, case_id, toolchain):
    return {'schema': 'reverseai-evidence/v1', 'generated_at': now(),
            'scope': '元数据、人工及显式集成记录；未执行样本。来源及模型以记录为准，AI 输出须人工复核。demo=true 为演示数据。',
            'case': locate(state, 'cases', case_id),
            **{key: [x for x in state[key] if x.get('case_id') == case_id]
               for key in ('samples', 'jobs', 'evidence')},
            'toolchain': toolchain,
            'audit': [x for x in state['audit'] if x.get('case_id') == case_id],
            'audit_chain_valid_at_export': audit_valid(state['audit'])}


def report_bytes(report):
    snapshot = report['snapshot']
    bundle = {'sha256': report['sha256'], 'snapshot': snapshot}
    content = json.dumps(bundle, ensure_ascii=False, indent=2, allow_nan=False)
    if report['format'] == 'json':
        return content.encode('utf-8'), 'application/json; charset=utf-8'
    if report['format'] == 'html':
        content = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
                   '<title>ReverseAI Evidence Report</title><h1>ReverseAI 证据快照</h1>'
                   '<p>元数据报告，不代表已完成二进制分析。SHA-256 用于快照校验，不是数字签名。</p>'
                   f'<pre>{html.escape(content)}</pre></html>')
        return content.encode('utf-8'), 'text/html; charset=utf-8'
    content = '# ReverseAI 证据快照\n\n元数据报告；未经二进制分析验证。\n\n' + '\n'.join('    ' + line for line in content.splitlines()) + '\n'
    return content.encode('utf-8'), 'text/markdown; charset=utf-8'


class APIHandler(BaseHTTPRequestHandler):
    server_version = 'ReverseAI/0.4'

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, fmt, *args):
        if not getattr(self.server, 'quiet', False):
            super().log_message(fmt, *args)

    def respond(self, body, status=200, content_type='application/json; charset=utf-8', filename=None):
        self.send_response(status)
        for key, value in {'Content-Type': content_type, 'Content-Length': str(len(body)),
                           'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                           'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
                           'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"}.items():
            self.send_header(key, value)
        if filename:
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload, status=200):
        self.respond(encoded(payload), status)

    def guard(self, write=False):
        host = self.headers.get('Host', '')
        port = self.server.server_address[1]
        if host not in {f'127.0.0.1:{port}', f'localhost:{port}'}:
            raise Problem('仅允许本机 loopback Host', 403)
        origin = self.headers.get('Origin')
        if origin and origin != f'http://{host}':
            raise Problem('拒绝跨站请求', 403)
        if self.headers.get('Sec-Fetch-Site') == 'cross-site':
            raise Problem('拒绝跨站请求', 403)
        if write and not secrets.compare_digest(self.headers.get('X-ReverseAI-Token', ''), self.server.csrf_token):
            raise Problem('缺少或无效的本机会话令牌，请刷新工作台', 403)

    def read_json(self):
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise Problem('只接受 application/json', 415)
        if self.headers.get('Transfer-Encoding'):
            raise Problem('不支持 Transfer-Encoding')
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            raise Problem('无效 Content-Length') from None
        if not 0 < length <= 1_000_000:
            raise Problem('请求正文必须为 1–1000000 bytes', 413)
        try:
            payload = json.loads(self.rfile.read(length).decode('utf-8'),
                                 parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeError):
            raise Problem('无效 JSON') from None
        if not isinstance(payload, dict):
            raise Problem('JSON 必须是对象')
        return payload

    def do_OPTIONS(self):
        self.send_json({'error': '不支持跨站访问'}, 405)

    def do_GET(self):
        self.handle_request(False)

    def do_POST(self):
        self.handle_request(True)

    def handle_request(self, write):
        body_consumed = False
        try:
            self.guard(write)
            parsed = urlsplit(self.path)
            path = unquote(parsed.path).rstrip('/') or '/'
            if not write and not path.startswith('/api/'):
                files = {'/': ('index.html', 'text/html; charset=utf-8'),
                         '/index.html': ('index.html', 'text/html; charset=utf-8'),
                         '/styles.css': ('styles.css', 'text/css; charset=utf-8'),
                         '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                         '/graph.js': ('graph.js', 'text/javascript; charset=utf-8'),
                         '/settings-ui.js': ('settings-ui.js', 'text/javascript; charset=utf-8'),
                         '/layout.js': ('layout.js', 'text/javascript; charset=utf-8')}
                if path not in files:
                    raise Problem('文件不存在', 404)
                filename, content_type = files[path]
                return self.respond((ROOT / filename).read_bytes(), content_type=content_type)
            if write and path == '/api/samples/apk':
                if self.headers.get('Transfer-Encoding'):
                    raise Problem('不支持 Transfer-Encoding')
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/vnd.android.package-archive':
                    raise Problem('只接受 APK 文件正文', 415)
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                except ValueError:
                    raise Problem('无效 Content-Length') from None
                if not 0 < length <= 100_000_000:
                    raise Problem('APK 必须为 1–100 MB', 413)
                query = parse_qs(parsed.query)
                self.connection.settimeout(60)
                result = self.server.apk_jobs.upload(self.rfile, length, query.get('case_id', [''])[0], query.get('name', [''])[0])
                body_consumed = True
                return self.send_json(result, 201)
            payload = self.read_json() if write else {}
            body_consumed = True
            if write and path == '/api/apk/jobs':
                return self.send_json(self.server.apk_jobs.start(payload), 201)
            cancel = re.fullmatch(r'/api/analysis/jobs/([\w-]+)/cancel', path)
            if write and cancel:
                result = self.server.apk_jobs.cancel(cancel[1], payload.get('case_id'))
                if result is not None:
                    return self.send_json(result, 201)
            if write and path in {'/api/credentials', '/api/providers/test', '/api/providers/models',
                                  '…115 tokens truncated…rver.store.load()
                if write:
                    result = self.post(path, payload, state)
                    self.server.store.save(state)
                    return self.send_json(result, 201)
                return self.get(path, parse_qs(parsed.query), state)
        except Problem as error:
            # Closing a Windows socket with a small unread request body can reset
            # the connection before the client receives our 403 response.
            if write and not body_consumed and error.status == 403:
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if 0 < length <= 1_000_000 and not self.headers.get('Transfer-Encoding'):
                        self.connection.settimeout(.25)
                        self.rfile.read(length)
                except (OSError, ValueError):
                    pass
            self.send_json({'error': error.message}, error.status)
        except RuntimeErrorSafe as error:
            self.send_json({'error': str(error)}, 400)
        except (OSError, ValueError, KeyError, TypeError):
            self.send_json({'error': '本地状态或请求异常；原始状态未被重置，请检查服务日志和备份'}, 500)

    def get(self, path, query, state):
        artifact = re.fullmatch(r'/api/apk/jobs/([\w-]+)/artifact', path)
        if artifact:
            job = locate(state, 'jobs', artifact[1])
            if job['case_id'] != query.get('case_id', [''])[0]:
                raise Problem('任务不属于当前 Case', 409)
            name = query.get('name', [''])[0]
            if name not in job.get('artifacts', []) or not re.fullmatch(r'(?:evidence/[\w-]+\.json|derived/[a-f0-9]{64}\.png|result\.json|extraction\.json)', name):
                raise Problem('产物不存在', 404)
            target = self.server.apk_jobs.root / job['id'] / name
            return self.respond(target.read_bytes(), content_type='image/png' if name.endswith('.png') else 'application/json; charset=utf-8', filename=target.name)
        if path == '/api/skills/catalog':
            return self.send_json({'items': skill_runtime.catalog()})
        if path.startswith('/api/skills/content/'):
            try:
                return self.send_json(skill_runtime.read(path.rsplit('/', 1)[-1]))
            except ValueError as error:
                raise Problem(str(error), 404) from None
        if path == '/api/settings':
            return self.send_json({'config': self.server.runtime.config(),
                                   'revision': state.get('settings_revision', 0),
                                   'runtime': 'text-and-readonly', 'defaults': integration_defaults(),
                                   'statuses': self.server.runtime.status(),
                                   'capabilities': {'providers': ['chat_completions', 'responses', 'anthropic_messages'],
                                                    'streaming': False, 'model_tool_calls': False, 'mcp': ['streamable_http'],
                                                    'agents': 'model-directed-text-delegation'}})
        if path == '/api/health':
            return self.send_json({'ok': True, 'version': '0.5', 'mode': 'metadata-and-apk-static',
                                   'csrf_token': self.server.csrf_token, 'time': now()})
        if path == '/api/toolchain/health':
            return self.send_json({'items': self.server.runtime.toolchain(self.server.toolchain)})
        mapping = {'/api/cases': 'cases', '/api/samples': 'samples', '/api/analysis/jobs': 'jobs',
                   '/api/messages': 'messages', '/api/reports': 'reports', '/api/audit': 'audit'}
        if path in mapping:
            items = state[mapping[path]]
            if query.get('case_id'):
                case_id = query['case_id'][0]
                locate(state, 'cases', case_id)
                items = [x for x in items if x.get('case_id') == case_id]
            if path == '/api/reports':
                items = [{k: v for k, v in x.items() if k != 'snapshot'} for x in items]
            return self.send_json({'items': items, **({'chain_valid': audit_valid(state['audit'])} if path == '/api/audit' else {})})
        if path.startswith('/api/evidence/'):
            case_id = path.rsplit('/', 1)[-1]
            locate(state, 'cases', case_id)
            return self.send_json({'items': [x for x in state['evidence'] if x['case_id'] == case_id]})
        match = re.fullmatch(r'/api/reports/([\w-]+)/download', path)
        if match:
            report = locate(state, 'reports', match[1])
            if 'snapshot' not in report:
                raise Problem('旧版仅登记的报告没有快照，请重新生成', 409)
            if digest(report['snapshot']) != report['sha256']:
                raise Problem('报告快照校验失败', 409)
            body, content_type = report_bytes(report)
            return self.respond(body, content_type=content_type, filename=f"{report['id']}.{report['format']}")
        raise Problem('接口不存在', 404)

    def post(self, path, payload, state):
        if path == '/api/settings':
            if payload.get('revision') != state.get('settings_revision', 0):
                raise Problem('配置已变化，请重新加载后合并修改', 409)
            try:
                config = validate_integrations(payload.get('config'))
            except ValueError as error:
                raise Problem(str(error)) from None
            state['settings'] = config
            state['settings_revision'] = state.get('settings_revision', 0) + 1
            audit(state, None, 'settings.saved', str(state['settings_revision']))
            return {'config': config, 'revision': state['settings_revision'], 'runtime': 'text-and-readonly'}
        if path == '/api/cases':
            case = {'id': uid('case'), 'name': text(payload, 'name', 120), 'status': 'active',
                    'authorization': text(payload, 'authorization', 1000, '待确认授权范围'), 'created_at': now()}
            state['cases'].insert(0, case)
            audit(state, case['id'], 'case.created', case['id'])
            return case
        if path == '/api/samples':
            case = locate(state, 'cases', text(payload, 'case_id', 100))
            name = text(payload, 'name', 180)
            size = payload.get('size')
            if type(size) is not int or not 0 <= size <= 2**53 - 1:
                raise Problem('size 必须是非负安全整数')
            sha = text(payload, 'sha256', 64).lower()
            if not re.fullmatch('[a-f0-9]{64}', sha):
                raise Problem('sha256 必须为 64 位十六进制字符串')
            existing = next((s for s in state['samples'] if s['case_id'] == case['id'] and s['sha256'] == sha), None)
            if existing:
                return {'sample': existing, 'duplicate': True}
            sample = {'id': uid('smp'), 'case_id': case['id'], 'name': name, 'size': size, 'sha256': sha,
                      'kind': text(payload, 'kind', 80, 'Unknown'), 'mime': text(payload, 'mime', 120, 'application/octet-stream'),
                      'risk': 'pending', 'created_at': now(), 'hash_source': 'client-provided', 'demo': False}
            state['samples'].insert(0, sample)
            audit(state, case['id'], 'sample.registered', sample['id'])
            return {'sample': sample, 'duplicate': False}
        if path == '/api/analysis/jobs':
            case, sample = case_sample(state, payload)
            kind = text(payload, 'type', 80, 'metadata_check')
            if kind not in {'metadata_check', 'ai_orchestrator', 'static_triage', 'android_analysis'}:
                raise Problem('不支持的任务类型')
            local = kind == 'metadata_check'
            job = {'id': uid('job'), 'case_id': case['id'], 'sample_id': sample['id'], 'type': kind,
                   'source': 'local_ui', 'operator': 'local_operator', 'demo': bool(sample.get('demo')),
                   'executor': 'metadata_validator/v1' if local else None,
                   'started_at': now() if local else None, 'finished_at': now() if local else None,
                   'status': 'completed' if local else 'blocked', 'progress': 100 if local else 0,
                   'created_at': now(), 'reason': '仅检查登记元数据，不分析文件内容' if local else '尚未配置分析适配器；未运行样本或工具'}
            state['jobs'].insert(0, job)
            if local:
                item = {'id': uid('evt'), 'case_id': case['id'], 'sample_id': sample['id'], 'source': 'metadata_validator',
                        'type': 'metadata_observation', 'subject': sample['name'],
                        'claim': f"登记大小 {sample['size']} bytes；客户端提供 SHA-256 {sample['sha256']}。未读取二进制内容、未判断恶意性。",
                        'confidence': None, 'artifacts': [f"sha256:{sample['sha256']}"], 'status': 'needs_review',
                        'created_at': now(), 'demo': bool(sample.get('demo'))}
                state['evidence'].insert(0, item)
                job['evidence_id'] = item['id']
            audit(state, case['id'], 'job.completed' if local else 'job.blocked', job['id'])
            return job
        match = re.fullmatch(r'/api/analysis/jobs/([\w-]+)/cancel', path)
        if match:
            job = locate(state, 'jobs', match[1])
            if job['case_id'] != text(payload, 'case_id', 100):
                raise Problem('任务不属于当前 Case', 409)
            if job['status'] not in {'queued', 'blocked'}:
                raise Problem('只有排队或阻塞任务可取消', 409)
            job.update(status='cancelled', reason='用户取消；未执行样本', finished_at=now())
            audit(state, job['case_id'], 'job.cancelled', job['id'])
            return job
        if path == '/api/evidence':
            case, sample = case_sample(state, payload)
            artifacts = payload.get('artifacts', [])
            if not isinstance(artifacts, list) or len(artifacts) > 30 or any(not isinstance(x, str) or len(x) > 1000 for x in artifacts):
                raise Problem('artifacts 必须是最多 30 个短字符串')
            item = {'id': uid('evt'), 'case_id': case['id'], 'sample_id': sample['id'], 'source': 'manual',
                    'subject': text(payload, 'subject', 300), 'claim': text(payload, 'claim', 8000),
                    'artifacts': artifacts, 'confidence': None, 'status': 'needs_review',
                    'created_at': now(), 'demo': bool(sample.get('demo')), 'type': 'analyst_note'}
            state['evidence'].insert(0, item)
            audit(state, case['id'], 'evidence.created', item['id'])
            return item
        match = re.fullmatch(r'/api/evidence/([\w-]+)/review', path)
        if match:
            item = locate(state, 'evidence', match[1])
            if item['case_id'] != text(payload, 'case_id', 100):
                raise Problem('证据不属于当前 Case', 409)
            status = text(payload, 'status', 30)
            if status not in {'accepted', 'rejected'}:
                raise Problem('status 必须是 accepted 或 rejected')
            if item.get('status') != 'needs_review':
                raise Problem('该证据已经复核，请刷新工作台', 409)
            item.update(status=status, review_note=text(payload, 'note', 2000), reviewed_at=now())
            audit(state, item['case_id'], f'evidence.{status}', item['id'])
            return item
        if path == '/api/copilot/messages':
            case, sample = case_sample(state, payload, optional=True)
            message = text(payload, 'message')
            evidence = [x for x in state['evidence'] if x['case_id'] == case['id'] and (not sample or x.get('sample_id') == sample['id'])]
            real = [x for x in evidence if not x.get('demo')]
            answer = f"【本地规则助手 · 非 LLM】当前上下文：{sample['name'] if sample else case['name']}。共有 {len(real)} 条非演示记录，其中 {sum(x['status'] == 'needs_review' for x in real)} 条待复核。未连接 Ghidra / Frida / LLM，无法据此判断 C2、恶意性或函数语义。"
            if real:
                answer += '\n最近记录 [' + real[0]['id'] + ']：' + real[0]['claim'][:600]
            answer += '\n建议：先登记授权范围，导入元数据，执行元数据检查，补充工具输出的人工记录后复核并导出。不会自动执行重命名、写操作或进程附加。'
            for role, content in [('user', message), ('assistant', answer)]:
                entry = {'id': uid('msg'), 'case_id': case['id'], 'sample_id': sample['id'] if sample else None,
                         'role': role, 'content': content, 'created_at': now(), 'mode': 'local-rules'}
                state['messages'].append(entry)
            audit(state, case['id'], 'copilot.local_response', entry['id'])
            return {'message': entry, 'mode': 'local-rules'}
        if path == '/api/reports':
            case = locate(state, 'cases', text(payload, 'case_id', 100))
            format_name = text(payload, 'format', 10, 'json')
            if format_name not in {'json', 'html', 'md'}:
                raise Problem('仅支持 json / html / md')
            snapshot = make_report(state, case['id'], self.server.runtime.toolchain(self.server.toolchain))
            report = {'id': uid('rpt'), 'case_id': case['id'], 'format': format_name, 'status': 'completed',
                      'created_at': now(), 'snapshot': snapshot, 'sha256': digest(snapshot)}
            # Freeze a deep copy: later changes cannot mutate the signed-off snapshot.
            report = json.loads(encoded(report))
            state['reports'].insert(0, report)
            audit(state, case['id'], 'report.created', report['id'])
            return {k: v for k, v in report.items() if k != 'snapshot'}
        raise Problem('接口不存在', 404)


class ExclusiveHTTPServer(ThreadingHTTPServer):
    # HTTPServer's SO_REUSEADDR permits duplicate listeners on Windows.
    allow_reuse_address = False
    # The workbench fetches several independent collections simultaneously.
    request_queue_size = 64

    def server_close(self):
        if hasattr(self, 'apk_jobs'):
            self.apk_jobs.close()
        super().server_close()

    def server_bind(self):
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def create_server(host=None, port=None, data_path=None, config_path=None):
    config = load_config(config_path)
    effective_host = host if host is not None else os.environ.get('REVERSEAI_HOST', config.get('host', '127.0.0.1'))
    effective_port = port if port is not None else int(os.environ.get('REVERSEAI_PORT', config.get('port', 8787)))
    validate_config(config, effective_host)
    if effective_host not in LOOPBACK_HOSTS:
        raise ValueError('This unauthenticated development service must bind to loopback only')
    server = ExclusiveHTTPServer((effective_host, effective_port), APIHandler)
    try:
        server.store = Store(data_path or os.environ.get('REVERSEAI_STATE_FILE') or ROOT / 'data' / 'state.json')
    except Exception:
        server.server_close()
        raise
    server.config = config
    server.registry = default_registry()
    server.toolchain = server.registry.statuses()
    server.csrf_token = secrets.token_urlsafe(32)
    server.runtime = Runtime(server.store, now, audit)
    server.apk_jobs = APKJobs(server.store, now, audit)
    return server


def main():
    server = create_server()
    print(f'ReverseAI 0.5 APK static workbench: http://127.0.0.1:{server.server_address[1]}/', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
