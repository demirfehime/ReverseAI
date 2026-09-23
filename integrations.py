"""Versioned integration settings; validation never performs network requests."""
import copy
import re
from urllib.parse import urlsplit

DEFAULTS = {
    'version': 1,
    'providers': [],
    'agents': {'enabled': False, 'max_concurrency': 1, 'call_budget': 4,
               'time_budget_seconds': 60, 'model': '', 'allowed_tools': [],
               'delegation_mode': 'manual', 'max_children': 20, 'provider_id': ''},
    'mcp': [{'id': 'ghidra', 'source': 'bethington/ghidra-mcp', 'enabled': False,
             'transport': 'streamable_http', 'url': 'http://127.0.0.1:8081/mcp', 'credential_env': '',
             'timeout_seconds': 10, 'allowed_tools': []}],
    'skills': [{'id': 'reverse-skill', 'source': 'zhaoxuya520/reverse-skill',
                'version': '', 'description': '逆向知识工作流模板，未安装',
                'enabled': False, 'tasks': [], 'allowed_tools': [], 'parameters': {}}],
    'workers': [{'id': name, 'enabled': False, 'description': '未安装 / 未连接'}
                for name in ('frida', 'yara', 'capa', 'triage', 'sandbox')],
    'playbooks': [],
}


def defaults():
    return copy.deepcopy(DEFAULTS)


def validate(value):
    value = copy.deepcopy(value)
    if isinstance(value, dict) and isinstance(value.get('agents'), dict):
        for key in ('delegation_mode', 'max_children', 'provider_id'):
            value['agents'].setdefault(key, DEFAULTS['agents'][key])
    if not isinstance(value, dict) or set(value) != set(DEFAULTS) or value.get('version') != 1:
        raise ValueError('配置必须包含全部模板字段，version 必须为 1')
    schemas = {
        'providers': {'id', 'protocol', 'base_url', 'credential_env', 'timeout_seconds', 'model', 'enabled'},
        'mcp': {'id', 'source', 'enabled', 'transport', 'url', 'credential_env', 'timeout_seconds', 'allowed_tools'},
        'skills': {'id', 'source', 'version', 'description', 'enabled', 'tasks', 'allowed_tools', 'parameters'},
        'workers': {'id', 'enabled', 'description'},
        'playbooks': {'id', 'name', 'steps', 'skill_ids'},
    }
    for group, fields in schemas.items():
        entries = value[group]
        if not isinstance(entries, list) or len(entries) > 100:
            raise ValueError(f'{group} 必须是最多 100 项的数组')
        ids = set()
        for entry in entries:
            optional = {'headers'} if group == 'providers' else set()
            if not isinstance(entry, dict) or not fields <= set(entry) or set(entry) - fields - optional:
                raise ValueError(f'{group} 字段必须为 {sorted(fields)}')
            ident = entry['id']
            if not isinstance(ident, str) or not re.fullmatch(r'[\w-]{1,80}', ident) or ident in ids:
                raise ValueError(f'{group} id 无效或重复')
            ids.add(ident)
            if 'enabled' in entry and type(entry['enabled']) is not bool:
                raise ValueError('enabled 必须为布尔值')
            if group == 'workers' and entry.get('enabled'):
                raise ValueError(f'{group} 运行时未实现，只能保存 disabled 配置草案')
            for key, item in entry.items():
                if key in {'enabled', 'timeout_seconds', 'parameters', 'headers'}:
                    continue
                if key in {'steps', 'skill_ids', 'tasks', 'allowed_tools'}:
                    if not isinstance(item, list) or len(item) > 100 or any(not isinstance(x, str) or not x.strip() or len(x) > 2000 for x in item):
                        raise ValueError(f'{key} 必须是短字符串数组')
                elif not isinstance(item, str) or len(item) > 2000:
                    raise ValueError(f'{key} 必须为短字符串')
            if 'timeout_seconds' in entry and (type(entry['timeout_seconds']) is not int or not 1 <= entry['timeout_seconds'] <= 120):
                raise ValueError('timeout_seconds 必须为 1–120')
            if 'headers' in entry:
                headers = entry['headers']
                if not isinstance(headers, dict) or len(headers) > 12:
                    raise ValueError('headers 必须是最多 12 项的对象')
                for key, val in headers.items():
                    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,70}', key) or key.lower() in {'host', 'authorization', 'x-api-key', 'cookie', 'content-length', 'content-type', 'accept', 'connection', 'transfer-encoding'}:
                        raise ValueError('请求头名称无效或包含需单独保管的凭据头')
                    if not isinstance(val, str) or len(val)>1000 or '\r' in val or '\n' in val:
                        raise ValueError('请求头值必须为短单行字符串')
            if entry.get('credential_env') and not re.fullmatch('[A-Z_][A-Z0-9_]{0,100}', entry['credential_env']):
                raise ValueError('凭据仅接受环境变量名，不接受密钥')
            for key in ('url', 'base_url'):
                if entry.get(key):
                    url = urlsplit(entry[key])
                    if url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password or url.query or url.fragment:
                        raise ValueError('URL 仅接受无凭据、无查询参数的 HTTP(S) 地址')
            if group == 'providers' and entry['protocol'] not in {'chat_completions', 'responses', 'anthropic_messages'}:
                raise ValueError('未知协议草案类型')
            if group == 'mcp' and entry['transport'] not in {'unconfigured', 'streamable_http', 'stdio'}:
                raise ValueError('未知 MCP 传输草案类型')
            if group == 'mcp' and entry.get('enabled') and entry['transport'] != 'streamable_http':
                raise ValueError('当前 MCP 客户端支持 Streamable HTTP；stdio 请通过独立桥接服务转换')
            if group in {'providers', 'mcp'} and entry.get('enabled') and not entry.get('base_url', entry.get('url')):
                raise ValueError('启用前需要填写服务地址')
            if group == 'skills' and entry['parameters'] != {}:
                raise ValueError('当前仅支持空 parameters；不保存未经定义的敏感参数')
            if group == 'skills' and entry.get('enabled'):
                from skill_runtime import resolve
                if entry['source'] != 'zhaoxuya520/reverse-skill':
                    raise ValueError('当前仅支持已导入并校验的 reverse-skill 文本')
                resolve([entry], [entry['id']])
            if group == 'playbooks' and (not entry['name'].strip() or not entry['steps']):
                raise ValueError('Playbook 必须有名称及至少一个步骤')
    agents = value['agents']
    if not isinstance(agents, dict) or set(agents) != set(DEFAULTS['agents']):
        raise ValueError('agents 字段无效')
    if type(agents['enabled']) is not bool:
        raise ValueError('agents.enabled 必须是布尔值')
    for key, limit in [('max_concurrency', 8), ('call_budget', 100), ('time_budget_seconds', 3600), ('max_children', 100)]:
        if type(agents[key]) is not int or not 1 <= agents[key] <= limit:
            raise ValueError(f'agents.{key} 超出范围')
    if not isinstance(agents['model'], str) or len(agents['model']) > 200 or agents['allowed_tools'] != []:
        raise ValueError('当前子 Agent 不支持工具权限，只接受短模型标识')
    if agents['delegation_mode'] not in ('manual', 'auto'):
        raise ValueError('委派模式必须为 manual 或 auto')
    if not isinstance(agents['provider_id'], str) or (agents['provider_id'] and agents['provider_id'] not in {p['id'] for p in value['providers']}):
        raise ValueError('子 Agent Provider 不存在')
    skill_ids = {x['id'] for x in value['skills']}
    if any(set(x['skill_ids']) - skill_ids for x in value['playbooks']):
        raise ValueError('Playbook 引用了不存在的 Skill')
    if sum(bool(x['enabled']) for x in value['providers']) > 1:
        raise ValueError('一次只能启用一个默认 Provider；其他配置可以保存和测试')
    return copy.deepcopy(value)
