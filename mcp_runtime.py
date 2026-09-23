"""Streamable HTTP MCP client, explicit discovery and constrained read tools."""
import json
import uuid
from provider_runtime import request, RuntimeErrorSafe

# Curated Ghidra read operations. Config allowlist is an additional restriction.
READ_TOOLS = frozenset({'list_functions', 'decompile_function', 'disassemble_function',
                        'get_function_by_address', 'get_xrefs_to', 'get_xrefs_from',
                        'list_strings', 'list_imports', 'list_exports', 'get_current_address',
                        'get_current_function', 'list_methods', 'get_program_info'})


class MCP:
    def __init__(self, config, secret=''):
        if config['transport'] != 'streamable_http':
            raise RuntimeErrorSafe('请使用 Streamable HTTP MCP 地址')
        self.config, self.secret = config, secret
        self.headers = {'Accept': 'application/json, text/event-stream'}
        if secret:
            self.headers['Authorization'] = 'Bearer ' + secret

    def rpc(self, method, params=None, notification=False):
        ident = str(uuid.uuid4())
        payload = {'jsonrpc': '2.0', 'method': method, 'params': params or {}}
        if not notification:
            payload['id'] = ident
        raw, headers, status = request(self.config['url'], payload, self.headers, self.config['timeout_seconds'])
        for key, value in headers.items():
            if key.lower() == 'mcp-session-id':
                self.headers['Mcp-Session-Id'] = value
        if notification and status in {200, 202, 204}:
            return {}
        try:
            if raw.lstrip().startswith(b'{'):
                result = json.loads(raw)
            else:
                # POST SSE response: notifications may precede the matching response.
                result = None
                for event in raw.decode('utf-8').replace('\r\n', '\n').split('\n\n'):
                    data = '\n'.join(line[5:].lstrip() for line in event.splitlines() if line.startswith('data:'))
                    if data:
                        item = json.loads(data)
                        if item.get('id') == ident:
                            result = item
                if result is None:
                    raise ValueError()
            if result.get('id') != ident:
                raise ValueError()
            if result.get('error'):
                raise RuntimeErrorSafe('MCP 返回协议错误；请检查工具参数、会话和协议版本')
            return result['result']
        except (KeyError, ValueError, UnicodeError, TypeError) as error:
            if isinstance(error, RuntimeErrorSafe):
                raise
            raise RuntimeErrorSafe('MCP 响应格式或请求 ID 不匹配') from None

    def initialize(self):
        result = self.rpc('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
                                        'clientInfo': {'name': 'ReverseAI', 'version': '0.5'}})
        version = result.get('protocolVersion')
        if version not in {'2025-03-26', '2025-06-18', '2025-11-25'}:
            raise RuntimeErrorSafe('MCP 协议版本不受支持（支持 2025 系列）')
        self.headers['MCP-Protocol-Version'] = version
        self.rpc('notifications/initialized', notification=True)
        return result

    def discover(self):
        info = self.initialize()
        tools, cursor = [], None
        for _ in range(30):
            result = self.rpc('tools/list', {'cursor': cursor} if cursor else {})
            if not isinstance(result.get('tools'), list):
                raise RuntimeErrorSafe('MCP 工具列表无效')
            tools.extend(result['tools'])
            next_cursor = result.get('nextCursor')
            if not next_cursor:
                return {'server': info.get('serverInfo', {}), 'protocol': info['protocolVersion'], 'tools': tools}
            if next_cursor == cursor:
                raise RuntimeErrorSafe('MCP 工具分页游标重复')
            cursor = next_cursor
        raise RuntimeErrorSafe('MCP 工具分页超过限制')

    def call(self, name, arguments):
        if name not in self.config['allowed_tools'] or name not in READ_TOOLS:
            raise RuntimeErrorSafe('工具不在已保存 allowlist 与只读工具白名单的交集中')
        self.initialize()
        result = self.rpc('tools/call', {'name': name, 'arguments': arguments})
        if result.get('isError'):
            raise RuntimeErrorSafe('MCP 工具执行失败；可能尚未连接 Ghidra 项目')
        return result

    def backend(self, project=None):
        """Explicit user action: list existing instances or connect a named project."""
        self.initialize()
        if project is not None:
            if not isinstance(project, str) or not 1 <= len(project.strip()) <= 200:
                raise RuntimeErrorSafe('请填写已有 Ghidra 项目名称')
            result = self.rpc('tools/call', {'name': 'connect_instance', 'arguments': {'project': project.strip()}})
        else:
            result = self.rpc('tools/call', {'name': 'list_instances', 'arguments': {}})
        if result.get('isError'):
            raise RuntimeErrorSafe('Ghidra 后端未就绪或未找到所选项目')
        return result

    def close(self):
        if self.headers.get('Mcp-Session-Id'):
            try:
                request(self.config['url'], headers=self.headers, timeout=2, method='DELETE')
            except RuntimeErrorSafe:
                pass
