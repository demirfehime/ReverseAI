"""Bounded HTTP protocol adapters. No automatic function/tool execution."""
import json
import socket
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit


class RuntimeErrorSafe(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeErrorSafe('服务返回重定向；为避免泄露凭据，请直接配置最终地址')


def request(url, payload=None, headers=None, timeout=20, method=None):
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json', **(headers or {})}, method=method)
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=timeout) as response:
            data = response.read(4_000_001)
            if len(data) > 4_000_000:
                raise RuntimeErrorSafe('响应超过 4 MB 限制')
            return data, dict(response.headers), response.status
    except urllib.error.HTTPError as error:
        # Do not relay response bodies: providers may echo submitted secrets.
        raise RuntimeErrorSafe(f'远程服务 HTTP {error.code}；请检查地址、凭据、模型和权限') from None
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError):
        raise RuntimeErrorSafe('连接失败或超时，请检查服务地址和网络') from None


def json_request(*args, **kwargs):
    data, headers, status = request(*args, **kwargs)
    try:
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError()
    except (ValueError, UnicodeError):
        raise RuntimeErrorSafe('远程服务返回了无效 JSON') from None
    return result, headers, status


def endpoint(base, suffix):
    parsed = urlsplit(base.rstrip('/'))
    path = parsed.path.rstrip('/')
    for ending in ('/chat/completions', '/responses', '/messages', '/models'):
        if path.endswith(ending):
            path = path[:-len(ending)]
            break
    if not path:
        path = '/v1'
    return urlunsplit((parsed.scheme, parsed.netloc, path + '/' + suffix, '', ''))


class Provider:
    def __init__(self, config, secret=''):
        self.config = config
        self.secret = secret
        self.protocol = config['protocol']

    def headers(self):
        headers = {'User-Agent': 'ReverseAI/1.0', **self.config.get('headers', {})}
        if self.protocol == 'anthropic_messages':
            return {**headers, 'anthropic-version': '2023-06-01', **({'x-api-key': self.secret} if self.secret else {})}
        return {**headers, **({'Authorization': 'Bearer ' + self.secret} if self.secret else {})}

    def models(self):
        url = endpoint(self.config['base_url'], 'models')
        models, cursor = [], None
        for _ in range(20):
            from urllib.parse import urlencode
            page_url = url + ('?' + urlencode({'after_id': cursor}) if cursor else '')
            result, _, _ = json_request(page_url, headers=self.headers(), timeout=self.config['timeout_seconds'])
            if not isinstance(result.get('data'), list):
                raise RuntimeErrorSafe('服务不支持模型列表；请手动填写模型 ID')
            models.extend(x['id'] for x in result['data'] if isinstance(x, dict) and isinstance(x.get('id'), str))
            if not result.get('has_more'):
                return sorted(set(models))
            next_cursor = result.get('last_id')
            if not next_cursor or next_cursor == cursor:
                raise RuntimeErrorSafe('模型分页游标无效；请手动填写模型 ID')
            cursor = next_cursor
        raise RuntimeErrorSafe('模型列表超过分页限制；请手动填写模型 ID')

    def complete(self, prompt, system='', model=None, timeout=None, stream=False, tools=None):
        if stream or tools:
            raise RuntimeErrorSafe('此适配器当前支持非流式文本；流式输出和模型工具调用不受支持')
        model = model or self.config['model']
        if not model:
            raise RuntimeErrorSafe('请先选择或填写模型 ID')
        if self.protocol == 'responses':
            suffix, body = 'responses', {'model': model, 'input': prompt, 'instructions': system, 'store': False}
        elif self.protocol == 'anthropic_messages':
            suffix, body = 'messages', {'model': model, 'system': system, 'max_tokens': 2048, 'messages': [{'role': 'user', 'content': prompt}]}
        else:
            suffix, body = 'chat/completions', {'model': model, 'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': prompt}], 'stream': False}
        result, _, _ = json_request(endpoint(self.config['base_url'], suffix), body, self.headers(), timeout or self.config['timeout_seconds'])
        try:
            if self.protocol == 'responses':
                output = result.get('output', [])
                if any(x.get('type') in {'function_call', 'mcp_call'} for x in output):
                    raise RuntimeErrorSafe('模型返回工具调用，当前不会执行；请使用文本输出模型')
                text = ''.join(c.get('text', '') for x in output if x.get('type') == 'message' for c in x.get('content', []) if c.get('type') == 'output_text')
            elif self.protocol == 'anthropic_messages':
                if any(x.get('type') == 'tool_use' for x in result.get('content', [])):
                    raise RuntimeErrorSafe('模型返回工具调用，当前不会执行')
                text = ''.join(x.get('text', '') for x in result['content'] if x.get('type') == 'text')
            else:
                message = result['choices'][0]['message']
                if message.get('tool_calls') or message.get('function_call'):
                    raise RuntimeErrorSafe('模型返回工具调用，当前不会执行')
                text = message['content']
            if not isinstance(text, str) or not text.strip():
                raise RuntimeErrorSafe('服务返回空文本或不支持的响应格式')
            if self.secret:
                text = text.replace(self.secret, '[REDACTED]')
            return text[:32000]
        except (KeyError, IndexError, TypeError):
            raise RuntimeErrorSafe('响应格式不匹配所选协议') from None
