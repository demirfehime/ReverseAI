"""Integrity-checked local Skill text registry. Never executes imported scripts."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent / 'third_party' / 'reverse-skill'


def catalog():
    manifest_path = ROOT / 'IMPORT_MANIFEST.json'
    if not manifest_path.exists():
        return []
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    items = []
    for path, checksum in manifest['files'].items():
        if not path.startswith('skills/') or not path.endswith('/SKILL.md') or len(path.split('/')) < 3:
            continue
        file = (ROOT / path).resolve()
        if not file.is_relative_to(ROOT.resolve()) or not file.is_file():
            continue
        raw = file.read_bytes()
        content = raw.decode('utf-8-sig')
        valid = hashlib.sha256(raw).hexdigest() == checksum
        name = re.search(r'^name:\s*(.+)$', content, re.M)
        description = re.search(r'^description:\s*(.+)$', content, re.M)
        items.append({'id': '--'.join(path.split('/')[1:-1]), 'name': name.group(1).strip('"\'') if name else path.split('/')[1],
                      'description': description.group(1).strip('"\'') if description else '', 'path': path,
                      'revision': manifest['revision'], 'sha256': checksum, 'verified': valid})
    return sorted(items, key=lambda x: x['id'])


def read(skill_id):
    item = next((x for x in catalog() if x['id'] == skill_id), None)
    if not item or not item['verified']:
        raise ValueError('Skill 缺失或内容校验失败，请重新导入固定版本')
    return {**item, 'content': (ROOT / item['path']).read_text(encoding='utf-8-sig')}


def resolve(definitions, ids):
    result = []
    for ident in ids:
        config = next((x for x in definitions if x['id'] == ident and x['enabled']), None)
        if not config:
            raise ValueError('任务引用的 Skill 未启用或不存在')
        # Root template uses the concrete reverse-engineering skill, not an executable router.
        source_id = 'reverse-engineering' if ident == 'reverse-skill' else ident
        content = read(source_id)
        if config['version'] and config['version'] != content['revision']:
            raise ValueError('Skill 配置版本与本地锁定版本不一致')
        result.append(content)
    return result
