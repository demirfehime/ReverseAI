"""Import pinned upstream text/code without running third-party installation hooks."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1] / 'third_party'

def install(repo, revision, expected_sha256=None):
    target = ROOT / repo.split('/')[1]
    url = f'https://codeload.github.com/{repo}/zip/{revision}'
    with urllib.request.urlopen(url, timeout=60) as response:
        archive = response.read(32 * 1024 * 1024 + 1)
    if len(archive) > 32 * 1024 * 1024:
        raise ValueError('Source archive exceeds 32 MiB; no files imported')
    if expected_sha256 and hashlib.sha256(archive).hexdigest() != expected_sha256:
        raise ValueError('Upstream archive hash mismatch; no files imported')
    files = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        for info in bundle.infolist():
            path = PurePosixPath(info.filename)
            relative = PurePosixPath(*path.parts[1:])
            if '..' in relative.parts or not relative.parts or info.is_dir():
                continue
            # Only text reference assets for Skill; only Python bridge code + metadata for MCP.
            if repo.endswith('reverse-skill'):
                wanted = relative.suffix.lower() in {'.md', '.json', '.yaml', '.yml'} or relative.name in {'LICENSE', 'VERSION'}
            else:
                wanted = relative.suffix.lower() in {'.py', '.toml', '.txt', '.md', '.json'} or relative.name == 'LICENSE'
            if not wanted or any(p in {'.git', 'tests', '.github', 'node_modules'} for p in relative.parts):
                continue
            if info.file_size > 2 * 1024 * 1024:
                continue
            data = bundle.read(info)
            destination = target.joinpath(*relative.parts).resolve()
            if not destination.is_relative_to(target.resolve()):
                raise ValueError('Unsafe archive path')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            files[str(relative)] = hashlib.sha256(data).hexdigest()
    manifest = {'repository': repo, 'revision': revision, 'archive_sha256': hashlib.sha256(archive).hexdigest(), 'files': files}
    target.mkdir(parents=True, exist_ok=True)
    (target / 'IMPORT_MANIFEST.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(repo, revision, len(files), 'files imported; no scripts executed')

if __name__ == '__main__':
    install(sys.argv[1], sys.argv[2])
