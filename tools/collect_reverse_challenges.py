"""Download public FLARE-On material only; never execute challenges or solvers."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib
import json
import urllib.request

ROOT = Path(__file__).resolve().parents[1] / 'datasets' / 'reverse-challenges'
FILES = {
    'archives/Flare-On10_Challenges.7z': 'https://www.flare-on.com/files/Flare-On10_Challenges.7z',
    'references/01-x/official-solution.pdf': 'https://services.google.com/fh/files/misc/1-x-flareon10.pdf',
    'references/02-itsonfire/official-solution.pdf': 'https://services.google.com/fh/files/misc/2-itsonfire-flareon10.pdf',
    'references/03-mypassion/official-solution.pdf': 'https://services.google.com/fh/files/misc/3-mypassion-flareon10.pdf',
    'references/04-aimbot/official-solution.pdf': 'https://services.google.com/fh/files/misc/4-aimbot-flareon10.pdf',
    'references/05-where-am-i/official-solution.pdf': 'https://services.google.com/fh/files/misc/5-where-am-i-flareon10.pdf',
    'references/12-hvm/official-solution.pdf': 'https://services.google.com/fh/files/misc/12-hvm-flareon10.pdf',
}

def download(item):
    relative, url = item
    target = ROOT / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        request = urllib.request.Request(url, headers={'User-Agent': 'ReverseAI-public-challenge-collection/1.0'})
        with urllib.request.urlopen(request, timeout=90) as response:
            content = response.read()
        expected = b'%PDF-' if target.suffix == '.pdf' else b'7z\xbc\xaf\x27\x1c'
        if not content.startswith(expected):
            raise ValueError(f'Unexpected file format: {url}')
        target.write_bytes(content)
    content = target.read_bytes()
    print(f'{relative}: {len(content)} bytes', flush=True)
    return {'path': relative, 'url': url, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}

if __name__ == '__main__':
    with ThreadPoolExecutor(max_workers=4) as pool:
        records = list(pool.map(download, FILES.items()))
    (ROOT / 'downloads.json').write_text(json.dumps(records, indent=2) + '\n', encoding='utf-8')
