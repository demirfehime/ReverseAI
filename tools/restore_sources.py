"""Restore pinned upstream sources; --check verifies existing files offline."""
import argparse
import hashlib
import json
from pathlib import Path

from import_sources import install

ROOT = Path(__file__).resolve().parents[1] / 'third_party'


def check(entry):
    target = ROOT / entry['repository'].split('/')[1]
    manifest_path = target / 'IMPORT_MANIFEST.json'
    if not manifest_path.exists():
        return False
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if any(manifest.get(key) != entry[key] for key in ('repository', 'revision', 'archive_sha256')):
        return False
    for relative, digest in manifest['files'].items():
        path = (target / relative).resolve()
        if not path.is_relative_to(target.resolve()) or not path.is_file():
            return False
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            return False
    return bool(manifest['files'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Verify locally without downloads')
    args = parser.parse_args()
    entries = json.loads((ROOT / 'sources.lock.json').read_text(encoding='utf-8'))['sources']
    for entry in entries:
        if not check(entry):
            if args.check:
                raise SystemExit(f"Missing or changed source: {entry['repository']}; run python tools/restore_sources.py")
            install(entry['repository'], entry['revision'], entry['archive_sha256'])
            if not check(entry):
                raise SystemExit(f"Restored source verification failed: {entry['repository']}")
        print(f"Verified {entry['repository']} @ {entry['revision']}")


if __name__ == '__main__':
    main()
