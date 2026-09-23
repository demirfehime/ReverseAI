"""Download and verify the pinned official JADX bundle inside the project."""
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[1]
URL='https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip'
SHA256='545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974'


def main():
    target=ROOT/'data/tools/jadx-1.5.6'
    target.mkdir(parents=True,exist_ok=True)
    archive=target/'distribution.zip'
    data=archive.read_bytes() if archive.exists() else urllib.request.urlopen(URL,timeout=90).read()
    if hashlib.sha256(data).hexdigest()!=SHA256: raise ValueError('JADX bundle hash mismatch')
    with zipfile.ZipFile(io.BytesIO(data)) as bundle:
        for info in bundle.infolist():
            if not (target/info.filename).resolve().is_relative_to(target.resolve()):
                raise ValueError('Unsafe archive member')
        bundle.extractall(target)
    archive.write_bytes(data)
    (target/'provenance.json').write_text(json.dumps({'url':URL,'sha256':SHA256,'bytes':len(data)},indent=2)+'\n')
    print(target)


if __name__=='__main__': main()
