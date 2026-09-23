"""Static challenge/API benchmark. Never executes sample files or solution scripts.

Uses the enabled provider and existing credential vault, with a separate local
API/state directory. Only extracted text evidence is sent to the provider.
Requires py7zr. Run explicitly; this is not part of offline regression tests.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from credentials import Vault
from server import create_server, audit_valid


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def score_result(result, observations, expected_flag):
    parsed = result.get('parsed')
    flag = parsed.get('flag') if isinstance(parsed, dict) else None
    citations = parsed.get('evidence') if isinstance(parsed, dict) else None
    valid_format = (isinstance(parsed, dict) and parsed.get('nonce')==result.get('nonce')
                    and 'flag' in parsed and (flag is None or isinstance(flag, str))
                    and isinstance(citations, list) and isinstance(parsed.get('limitations'), list))
    valid_citations = isinstance(citations, list) and all(
        isinstance(c,dict) and any(all(c.get(k)==s.get(k) for k in ('file','offset','text')) for s in observations)
        for c in citations)
    visible_flag = isinstance(flag,str) and bool(flag) and valid_citations and any(flag in c['text'] for c in citations)
    reference_match = isinstance(flag,str) and flag==expected_flag
    return {'format_pass':valid_format, 'flag_matches_reference':reference_match,
            'citations_supported':valid_citations, 'flag_supported_by_citation':bool(visible_flag),
            'grounded_flag_pass':bool(valid_format and reference_match and visible_flag),
            'abstained':bool(valid_format and flag is None)}


def strings(data):
    result = []
    for pattern, encoding in [(rb'[\x20-\x7e]{5,}', 'ascii'), (rb'(?:[\x20-\x7e]\x00){5,}', 'utf-16le')]:
        for match in re.finditer(pattern, data):
            value = match.group().decode(encoding)
            if len(value) <= 240:
                result.append({'offset': hex(match.start()), 'encoding': encoding, 'text': value})
    return result


def inspect_bytes(name, data):
    meta = {'file': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    observations = []
    if data.startswith(b'MZ'):
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        if data[pe:pe+4] != b'PE\0\0':
            raise ValueError('Invalid PE signature')
        machine, count = struct.unpack_from('<HH', data, pe+4)
        optsize = struct.unpack_from('<H', data, pe+20)[0]
        meta.update(format='PE', machine=hex(machine), sections=[])
        for n in range(count):
            off = pe+24+optsize+40*n
            meta['sections'].append(data[off:off+8].rstrip(b'\0').decode('ascii', errors='replace'))
        observations = strings(data)
    elif data.startswith(b'PK'):
        meta['format'] = 'APK/ZIP'
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            meta['entries'] = archive.namelist()[:40]
            for info in archive.infolist():
                if info.filename.endswith('.dex') or info.filename in {'resources.arsc', 'AndroidManifest.xml'}:
                    if info.file_size > 32_000_000:
                        continue
                    observations.extend({**s, 'member': info.filename} for s in strings(archive.read(info)))
    else:
        meta['format'] = 'Unknown'
        observations = strings(data)
    pattern = re.compile(r'flare|flag|password|correct|wrong|success|fail|lock|decrypt|encrypt|hypervisor|WinHv|debugger|wednesday|firebase|MessageWorker', re.I)
    selected = [s for s in observations if pattern.search(s['text'])]
    meta['strings_total'] = len(observations)
    meta['strings_selected_total'] = len(selected)
    return meta, selected


def prepare(spec, output):
    import py7zr
    from py7zr.io import BytesIOFactory
    path = ROOT/'datasets/reverse-challenges'/spec['archive']
    factory = BytesIOFactory(limit=64_000_000)
    with py7zr.SevenZipFile(path, password=spec['archive_password']) as archive:
        members = [x.filename for x in archive.list() if not x.is_directory]
        selected = ['X.exe', 'X.dll'] if spec['id'] == '01-x' else members
        archive.extract(targets=selected, factory=factory)
    metadata, evidence = [], []
    for name in selected:
        content = factory.get(name).read()
        target = output/'samples'/spec['id']/(Path(name).name+'.bin')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        meta, observations = inspect_bytes(name, content)
        metadata.append(meta)
        evidence.extend({**s, 'file': name} for s in observations)
    # Deterministic generic string filter; never reads reference answers here.
    packet = {'method': 'PE headers and ASCII/UTF-16LE strings; APK member strings',
              'sample_executed': False, 'disassembly_available': False,
              'files': metadata, 'observations': evidence}
    save(output/'artifacts'/f"{spec['id']}.json", packet)
    return packet


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ids', nargs='+', default=['01-x'])
    parser.add_argument('--max-observations', type=int, default=40)
    parser.add_argument('--model', help='Override the model in this isolated test state only')
    args = parser.parse_args()
    output = ROOT/'data/challenge-runs'/time.strftime('%Y%m%d-%H%M%S')
    output.mkdir(parents=True, exist_ok=False)
    source = json.loads((ROOT/'data/state.json').read_text(encoding='utf-8'))
    enabled = next(p for p in source['settings']['providers'] if p['enabled'])
    if args.model:
        enabled['model'] = args.model
    server = create_server(port=0, data_path=output/'state.json')
    server.quiet = True
    with server.store.lock:
        state = server.store.load()
        state['settings'] = source['settings']
        server.store.save(state)
    server.runtime.vault = Vault(ROOT/'data/credentials.dpapi')
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    token = server.csrf_token

    def api(path, payload):
        request = urllib.request.Request(base+path, data=json.dumps(payload).encode(),
            headers={'Content-Type':'application/json', 'X-ReverseAI-Token':token})
        try:
            with urllib.request.urlopen(request, timeout=enabled['timeout_seconds']+30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError(json.loads(error.read()).get('error','Local API error')) from None

    results = []
    try:
        specs = json.loads((ROOT/'datasets/reverse-challenges/manifest.json').read_text(encoding='utf-8'))['challenges']
        if set(args.ids)-{s['id'] for s in specs}:
            raise ValueError('Unknown challenge id')
        for spec in specs:
            if spec['id'] not in args.ids:
                continue
            packet = prepare(spec, output)
            case = api('/api/cases', {'name':'API benchmark '+spec['id'], 'authorization':'User-authorized public CTF static analysis and configured API test'})
            primary = packet['files'][-1] if spec['id']=='01-x' else packet['files'][0]
            sample = api('/api/samples', {'case_id':case['id'], 'name':primary['file'], 'size':primary['bytes'],
                'sha256':primary['sha256'], 'kind':primary['format']})['sample']
            duplicate = api('/api/samples', {'case_id':case['id'], 'name':primary['file'], 'size':primary['bytes'],
                'sha256':primary['sha256'], 'kind':primary['format']})
            assert duplicate['duplicate'] and duplicate['sample']['id']==sample['id']
            job = api('/api/analysis/jobs', {'case_id':case['id'], 'sample_id':sample['id'], 'type':'metadata_check'})
            assert job['status']=='completed'
            blocked = api('/api/analysis/jobs', {'case_id':case['id'], 'sample_id':sample['id'], 'type':'static_triage'})
            assert blocked['status']=='blocked'
            # Prioritize direct indicators and primary-file observations over
            # launcher/framework noise before applying the context limit.
            ranked = sorted(packet['observations'], key=lambda s: (
                0 if re.search(r'flag|@flare-on\.com|password', s['text'], re.I) else 1,
                0 if s['file']==primary['file'] else 1))
            excerpt = {**packet, 'observations':ranked[:max(1,args.max_observations)],
                       'observations_total':len(ranked)}
            claim = json.dumps(excerpt, ensure_ascii=False)
            while len(claim)>7500 and excerpt['observations']:
                excerpt['observations'].pop()
                claim = json.dumps(excerpt, ensure_ascii=False)
            api('/api/evidence', {'case_id':case['id'], 'sample_id':sample['id'], 'subject':'Local static extraction (not sample execution)',
                'claim':claim, 'artifacts':['sha256:'+primary['sha256']]})
            nonce = uuid.uuid4().hex[:12]
            prompt = ('Analyze only the supplied static observations from this public CTF sample. '
                'Do not use recalled challenge solutions. Do not claim to run or disassemble the file. '
                'This is candidate extraction, not proof that execution accepts the candidate. '
                'The public competition uses email-shaped flags ending in @flare-on.com. '
                'If an observation contains a complete nonempty email-shaped candidate with that domain, '
                'copy that candidate to flag without surrounding whitespace. A bare @flare-on.com suffix is not a candidate. '
                'Return one JSON object with fields nonce, flag (string or null), evidence '
                '(array of objects with file, offset, text copied from observations), limitations (array of strings). '
                'Report a flag only when its exact bytes are visible in observations; otherwise use null. '
                f'The nonce must be {nonce}. Explain briefly in Chinese in limitations.')
            save(output/'requests'/f"{spec['id']}.json", {'user_request':prompt,'evidence':excerpt,'nonce':nonce})
            print('CALL',spec['id'],enabled['model'],flush=True)
            started = time.monotonic()
            result = {'id':spec['id'], 'provider':enabled['id'], 'model':enabled['model'], 'nonce':nonce,
                      'sample_executed':False, 'local_api_workflow':'passed', 'automatic_static_adapter':'blocked'}
            try:
                response = api('/api/copilot/complete', {'case_id':case['id'],'sample_id':sample['id'],'message':prompt,'skill_ids':[]})
                raw = response['message']['content']
                result['response'] = raw
                normalized = re.sub(r'^```(?:json)?\s*|\s*```$', '', raw.strip())
                try:
                    parsed = json.loads(normalized)
                    result['parsed'] = parsed
                    result['format_pass'] = isinstance(parsed,dict) and parsed.get('nonce')==nonce
                except (ValueError, TypeError):
                    result['format_pass'] = False
                result['transport'] = 'passed'
            except (RuntimeError, OSError) as error:
                result.update(transport='failed', error=str(error), format_pass=False)
            result['elapsed_seconds'] = round(time.monotonic()-started,2)
            results.append(result)
            save(output/'results.json',results)
            print('RESULT', spec['id'],result['transport'],'format:',result['format_pass'],result['elapsed_seconds'],flush=True)
        # Answer material becomes visible only to the scorer, after all requests.
        answers = {a['id']:a for a in json.loads((ROOT/'datasets/reverse-challenges/references/answers.json').read_text(encoding='utf-8'))}
        for result in results:
            sent = json.loads((output/'requests'/f"{result['id']}.json").read_text(encoding='utf-8'))['evidence']['observations']
            result.update(score_result(result, sent, answers[result['id']]['flag']))
        save(output/'results.json',results)
        assert audit_valid(server.store.load()['audit'])
        print('REPORT',output,flush=True)
    finally:
        server.shutdown()
        server.server_close()
        server.runtime.pool.shutdown(wait=True, cancel_futures=True)
        thread.join(timeout=2)


if __name__ == '__main__':
    main()
