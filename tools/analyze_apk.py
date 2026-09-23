"""Explicit local static-analysis worker; uses the configured provider credential.

Example: python tools/analyze_apk.py --apk sample.apk --model gpt-5.6-sol
Requires Java, pinned JADX under data/tools, and tools/apk-requirements.txt.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from apk_analysis import Corpus, Investigator, sha, write_json
from credentials import Vault
from provider_runtime import Provider


def decompile(apk, destination):
    jar=ROOT/'data/tools/jadx-1.5.6/lib/jadx-1.5.6-all.jar'
    if not jar.exists(): raise ValueError('Install JADX first: python tools/setup_jadx.py')
    destination.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,JADX_CONFIG_DIR=str(destination/'tool-config'),JADX_CACHE_DIR=str(destination/'tool-cache'))
    command=['java','-Xmx2g','--enable-native-access=ALL-UNNAMED','-cp',str(jar),'jadx.cli.JadxCLI',
             '-j','4','--no-inline-methods','--no-inline-anonymous','-d',str(destination),str(apk)]
    with (destination/'jadx.log').open('w',encoding='utf-8') as log:
        result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=300,
                              creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    info={'input_sha256':sha(apk.read_bytes()),'jadx_version':'1.5.6','jar_sha256':sha(jar.read_bytes()),
          'returncode':result.returncode,'partial':result.returncode!=0,'command':command}
    write_json(destination/'extraction.json',info)
    if not (destination/'resources/AndroidManifest.xml').exists() or not (destination/'sources').exists():
        raise ValueError('JADX did not produce an APK corpus; inspect jadx.log')
    return info


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk',type=Path,required=True)
    parser.add_argument('--corpus',type=Path,help='Reuse an existing JADX corpus after checking input hash')
    parser.add_argument('--model',default='gpt-5.6-sol')
    parser.add_argument('--max-calls',type=int,default=16)
    parser.add_argument('--seconds',type=int,default=900)
    parser.add_argument('--task', help='Analysis goal; specify challenge conventions explicitly for CTF tasks')
    parser.add_argument('--reference-id',help='Optional post-run scoring only; never sent to the model')
    parser.add_argument('--seed-run',type=Path,help='Replay prior read-only evidence; no previous answers are loaded')
    args=parser.parse_args()
    apk=args.apk.resolve()
    if not apk.is_file() or apk.stat().st_size>100_000_000:
        raise ValueError('APK must be an existing file under 100 MB')
    output=ROOT/'data/apk-analysis'/('run-'+time.strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6])
    output.mkdir(parents=True)
    corpus_path=args.corpus.resolve() if args.corpus else output/'jadx'
    if args.corpus:
        extraction=json.loads((corpus_path/'extraction.json').read_text(encoding='utf-8'))
        if extraction['input_sha256']!=sha(apk.read_bytes()): raise ValueError('Corpus input hash mismatch')
    else: extraction=decompile(apk,corpus_path)
    config=json.loads((ROOT/'data/state.json').read_text(encoding='utf-8'))['settings']
    entry=copy.deepcopy(next(p for p in config['providers'] if p['enabled']))
    entry['model']=args.model
    provider=Provider(entry,Vault(ROOT/'data/credentials.dpapi').get('providers/'+entry['id'],entry['credential_env']))
    write_json(output/'run.json',{'sample_sha256':sha(apk.read_bytes()),'provider':entry['id'],'model':entry['model'],
                                'corpus':str(corpus_path),'extraction':extraction,'max_calls':args.max_calls,
                                'time_budget_seconds':args.seconds,'reference_answers_sent':False})
    print('RUN',output,flush=True)
    corpus=Corpus(corpus_path,output)
    if args.seed_run:
        previous=json.loads((args.seed_run/'run.json').read_text(encoding='utf-8'))
        if previous['sample_sha256']!=sha(apk.read_bytes()): raise ValueError('Seed run belongs to another sample')
        for item in sorted((args.seed_run/'evidence').glob('*.json')):
            record=json.loads(item.read_text(encoding='utf-8'))
            if record['action'] in {'read','search','resource','list_files'}:
                corpus.dispatch(record['action'],record['arguments'])
        write_json(output/'seed.json',{'source_run':str(args.seed_run.resolve()),'replayed_evidence':len(corpus.records)})
    result=Investigator(corpus,provider,args.max_calls,args.seconds,task=args.task).run()
    if args.reference_id:
        answers=json.loads((ROOT/'datasets/reverse-challenges/references/answers.json').read_text(encoding='utf-8'))
        expected=next(a['flag'] for a in answers if a['id']==args.reference_id)
        verification=result['verification']
        verification['reference_match']=verification.get('candidate')==expected
        verification['derived_answer_pass']=bool(verification.get('reference_match') and verification.get('derivation_replayed')
                                                 and verification.get('candidate_in_derived_ocr'))
        write_json(output/'result.json',result)
    print(json.dumps({'status':result['status'],'verification':result['verification']},ensure_ascii=True),flush=True)


if __name__=='__main__': main()
