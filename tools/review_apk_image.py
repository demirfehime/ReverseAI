"""Record an explicit visual transcription against a replayed derived image.

Separate from model tools: a reviewer must inspect the image before invoking.
Does not rewrite the model's answer or claim an OCR correction was automatic.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from apk_analysis import Corpus, Investigator, sha, write_json


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True)
    p.add_argument('--evidence-id',required=True)
    p.add_argument('--flag',required=True)
    p.add_argument('--reviewer',required=True)
    p.add_argument('--note',required=True)
    p.add_argument('--reference-id')
    a=p.parse_args()
    run=a.run.resolve()
    config=json.loads((run/'run.json').read_text(encoding='utf-8'))
    c=Corpus(config['corpus'],run)
    c.records=[json.loads(f.read_text(encoding='utf-8')) for f in sorted((run/'evidence').glob('*.json'))]
    engine=Investigator(c,None)
    engine.computations={r['id']:r for r in c.records if r['action']=='compute'}
    evidence=engine.computations[a.evidence_id]
    replay=engine.verify({'flag':a.flag,'evidence_ids':[a.evidence_id]})
    if not replay['derivation_replayed']:
        raise ValueError('Image derivation could not be replayed')
    review={'reviewer':a.reviewer,'note':a.note,'candidate':a.flag,'evidence_id':a.evidence_id,
            'artifact':evidence['result']['artifact'],'artifact_sha256':evidence['result']['output_sha256'],
            'derivation_replayed':True,'method':'explicit_visual_review','automatic_model_success':False}
    if a.reference_id:
        answers=json.loads((ROOT/'datasets/reverse-challenges/references/answers.json').read_text(encoding='utf-8'))
        review['reference_match']=a.flag==next(x['flag'] for x in answers if x['id']==a.reference_id)
    write_json(run/'visual-review.json',review)
    print(json.dumps(review,ensure_ascii=True))


if __name__=='__main__':main()
