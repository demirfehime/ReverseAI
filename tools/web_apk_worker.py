"""Fixed web worker entry point; no client-supplied commands or reference answers."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from apk_analysis import Corpus, Investigator, sha, write_json
from credentials import Vault
from provider_runtime import Provider
from tools.analyze_apk import decompile


def main():
    output = Path(sys.argv[1])
    config = json.loads((output / 'config.json').read_text(encoding='utf-8'))
    apk = Path(config['apk'])
    if sha(apk.read_bytes()) != config['sha256']:
        raise ValueError('Stored sample hash mismatch')
    extraction = decompile(apk, output / 'jadx')
    write_json(output / 'extraction.json', extraction)
    entry = config['provider']
    provider = Provider(entry, Vault(Path(config['vault'])).get('providers/' + entry['id'], entry['credential_env']))
    write_json(output / 'run.json', dict(sample_sha256=config['sha256'], model=entry['model'],
               extraction=extraction, reference_answers_sent=False, sample_executed=False))
    partial = '（存在反编译错误，部分代码可能不完整）' if extraction['partial'] else ''
    write_json(output / 'progress.json', dict(reason='反编译完成' + partial + '，模型正在读取代码和资源', progress=25,
                                            extraction_partial=extraction['partial']))
    engine = Investigator(Corpus(output / 'jadx', output), provider, config['max_calls'], config['seconds'], task=config.get('task'))
    engine.progress = lambda number: write_json(output / 'progress.json',
        dict(reason=f'模型调用 {number}/{config["max_calls"]}，证据持续保存' + partial, extraction_partial=extraction['partial'],
             progress=25 + int(65 * (number - 1) / config['max_calls'])))
    engine.run()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        write_json(Path(sys.argv[1]) / 'failure.json',
                   dict(reason=f'静态分析准备或执行失败（{type(error).__name__}）；请检查 Java、JADX、凭据及本地 worker.log'))
        raise
