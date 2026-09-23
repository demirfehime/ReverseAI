"""Web APK storage and supervised static-analysis subprocesses."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time
import uuid
import zipfile

from provider_runtime import RuntimeErrorSafe

ROOT = Path(__file__).resolve().parent
ACTIVE = {'queued', 'running'}


class APKJobs:
    def __init__(self, store, now, audit):
        self.store, self.now, self.audit = store, now, audit
        self.root = store.path.parent / 'web-apk'
        self.root.mkdir(exist_ok=True)
        self.closed = threading.Event()
        self.threads = []
        with store.lock:
            state = store.load()
            for job in state['jobs']:
                if job.get('executor') == 'apk_static/v1' and job['status'] in ACTIVE:
                    job.update(status='failed', reason='服务重启，任务中断；请重新启动', finished_at=now())
                    self.audit(state, job['case_id'], 'apk.interrupted', job['id'])
            store.save(state)

    def upload(self, stream, length, case_id, name):
        if not isinstance(name, str) or not 1 <= len(name) <= 180 or '/' in name or '\\' in name:
            raise RuntimeErrorSafe('无效文件名')
        with self.store.lock:
            if not any(c['id'] == case_id for c in self.store.load()['cases']):
                raise RuntimeErrorSafe('Case 不存在')
        temporary = self.root / (uuid.uuid4().hex + '.upload')
        hasher = hashlib.sha256()
        try:
            with temporary.open('wb') as target:
                remaining = length
                while remaining:
                    chunk = stream.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        raise RuntimeErrorSafe('上传不完整')
                    target.write(chunk)
                    hasher.update(chunk)
                    remaining -= len(chunk)
            try:
                with zipfile.ZipFile(temporary) as archive:
                    entries = archive.infolist()
                    names = {e.filename for e in entries}
                    if len(entries) > 50000 or sum(e.file_size for e in entries) > 1_000_000_000:
                        raise RuntimeErrorSafe('APK 解压规模超过限制')
                    if 'AndroidManifest.xml' not in names or 'classes.dex' not in names:
                        raise RuntimeErrorSafe('需要包含 AndroidManifest.xml 和 classes.dex 的 APK')
                    if any(n.startswith(('/', '\\')) or '\\' in n or ':' in n or '..' in n.split('/') for n in names):
                        raise RuntimeErrorSafe('APK 包含不安全的归档路径')
            except zipfile.BadZipFile:
                raise RuntimeErrorSafe('文件不是有效 APK ZIP 归档') from None
            digest = hasher.hexdigest()
            with self.store.lock:
                state = self.store.load()
                sample = next((s for s in state['samples'] if s['case_id'] == case_id and s['sha256'] == digest), None)
                duplicate = sample is not None
                if sample is None:
                    sample = dict(id='smp_' + uuid.uuid4().hex, case_id=case_id, name=name,
                                  created_at=self.now(), risk='pending', demo=False)
                    state['samples'].insert(0, sample)
                destination = self.root / (digest + '.apk')
                if destination.exists():
                    temporary.unlink()
                else:
                    temporary.replace(destination)
                sample.update(size=length, sha256=digest, kind='APK', mime='application/vnd.android.package-archive',
                              hash_source='server-upload', stored_apk=True)
                self.audit(state, case_id, 'sample.apk_uploaded', sample['id'])
                self.store.save(state)
                return {'sample': sample, 'duplicate': duplicate}
        finally:
            temporary.unlink(missing_ok=True)

    def start(self, payload):
        if self.closed.is_set():
            raise RuntimeErrorSafe('服务正在关闭')
        with self.store.lock:
            state = self.store.load()
            sample = next((s for s in state['samples'] if s['id'] == payload.get('sample_id') and s['case_id'] == payload.get('case_id')), None)
            if not sample or not sample.get('stored_apk'):
                raise RuntimeErrorSafe('请先上传 APK 文件正文，再启动 APK 静态分析')
            if any(j.get('executor') == 'apk_static/v1' and j['status'] in ACTIVE for j in state['jobs']):
                raise RuntimeErrorSafe('已有 APK 分析任务运行，请完成或取消后重试')
            entry = next((p for p in state.get('settings', {}).get('providers', []) if p['enabled']), None)
            if not entry:
                raise RuntimeErrorSafe('请先配置并启用 API Provider')
            entry = copy.deepcopy(entry)
            model = payload.get('model', entry['model'])
            calls, seconds = payload.get('max_calls', 12), payload.get('seconds', 900)
            task = payload.get('task', '')
            if not isinstance(task, str) or len(task) > 8000:
                raise RuntimeErrorSafe('分析目标必须为最多 8000 字符的文本')
            if not isinstance(model, str) or not re.fullmatch(r'[\w.\-:/]{1,120}', model):
                raise RuntimeErrorSafe('无效模型 ID')
            if type(calls) is not int or not 1 <= calls <= 30 or type(seconds) is not int or not 30 <= seconds <= 1800:
                raise RuntimeErrorSafe('调用预算为 1–30 次，分析时间为 30–1800 秒')
            python = ROOT / '.venv-analysis' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
            if not python.exists() or not (ROOT / 'data/tools/jadx-1.5.6/lib/jadx-1.5.6-all.jar').exists():
                raise RuntimeErrorSafe('缺少 APK worker 环境或 JADX，请完成本地安装')
            entry['model'] = model
            job = dict(id='job_' + uuid.uuid4().hex, case_id=sample['case_id'], sample_id=sample['id'],
                       type='android_analysis', executor='apk_static/v1', source='apk_static', status='queued',
                       progress=0, reason='等待静态分析进程启动', created_at=self.now(), model=model,
                       max_calls=calls, seconds=seconds, task=task, sample_executed=False, demo=False)
            output = self.root / job['id']
            output.mkdir()
            snapshot = dict(provider=entry, apk=str(self.root / (sample['sha256'] + '.apk')),
                            sha256=sample['sha256'], vault=str(self.store.path.with_name('credentials.dpapi').resolve()),
                            max_calls=calls, seconds=seconds, task=task)
            (output / 'config.json').write_text(json.dumps(snapshot), encoding='utf-8')
            state['jobs'].insert(0, job)
            self.audit(state, job['case_id'], 'apk.queued', job['id'])
            self.store.save(state)
            thread = threading.Thread(target=self.run, args=(job['id'], python, seconds), daemon=True)
            self.threads.append(thread)
            thread.start()
            return job

    def cancel(self, ident, case_id):
        with self.store.lock:
            state = self.store.load()
            job = next((j for j in state['jobs'] if j['id'] == ident and j['case_id'] == case_id), None)
            if not job or job.get('executor') != 'apk_static/v1':
                return None
            if job['status'] not in ACTIVE:
                raise RuntimeErrorSafe('任务已结束')
            job.update(status='cancelled', reason='用户取消，正在清理静态分析进程', finished_at=self.now())
            self.audit(state, case_id, 'apk.cancelled', ident)
            self.store.save(state)
            return job

    def update(self, ident, **fields):
        with self.store.lock:
            state = self.store.load()
            job = next(j for j in state['jobs'] if j['id'] == ident)
            if job['status'] not in ACTIVE:
                return False
            job.update(fields)
            if fields.get('status') in {'failed', 'needs_review'}:
                self.audit(state, job['case_id'], 'apk.' + fields['status'], ident)
            self.store.save(state)
            return True

    def collect(self, ident):
        output = self.root / ident
        with self.store.lock:
            state = self.store.load()
            job = next(j for j in state['jobs'] if j['id'] == ident)
            if job['status'] not in ACTIVE:
                return
            known = {e['id'] for e in state['evidence']}
            for path in sorted((output / 'evidence').glob('*.json')):
                eid = ident + '_' + path.stem
                if eid in known:
                    continue
                try:
                    record = json.loads(path.read_text(encoding='utf-8'))
                except (ValueError, OSError):
                    continue  # A writer may still be publishing this file.
                state['evidence'].append(dict(id=eid, job_id=ident, case_id=job['case_id'], sample_id=job['sample_id'],
                    source='apk_static', subject=record['action'] + ' · ' + record['id'],
                    claim=json.dumps(record, ensure_ascii=False)[:8000], artifacts=[f'evidence/{path.name}'],
                    status='needs_review', confidence=None, created_at=self.now(), demo=False))
                self.audit(state, job['case_id'], 'apk.evidence', eid)
            job['artifacts'] = sorted(p.relative_to(output).as_posix() for folder in ('evidence', 'derived')
                                      for p in (output / folder).glob('*') if p.suffix in {'.json', '.png'})
            if (output / 'result.json').exists():
                job['artifacts'].append('result.json')
            if (output / 'extraction.json').exists():
                job['artifacts'].append('extraction.json')
            self.store.save(state)

    @staticmethod
    def terminate(process):
        if process.poll() is not None:
            return
        if os.name == 'nt':
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True,
                           creationflags=subprocess.CREATE_NO_WINDOW, timeout=15)
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=15)

    def run(self, ident, python, seconds):
        output = self.root / ident
        process = None
        try:
            if not self.update(ident, status='running', started_at=self.now(), reason='JADX 正在反编译 APK', progress=5):
                return
            with (output / 'worker.log').open('w', encoding='utf-8') as log:
                process = subprocess.Popen([str(python), str(ROOT / 'tools/web_apk_worker.py'), str(output.resolve())],
                    stdout=log, stderr=subprocess.STDOUT, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                    start_new_session=os.name != 'nt')
                deadline = time.monotonic() + seconds + 330
                while process.poll() is None:
                    self.collect(ident)
                    progress = output / 'progress.json'
                    try:
                        info = json.loads(progress.read_text(encoding='utf-8')) if progress.exists() else {}
                    except (ValueError, OSError):
                        info = {}
                    alive = self.update(ident, **info) if info else self.update(ident)
                    if self.closed.is_set() or not alive or time.monotonic() > deadline:
                        self.terminate(process)
                        self.update(ident, status='failed', reason='服务关闭或任务超过总时间预算', finished_at=self.now())
                        return
                    self.closed.wait(1)
            self.collect(ident)
            result_path = output / 'result.json'
            if process.returncode or not result_path.exists():
                failure = output / 'failure.json'
                reason = json.loads(failure.read_text(encoding='utf-8'))['reason'] if failure.exists() else '静态分析进程失败，请检查本地 worker.log'
                self.update(ident, status='failed', reason=reason, finished_at=self.now())
                return
            result = json.loads(result_path.read_text(encoding='utf-8'))
            status = 'needs_review' if result['status'] == 'finished' else 'failed'
            reasons = {'finished':'模型已提交候选结果，需人工复核', 'provider_unavailable':'API 连续失败，未得出答案',
                       'budget_exhausted':'已用完调用或时间预算，未得出答案'}
            self.update(ident, status=status, reason=reasons.get(result['status'], '分析失败'), progress=100,
                        result=result, finished_at=self.now())
        except Exception:
            self.update(ident, status='failed', reason='后台任务异常，请检查静态分析环境', finished_at=self.now())
        finally:
            if process is not None:
                self.terminate(process)
            with self.store.lock:
                state = self.store.load()
                job = next(j for j in state['jobs'] if j['id'] == ident)
                if job['status'] == 'cancelled':
                    job['reason'] = '已取消；静态分析进程已停止，未执行样本'
                    self.store.save(state)

    def close(self):
        self.closed.set()
        for thread in self.threads:
            thread.join(timeout=20)
