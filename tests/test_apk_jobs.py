"""Web APK boundary, worker lifecycle and evidence isolation regressions."""
import io
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from integrations import defaults
from provider_runtime import RuntimeErrorSafe
from server import create_server, audit_valid


class APKJobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = create_server(port=0, data_path=Path(self.temp.name) / 'state.json')
        self.server.quiet = True
        self.manager = self.server.apk_jobs
        with self.server.store.lock:
            state = self.server.store.load()
            self.case = state['cases'][0]['id']
            config = defaults()
            config['providers'] = [dict(id='fixture', enabled=True, model='fixture-model',
                protocol='responses', base_url='http://127.0.0.1:9', credential_env='', timeout_seconds=1)]
            state['settings'] = config
            self.server.store.save(state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server.runtime.pool.shutdown(wait=True)
        self.thread.join(2)
        self.temp.cleanup()

    def apk(self, extra=None):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('AndroidManifest.xml', b'fixture manifest')
            archive.writestr('classes.dex', b'fixture dex; never executed')
            if extra:
                archive.writestr(extra, 'fixture')
        return buffer.getvalue()

    def upload(self):
        raw = self.apk()
        return self.manager.upload(io.BytesIO(raw), len(raw), self.case, 'fixture.apk')['sample']

    def job(self, ident):
        return next(j for j in self.server.store.load()['jobs'] if j['id'] == ident)

    def wait_done(self, ident):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            job = self.job(ident)
            if job['status'] not in {'queued', 'running'}:
                return job
            time.sleep(.05)
        self.fail('Worker did not settle')

    def fixture_launcher(self, delay=0):
        real = subprocess.Popen
        def launch(command, **kwargs):
            if len(command) < 2 or not command[1].endswith('web_apk_worker.py'):
                return real(command, **kwargs)
            output = command[-1]
            program = '''import json,sys,time
from pathlib import Path
p=Path(sys.argv[1]);(p/'evidence').mkdir()
(p/'evidence/e0001.json').write_text(json.dumps({'id':'e0001','action':'read','result':{'path':'sources/Fixture.java'},'arguments':{}}))
time.sleep(float(sys.argv[2]))
(p/'result.json').write_text(json.dumps({'status':'finished','attempts':[{'call':1,'action':'finish'}],'verification':{'candidate':'fixture-answer','derivation_replayed':False},'sample_executed':False}))
'''
            return real([command[0], '-c', program, output, str(delay)], **kwargs)
        return launch

    def test_upload_checks_archive_hash_and_upgrades_duplicate(self):
        first = self.upload()
        second = self.upload()
        self.assertEqual(first['id'], second['id'])
        self.assertEqual(second['hash_source'], 'server-upload')
        self.assertTrue((self.manager.root / (second['sha256'] + '.apk')).is_file())
        for data in (b'not apk', self.apk('../escape')):
            with self.assertRaises(RuntimeErrorSafe):
                self.manager.upload(io.BytesIO(data), len(data), self.case, 'bad.apk')
        self.assertFalse(list(self.manager.root.glob('*.upload')))

    def test_http_upload_requires_token_and_artifact_case(self):
        raw = self.apk()
        url = self.base + '/api/samples/apk?' + urllib.parse.urlencode(dict(case_id=self.case, name='fixture.apk'))
        request = urllib.request.Request(url, data=raw, headers={'Content-Type':'application/vnd.android.package-archive'})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request)
        self.assertEqual(caught.exception.code, 403)
        request.add_header('X-ReverseAI-Token', self.server.csrf_token)
        with urllib.request.urlopen(request) as response:
            sample = json.load(response)['sample']
        with patch('apk_jobs.subprocess.Popen', side_effect=self.fixture_launcher()):
            job = self.manager.start(dict(case_id=self.case, sample_id=sample['id'], max_calls=1, seconds=30))
            finished = self.wait_done(job['id'])
        self.assertEqual(finished['status'], 'needs_review')
        prefix = self.base + '/api/apk/jobs/' + job['id'] + '/artifact?'
        with urllib.request.urlopen(prefix + urllib.parse.urlencode(dict(case_id=self.case, name='result.json'))) as response:
            self.assertEqual(json.load(response)['verification']['candidate'], 'fixture-answer')
        for case_id, name, expected in [('other', 'result.json',409), (self.case,'config.json',404), (self.case,'../config.json',404)]:
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(prefix + urllib.parse.urlencode(dict(case_id=case_id, name=name)))
            self.assertEqual(caught.exception.code, expected)
        evidence = self.server.store.load()['evidence']
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]['job_id'], job['id'])
        self.assertEqual(evidence[0]['status'], 'needs_review')
        self.assertTrue(audit_valid(self.server.store.load()['audit']))

    def test_cancel_stops_process_and_discards_late_results(self):
        sample = self.upload()
        with patch('apk_jobs.subprocess.Popen', side_effect=self.fixture_launcher(30)):
            job = self.manager.start(dict(case_id=self.case, sample_id=sample['id']))
            deadline = time.monotonic() + 5
            while not (self.manager.root / job['id'] / 'evidence/e0001.json').exists() and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertIsNone(self.manager.cancel(job['id'], 'other'))
            self.assertEqual(self.job(job['id'])['status'], 'running')
            self.manager.cancel(job['id'], self.case)
            for worker in self.manager.threads:
                worker.join(5)
                self.assertFalse(worker.is_alive())
        self.assertEqual(self.job(job['id'])['status'], 'cancelled')
        self.assertNotIn('result', self.job(job['id']))
        self.assertFalse((self.manager.root / job['id'] / 'result.json').exists())

    def test_job_validates_sample_budget_and_single_active_task(self):
        sample = self.upload()
        valid = dict(case_id=self.case, sample_id=sample['id'])
        for invalid in (dict(case_id='other'), dict(max_calls=True), dict(seconds=0), dict(model='../bad model')):
            with self.assertRaises(RuntimeErrorSafe):
                self.manager.start({**valid, **invalid})
        with patch.object(self.manager, 'run'):
            job = self.manager.start(valid)
            with self.assertRaises(RuntimeErrorSafe):
                self.manager.start(valid)
        self.manager.cancel(job['id'], self.case)
