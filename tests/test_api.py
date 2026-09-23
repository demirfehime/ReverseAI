#!/usr/bin/env python3
"""Focused security regression tests for the local metadata-only API."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from adapters import AdapterNotConfigured, NullAdapter
from server import audit_valid, create_server, validate_config, digest


class ApiSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.server = create_server(port=0, data_path=Path(self.tempdir.name) / "state.json")
        self.server.quiet = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.token = self.get("/api/health")["csrf_token"]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tempdir.cleanup()

    def request(self, path, method="GET", payload=None, token=None, host=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["X-ReverseAI-Token"] = token
        if host is not None:
            headers["Host"] = host
        request = urllib.request.Request(self.base + path, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()

    def get(self, path):
        status, _, body = self.request(path)
        self.assertEqual(status, 200, body)
        return json.loads(body.decode("utf-8"))

    def post(self, path, payload, token=None, host=None):
        status, headers, body = self.request(path, "POST", payload, token, host)
        parsed = json.loads(body.decode("utf-8")) if body else {}
        return status, headers, parsed

    def case_id(self):
        return self.get("/api/cases")["items"][0]["id"]

    def register_sample(self, case_id, sha="a" * 64):
        status, _, body = self.post("/api/samples", {
            "case_id": case_id,
            "name": "security-metadata.exe",
            "size": 0,
            "mime": "application/octet-stream",
            "sha256": sha,
            "kind": "PE 64-bit",
        }, self.token)
        self.assertEqual(status, 201, body)
        return body["sample"]["id"]

    def test_settings_persist_conflicts_and_fail_closed(self):
        from server import Store
        config = self.get('/api/settings')['config']
        config['playbooks'] = [{'id': 'test', 'name': '人工流程', 'steps': ['复核记录'], 'skill_ids': []}]
        status, _, result = self.post('/api/settings', {'config': config, 'revision': 0}, self.token)
        self.assertEqual(status, 201, result)
        self.assertEqual(Store(self.server.store.path).load()['settings'], config)
        self.assertTrue(audit_valid(self.server.store.load()['audit']))
        self.assertEqual(self.post('/api/settings', {'config': config, 'revision': 0}, self.token)[0], 409)
        config['workers'][0]['enabled'] = True
        self.assertEqual(self.post('/api/settings', {'config': config, 'revision': 1}, self.token)[0], 400)
        self.assertEqual(self.get('/api/settings')['revision'], 1)
        for endpoint in ('/api/providers/test', '/api/providers/models', '/api/mcp/test', '/api/agents/run'):
            self.assertEqual(self.post(endpoint, {}, self.token)[0], 400)

    def test_settings_reject_secret_fields_and_bad_references(self):
        config = self.get('/api/settings')['config']
        config['api_key'] = 'must-not-be-saved'
        self.assertEqual(self.post('/api/settings', {'config': config, 'revision': 0}, self.token)[0], 400)
        del config['api_key']
        config['mcp'][0]['url'] = 'https://user:secret@example.com'
        self.assertEqual(self.post('/api/settings', {'config': config, 'revision': 0}, self.token)[0], 400)
        config['mcp'][0]['url'] = ''
        config['playbooks'] = [{'id': 'test', 'name': 'test', 'steps': ['read'], 'skill_ids': ['missing']}]
        self.assertEqual(self.post('/api/settings', {'config': config, 'revision': 0}, self.token)[0], 400)
        self.assertNotIn('must-not-be-saved', self.server.store.path.read_text(encoding='utf-8'))

    def test_null_adapter_is_fail_closed(self):
        adapter = NullAdapter("test", "not configured")
        with self.assertRaises(AdapterNotConfigured):
            adapter.inspect({})
        with self.assertRaises(AdapterNotConfigured):
            adapter.annotate({})

    def test_toolchain_uses_uniform_registry_statuses(self):
        items = self.get("/api/toolchain/health")["items"]
        self.assertEqual(set(items), {"ghidra_mcp", "frida", "llm", "sandbox"})
        for status in items.values():
            self.assertEqual(set(status), {"name", "version", "status", "capabilities", "reason"})
            self.assertEqual(status["version"], "contract-v1")
            self.assertEqual(status["status"], "not_configured")

    def test_post_requires_token(self):
        status, _, body = self.post("/api/cases", {"name": "unauthorized", "authorization": "no"})
        self.assertEqual(status, 403, body)

    def test_non_loopback_host_is_rejected(self):
        status, _, body = self.request("/api/health", host="evil.example")
        self.assertEqual(status, 403, body)

    def test_invalid_sha256_is_rejected(self):
        status, _, body = self.post("/api/samples", {
            "case_id": self.case_id(), "name": "bad.exe", "size": 0,
            "mime": "application/octet-stream", "sha256": "not-a-hash", "kind": "PE",
        }, self.token)
        self.assertEqual(status, 400, body)

    def test_cross_case_sample_is_rejected(self):
        first = self.case_id()
        status, _, second_case = self.post("/api/cases", {"name": "second", "authorization": "test"}, self.token)
        self.assertEqual(status, 201, second_case)
        second = second_case["id"]
        sample_id = self.register_sample(first)
        status, _, body = self.post("/api/analysis/jobs", {
            "case_id": second, "sample_id": sample_id, "type": "metadata_check",
        }, self.token)
        self.assertEqual(status, 409, body)

    def test_invalid_job_type_is_rejected(self):
        case = self.case_id()
        sample = self.register_sample(case)
        status, _, body = self.post("/api/analysis/jobs", {
            "case_id": case, "sample_id": sample, "type": "execute_binary",
        }, self.token)
        self.assertEqual(status, 400, body)

    def test_evidence_review_requires_note_and_writes_audit(self):
        case = self.case_id()
        sample = self.register_sample(case)
        status, _, evidence = self.post('/api/evidence', {
            'case_id': case,
            'sample_id': sample,
            'subject': 'sub_test',
            'claim': '人工记录，等待复核',
            'artifacts': ['manual://observation'],
        }, self.token)
        self.assertEqual(status, 201, evidence)

        status, _, body = self.post(f"/api/evidence/{evidence['id']}/review", {
            'case_id': case, 'status': 'accepted', 'note': '',
        }, self.token)
        self.assertEqual(status, 400, body)

        status, _, reviewed = self.post(f"/api/evidence/{evidence['id']}/review", {
            'case_id': case, 'status': 'accepted', 'note': '已由授权分析员复核',
        }, self.token)
        self.assertEqual(status, 201, reviewed)
        self.assertEqual(reviewed['status'], 'accepted')
        self.assertEqual(reviewed['review_note'], '已由授权分析员复核')
        audit = self.get('/api/audit')
        self.assertTrue(audit['chain_valid'])
        self.assertTrue(any(item['action'] == 'evidence.accepted' for item in audit['items']))

    def test_report_download_supports_all_formats_and_hides_snapshot_in_listing(self):
        case = self.case_id()
        for format_name in ('json', 'html', 'md'):
            status, _, report = self.post('/api/reports', {
                'case_id': case, 'format': format_name,
            }, self.token)
            self.assertEqual(status, 201, report)
            self.assertNotIn('snapshot', report)

            status, headers, body = self.request(f"/api/reports/{report['id']}/download")
            self.assertEqual(status, 200)
            self.assertIn(f'filename="{report["id"]}.{format_name}"', headers.get('Content-Disposition', ''))
            if format_name == 'json':
                bundle = json.loads(body.decode('utf-8'))
                self.assertEqual(bundle['sha256'], report['sha256'])
                self.assertEqual(bundle['snapshot']['schema'], 'reverseai-evidence/v1')
            elif format_name == 'html':
                self.assertIn('<!doctype html>', body.decode('utf-8'))
                self.assertIn('元数据报告', body.decode('utf-8'))
            else:
                self.assertTrue(body.decode('utf-8').startswith('# ReverseAI 证据快照'))

        listed = self.get('/api/reports')['items']
        self.assertTrue(listed)
        self.assertTrue(all('snapshot' not in item for item in listed))
    def test_audit_chain_stays_valid(self):
        case = self.case_id()
        self.register_sample(case)
        audit = self.get("/api/audit")
        self.assertTrue(audit["chain_valid"])
        self.assertTrue(audit_valid(audit["items"]))

    def test_report_is_frozen_and_detects_tampering(self):
        case = self.case_id()
        status, _, report = self.post('/api/reports', {'case_id': case}, self.token)
        self.assertEqual(status, 201)
        self.register_sample(case)
        path = f"/api/reports/{report['id']}/download"
        bundle = self.get(path)
        self.assertEqual(digest(bundle['snapshot']), report['sha256'])
        self.assertEqual(bundle['snapshot']['samples'], [])
        with self.server.store.lock:
            state = self.server.store.load()
            state['reports'][0]['snapshot']['scope'] = 'tampered'
            self.server.store.save(state)
        self.assertEqual(self.request(path)[0], 409)

    def test_static_files_do_not_expose_state_or_source(self):
        for path in ('/data/state.json', '/server.py', '/config.example.json', '/../server.py'):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)


class ConfigValidationTests(unittest.TestCase):
    def test_malformed_policy_and_host_are_rejected_cleanly(self):
        for patch in ({'write_policy': None}, {'write_policy': []}, {'host': []}):
            config = {'mode': 'metadata-only', 'write_policy': {'default': 'proposal_only'}, 'adapters': {}}
            config.update(patch)
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                validate_config(config)

    def write_config(self, value):
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False)
        with handle:
            json.dump(value, handle)
        return handle.name

    def test_invalid_mode_and_write_policy_are_rejected(self):
        for patch in ({"mode": "live"}, {"write_policy": {"default": "apply"}}):
            config = {"mode": "metadata-only", "write_policy": {"default": "proposal_only"}, "adapters": {}}
            config.update(patch)
            path = self.write_config(config)
            try:
                with self.assertRaises(ValueError):
                    create_server(port=0, config_path=path, data_path=Path(path).with_suffix(".state"))
            finally:
                Path(path).unlink(missing_ok=True)

    def test_enabled_adapter_requires_security_fields_and_worker(self):
        config = {"adapters": {"ghidra_mcp": {"enabled": True}}}
        path = self.write_config(config)
        try:
            with self.assertRaises(ValueError):
                create_server(port=0, config_path=path, data_path=Path(path).with_suffix(".state"))
        finally:
            Path(path).unlink(missing_ok=True)

    def test_even_complete_adapter_is_rejected_until_worker_exists(self):
        config = {"adapters": {"frida": {
            "enabled": True, "worker": "frida-worker:v1", "allowlist": ["trace"],
            "isolation": {"network": "disabled"},
        }}}
        path = self.write_config(config)
        try:
            with self.assertRaises(ValueError):
                create_server(port=0, config_path=path, data_path=Path(path).with_suffix(".state"))
        finally:
            Path(path).unlink(missing_ok=True)

    def test_non_loopback_bind_is_rejected(self):
        with self.assertRaises(ValueError):
            create_server(host="0.0.0.0", port=0, data_path=Path(tempfile.mkdtemp()) / "state.json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
