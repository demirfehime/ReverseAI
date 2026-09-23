import json
from pathlib import Path
import tempfile
import unittest

from apk_analysis import Corpus, Investigator, recipe, sha, model_evidence
from provider_runtime import RuntimeErrorSafe


class StaticAPKTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)/'corpus';self.out=Path(self.temp.name)/'run'
        (self.root/'resources/res/values').mkdir(parents=True)
        (self.root/'resources/res/raw').mkdir()
        (self.root/'sources/example').mkdir(parents=True)
        (self.root/'resources/AndroidManifest.xml').write_text('<manifest package="example"/>')
        (self.root/'resources/res/values/strings.xml').write_text(
            '<resources><string name="seed">abc</string><string name="key">0123456789abcdef</string>'
            '<string name="iv">fedcba9876543210</string></resources>')
        (self.root/'sources/example/Main.java').write_text('class Main {\n// AES/CBC and resource references\n}')
        self.corpus=Corpus(self.root,self.out)

    def tearDown(self): self.temp.cleanup()

    def test_analysis_goal_is_generic_or_explicit(self):
        captured = []
        class Provider:
            config = {'model': 'fixture', 'timeout_seconds': 3}
            def complete(self, prompt, *args, **kwargs):
                captured.append(json.loads(prompt)['task'])
                return json.dumps({'action':'finish','arguments':{'flag':None,'evidence_ids':[],'reasoning':'fixture'}})
        Investigator(self.corpus, Provider(), max_calls=1).run()
        self.assertNotIn('@flare-on.com', captured[-1])
        Investigator(self.corpus, Provider(), max_calls=1, task='Explain login validation').run()
        self.assertEqual(captured[-1], 'Explain login validation')

    def test_lookup_and_path_boundary(self):
        hit=self.corpus.dispatch('search',{'query':'AES/CBC'})
        self.assertEqual(hit['result']['hits'][0]['path'],'sources/example/Main.java')
        self.assertEqual(self.corpus.resource(['seed'])['values']['seed'],'abc')
        self.assertEqual(len(self.corpus.read('sources/example/Main.java',count=300)['lines']),3)
        for path in ['../secret.txt','C:/Windows/win.ini','sources/../../secret.txt']:
            with self.assertRaises(ValueError): self.corpus.read(path)
        with self.assertRaises(ValueError): self.corpus.dispatch('shell',{'command':'echo unsafe'})

    def test_replayable_key_derivation(self):
        data,trace=recipe(self.corpus,[{'id':'s','op':'resource','name':'seed'},
            {'id':'c','op':'crc32_decimal','input':'s'}, {'id':'r','op':'repeat','input':'c','count':2}])
        self.assertEqual(data,b'891568578891568578')
        self.assertEqual(trace['output_sha256'],sha(data))
        self.assertIn('resources/res/values/strings.xml',trace['sources'])

    def test_invalid_recipe_is_not_executed(self):
        cases=[[{'id':'x','op':'python','code':'raise Exception()'}],
               [{'id':'x','op':'slice','input':'missing','start':0,'end':1}],
               [{'id':'x','op':'resource','name':'seed'},{'id':'y','op':'repeat','input':'x','count':100000000}]]
        for steps in cases:
            with self.assertRaises(ValueError):recipe(self.corpus,steps)

    def test_derived_answer_can_pass_without_original_plaintext(self):
        try:
            from Cryptodome.Cipher import AES
            from Cryptodome.Util.Padding import pad
        except ImportError:
            self.skipTest('Run in .venv-analysis for AES verification')
        plaintext=b'\x89PNG\r\n\x1a\nsynthetic image fixture'
        encrypted=AES.new(b'0123456789abcdef',AES.MODE_CBC,b'fedcba9876543210').encrypt(pad(plaintext,16))
        path=self.root/'resources/res/raw/payload.bin';path.write_bytes(encrypted)
        read=self.corpus.dispatch('read',{'path':'sources/example/Main.java'})
        steps=[{'id':'k','op':'resource','name':'key'},{'id':'v','op':'resource','name':'iv'},
               {'id':'d','op':'aes_cbc_decrypt','path':'resources/res/raw/payload.bin','key':'k','iv':'v'}]
        investigator=Investigator(self.corpus,None,ocr=lambda _: {'text':'new_answer@example.test','engine':'test-fixture'})
        computed=investigator.compute({'steps':steps,'evidence_ids':[read['id']]})
        final={'flag':'new_answer@example.test','evidence_ids':[computed['id']]}
        self.assertTrue(investigator.verify(final)['candidate_in_derived_ocr'])
        self.assertTrue(investigator.verify(final)['derivation_replayed'])
        self.assertFalse(investigator.verify({'flag':'invented','evidence_ids':[computed['id']]})['candidate_in_derived_ocr'])
        code=self.root/'sources/example/Main.java';original=code.read_text()
        code.write_text('modified code')
        self.assertFalse(investigator.verify(final)['derivation_replayed'])
        code.write_text(original)
        path.write_bytes(encrypted[:-16]+bytes(16))
        self.assertFalse(investigator.verify(final)['derivation_replayed'])

    def test_unknown_evidence_cannot_verify_an_answer(self):
        result=Investigator(self.corpus,None).verify({'flag':'answer','evidence_ids':['e9999']})
        self.assertFalse(result['derivation_replayed'])

    def test_model_loop_is_bounded_and_records_actions(self):
        class Provider:
            config={'model':'fixture','timeout_seconds':1}
            def complete(self,*args,**kwargs):
                return json.dumps({'action':'shell','arguments':{'command':'not allowed'}})
        result=Investigator(self.corpus,Provider(),max_calls=2).run()
        self.assertEqual(result['status'],'budget_exhausted')
        self.assertEqual(len(result['attempts']),2)
        self.assertTrue(all('error' in x for x in result['attempts']))

    def test_provider_failures_stop_after_three_attempts(self):
        class Provider:
            config={'model':'fixture','timeout_seconds':1}
            def complete(self,*args,**kwargs): raise RuntimeErrorSafe('offline')
        result=Investigator(self.corpus,Provider(),max_calls=8).run()
        self.assertEqual(result['status'],'provider_unavailable')
        self.assertEqual(len(result['attempts']),3)

    def test_complete_investigation_replays_derived_output(self):
        try:
            from Cryptodome.Cipher import AES
            from Cryptodome.Util.Padding import pad
        except ImportError:
            self.skipTest('Run in .venv-analysis for AES verification')
        plaintext=b'\x89PNG\r\n\x1a\nsynthetic orchestration fixture'
        (self.root/'resources/res/raw/payload.bin').write_bytes(
            AES.new(b'0123456789abcdef',AES.MODE_CBC,b'fedcba9876543210').encrypt(pad(plaintext,16)))
        actions=iter([
            {'action':'read','arguments':{'path':'sources/example/Main.java'}},
            {'action':'compute','arguments':{'evidence_ids':['e0004'],'steps':[
                {'id':'k','op':'resource','name':'key'}, {'id':'v','op':'resource','name':'iv'},
                {'id':'d','op':'aes_cbc_decrypt','path':'resources/res/raw/payload.bin','key':'k','iv':'v'}]}},
            {'action':'finish','arguments':{'flag':'derived@example.test','evidence_ids':['e0005']}}])
        class Provider:
            config={'model':'fixture','timeout_seconds':1}
            def complete(self,*args,**kwargs): return json.dumps(next(actions))
        result=Investigator(self.corpus,Provider(),max_calls=3,
            ocr=lambda _: {'text':'derived@example.test','engine':'fixture'}).run()
        self.assertEqual(result['status'],'finished')
        self.assertTrue(result['verification']['derivation_replayed'])
        self.assertTrue(result['verification']['candidate_in_derived_ocr'])
        self.assertEqual(len(result['attempts']),3)

    def test_prompt_boilerplate_filter_preserves_original_evidence(self):
        (self.root/'sources/example/Main.java').write_text('import x.Y;\nclass Main {}')
        record=self.corpus.dispatch('read',{'path':'sources/example/Main.java'})
        view=model_evidence([record])
        self.assertEqual(len(record['result']['lines']),2)
        self.assertEqual(len(view[0]['result']['lines']),1)
        self.assertEqual(view[0]['result']['lines'][0]['line'],2)
        self.assertEqual(view[0]['result']['sha256'],record['result']['sha256'])
