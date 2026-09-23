import unittest

from tools.benchmark_challenges import score_result


class BenchmarkScoringTests(unittest.TestCase):
    def score(self, flag, evidence):
        observation = {'file':'sample.bin', 'offset':'0x10', 'text':'candidate@example.test'}
        return score_result({'nonce':'test', 'parsed':{'nonce':'test', 'flag':flag,
            'evidence':evidence, 'limitations':[]}}, [observation], observation['text'])

    def test_grounded_answer(self):
        self.assertTrue(self.score('candidate@example.test', [{'file':'sample.bin', 'offset':'0x10',
            'text':'candidate@example.test'}])['grounded_flag_pass'])

    def test_correct_answer_with_fabricated_offset_fails(self):
        self.assertFalse(self.score('candidate@example.test', [{'file':'sample.bin', 'offset':'0x11',
            'text':'candidate@example.test'}])['grounded_flag_pass'])

    def test_correct_answer_without_evidence_fails(self):
        self.assertFalse(self.score('candidate@example.test', [])['grounded_flag_pass'])

    def test_abstention_does_not_count_as_solution(self):
        result = self.score(None, [])
        self.assertTrue(result['abstained'])
        self.assertTrue(result['citations_supported'])
        self.assertFalse(result['grounded_flag_pass'])
