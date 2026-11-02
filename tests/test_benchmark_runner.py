import json
from pathlib import Path
import unittest

from benchmark.run import ratios


class BenchmarkRunnerTests(unittest.TestCase):
    def test_metric_definitions_and_frozen_labels(self):
        self.assertEqual(ratios(dict(TP=2, FP=1, TN=4, FN=2))['precision'], 2 / 3)
        self.assertEqual(ratios(dict(TP=2, FP=1, TN=4, FN=2))['recall'], .5)
        root = Path(__file__).resolve().parents[1] / 'benchmark'
        cases = json.loads((root / 'cases.json').read_text(encoding='utf-8'))
        baseline = json.loads((root / 'results/baseline.json').read_text(encoding='utf-8'))
        final = json.loads((root / 'results/final.json').read_text(encoding='utf-8'))
        self.assertEqual(baseline['dataset_sha256'], final['dataset_sha256'])
        for case, recorded in zip(cases, baseline['cases']):
            self.assertEqual((case['id'], case['label'], case['group']), (recorded['id'], recorded['label'], recorded['group']))
            self.assertEqual([[e['rule'], e['line']] for e in case['expected']], recorded['expected'])
