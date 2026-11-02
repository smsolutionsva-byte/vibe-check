import unittest
from vibe_check.report import render
from vibe_check.secrets import Finding


class ReportTests(unittest.TestCase):
    def test_redacted_and_verdict(self):
        report = render([Finding('hardcoded-credential', 'app.py', 2, 'abcd****')])
        self.assertIn('FIX FIRST', report)
        self.assertIn('abcd****', report)
        self.assertNotIn('abcd9876543210', report)

    def test_access_message(self):
        report = render([Finding('js-eval', 'a.js', 3, 'eval(...)', 'medium')], [None], True)
        self.assertIn('AI explanations unavailable: BharatCode access required.', report)
        self.assertIn('REVIEW', report)
