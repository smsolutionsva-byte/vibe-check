import io
import json
import unittest
from vibe_check.ai import explain
from vibe_check.secrets import Finding


class ApiTests(unittest.TestCase):
    def test_payload_contains_no_source_or_credential(self):
        finding = Finding('hardcoded-credential', 'path.py', 1, 'abcd****')
        def fake_open(req, timeout):
            body = json.loads(req.data)
            self.assertNotIn('abcd', json.dumps(body))
            self.assertNotIn('path.py', json.dumps(body))
            self.assertEqual(body['model'], 'qwen-3.8-27b')
            return io.BytesIO(b'{"choices":[{"message":{"content":"Check the credential."}}]}')
        self.assertEqual(explain(finding, 'FAKE_KEY', fake_open), 'Check the credential.')

    def test_failure_falls_back(self):
        def fail(req, timeout):
            raise OSError('offline')
        self.assertIsNone(explain(Finding('js-eval', 'x.js', 1, 'eval(...)', 'medium'), 'FAKE_KEY', fail))
