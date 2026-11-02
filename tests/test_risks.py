import tempfile
import unittest
from pathlib import Path
from vibe_check.risks import scan


class RiskTests(unittest.TestCase):
    def test_javascript_typescript_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'app.ts').write_text("import { exec } from 'node:child_process';\neval(code);\nnew Function(code);\nexec('ls ' + input);\n// eval(ignored)\n", encoding='utf-8')
            results = scan(root)
            self.assertEqual([(f.rule, f.line, f.severity) for f in results], [('js-eval', 2, 'medium'), ('js-new-function', 3, 'medium'), ('js-child-process-concatenation', 4, 'medium')])

    def test_evidence_and_missing_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'app.py').write_text('import subprocess\neval(user_input)\nsubprocess.run(cmd, shell=True)\n', encoding='utf-8')
            found = scan(root)
            self.assertEqual([(f.rule, f.line) for f in found], [('dynamic-code-execution', 2), ('subprocess-shell-true', 3), ('no-python-test-files-found', 1)])
            (root / 'test_app.py').write_text('def test_example(): pass\n', encoding='utf-8')
            self.assertNotIn('no-python-test-files-found', [f.rule for f in scan(root)])

    def test_string_and_safe_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'test_safe.py').write_text('message = "eval(x)"\nsubprocess.run(["echo", "ok"], shell=False)\n', encoding='utf-8')
            self.assertEqual(scan(root), [])
