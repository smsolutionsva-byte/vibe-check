import json
from pathlib import Path
import tempfile
import unittest

from vibe_check.js_patterns import risk_matches
from vibe_check.secrets import scan


class BenchmarkRegressions(unittest.TestCase):
    def test_js_comments_strings_and_multiline_calls(self):
        text = 'const message = "eval(input)"; // new Function(code)\n/*\neval(input)\n*/\neval\n(input);\nnew\nFunction(code);\n'
        self.assertEqual([(r, n) for r, n, _ in risk_matches(text)], [('js-eval', 5), ('js-new-function', 7)])

    def test_child_process_alias_and_unrelated_exec(self):
        text = 'import {exec as launch} from "node:child_process";\nlaunch(\n "echo " + value\n);\nregex.exec(value + suffix);\n'
        self.assertEqual([(r, n) for r, n, _ in risk_matches(text)], [('js-child-process-concatenation', 2)])

    def test_child_process_constant_command_and_callback_plus(self):
        text = 'const cp = require("child_process");\ncp.exec("echo hello", () => count + 1);\n'
        self.assertEqual(risk_matches(text), [])

    def test_python_literals_ignore_comments_and_support_bytes(self):
        fake = 'ABCD' + 'not-a-real-credential-0123456789'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'app.py').write_text(f'# api_key = "{fake}"\napi_key = (\n b"{fake}"\n)\n', encoding='utf-8')
            self.assertEqual([(f.rule, f.line, f.masked_value) for f in scan(root)], [('hardcoded-credential', 2, 'ABCD****')])

    def test_rust_reference_type_and_js_comment(self):
        fake = 'ABCD' + 'not-a-real-credential-0123456789'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'app.rs').write_text(f'let api_key: &str = "{fake}";', encoding='utf-8')
            (root / 'app.js').write_text(f'// const apiKey = "{fake}";', encoding='utf-8')
            self.assertEqual([(f.path, f.rule) for f in scan(root)], [('app.rs', 'hardcoded-credential')])

    def test_python_attribute_and_subscript_settings(self):
        fake = 'ABCD' + 'not-a-real-credential-0123456789'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'app.py').write_text(f'app.secret_key = "{fake}"\napp.config["SECRET_KEY"] = "{fake}"\n', encoding='utf-8')
            self.assertEqual([(f.rule, f.line) for f in scan(root)], [('hardcoded-credential', 1), ('hardcoded-credential', 2)])

    def test_corpus_counts_and_explicit_labels(self):
        root = Path(__file__).resolve().parents[1]
        cases = json.loads((root / 'benchmark' / 'cases.json').read_text(encoding='utf-8'))
        self.assertEqual(len(cases), 90)
        self.assertEqual({g: sum(c['group'] == g for c in cases) for g in ('positive', 'negative', 'tricky')}, {'positive': 40, 'negative': 40, 'tricky': 10})
        self.assertEqual(sum(c['label'] == 'positive' for c in cases), 47)
        self.assertTrue(all(bool(c['expected']) == (c['label'] == 'positive') for c in cases))
