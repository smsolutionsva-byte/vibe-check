"""Development regressions from public findings and requested rule semantics.

These tests do not load the held-out cases or their evaluation result.
"""
import ast
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vibe_check.python_patterns import risk_matches
from vibe_check.secrets import scan


class PrecisionPassTests(unittest.TestCase):
    def test_nodegoat_error_messages_are_not_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = 'ABCD' + 'not-a-real-credential-0123456789'
            (root / 'app.js').write_text('const invalidPasswordErrorMessage = "Invalid password";\nerrors.passwordError = "Password must be long enough";\n' + f'const service_api_key = "{fake}";\n', encoding='utf-8')
            self.assertEqual([(f.rule, f.line) for f in scan(root)], [('hardcoded-credential', 3)])

    def test_python_ui_suffix_filter_preserves_real_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = 'ABCD' + 'not-a-real-credential-0123456789'
            (root / 'app.py').write_text('password_error = "Invalid password"\n' + f'password = "{fake}"\n', encoding='utf-8')
            self.assertEqual([(f.rule, f.line) for f in scan(root)], [('hardcoded-credential', 2)])

    def test_pygoat_sql_tutorial_text_not_generic_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = 'ABCD' + 'not-a-real-credential-0123456789'
            for name in ['lesson.html', 'notes.md', 'guide.rst', 'example.txt']:
                (root / name).write_text(f'<pre>SELECT * FROM users WHERE password=\'{fake}\'</pre>', encoding='utf-8')
            self.assertEqual(scan(root), [])

    def test_documentation_still_scanned_for_provider_tokens_and_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = 'gh' + 'p_' + 'Z' * 36
            header = '-----BEGIN ' + 'PRIVATE KEY-----'
            (root / 'guide.md').write_text(provider + '\n' + header + '\nNOTREAL\n-----END PRIVATE KEY-----', encoding='utf-8')
            self.assertEqual([f.rule for f in scan(root)], ['github-token', 'private-key-block'])

    def test_subprocess_aliases_and_reassignment(self):
        tree = ast.parse('import subprocess as sp\nfrom subprocess import run as start\nsp.run(command, shell=True)\nstart(command, shell=True)\nsp = other\nsp.run(command, shell=True)\n')
        self.assertEqual([(r, n) for r, n, _ in risk_matches(tree)], [('subprocess-shell-true', 3), ('subprocess-shell-true', 4)])

    def test_function_scopes_and_safe_shell_argument(self):
        tree = ast.parse('import subprocess as sp\ndef f(sp):\n    sp.run(command, shell=True)\ndef g():\n    from subprocess import call as invoke\n    invoke(command, shell=True)\nsp.run(command, shell=False)\n')
        self.assertEqual([(r, n) for r, n, _ in risk_matches(tree)], [('subprocess-shell-true', 6)])

    def test_possible_sql_string_building_is_medium_review_evidence(self):
        tree = ast.parse('cursor.execute(f"SELECT {column}")\ncur.execute("SELECT " + column)\nhandle = db.cursor()\nhandle.execute(f"SELECT {column}")\n')
        matches = risk_matches(tree)
        self.assertEqual([(r, n) for r, n, _ in matches], [('possible-sql-string-building', 1), ('possible-sql-string-building', 2), ('possible-sql-string-building', 4)])
        self.assertTrue(all(e.startswith('possible SQL string building:') for _, _, e in matches))
        from vibe_check.risks import scan as scan_risks
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'test_sql.py').write_text('cursor.execute(f"SELECT {column}")', encoding='utf-8')
            self.assertEqual(scan_risks(root)[0].severity, 'medium')

    def test_parameterized_indirect_and_unrelated_execute_not_flagged(self):
        tree = ast.parse('cursor.execute("SELECT value FROM data WHERE id = ?", (item,))\ncursor.execute(query)\nworker.execute(f"job {number}")\ncursor.execute("SELECT 1")\n')
        self.assertEqual(risk_matches(tree), [])

    def test_sql_review_verdict_and_report(self):
        from vibe_check.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'test_query.py').write_text('cursor.execute(f"SELECT {column}")', encoding='utf-8')
            report = root / 'report.md'
            output = io.StringIO()
            with patch('sys.argv', ['vibe-check', str(root), '--report', str(report)]), contextlib.redirect_stdout(output):
                self.assertEqual(main(), 1)
            self.assertIn('MEDIUM', output.getvalue())
            self.assertIn('possible SQL string building', output.getvalue())
            self.assertIn('REVIEW', output.getvalue())
            self.assertNotIn('FIX FIRST', output.getvalue())
            self.assertIn('possible SQL string building', report.read_text(encoding='utf-8'))
