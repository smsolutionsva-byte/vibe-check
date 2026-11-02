import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from vibe_check.cli import main


class CliTests(unittest.TestCase):
    def test_verdicts_and_exits(self):
        for content, verdict, code in [('x = 1\n', 'SHIP', 0), ('eval(x)\n', 'REVIEW', 1), ('api_key = "abcd123456789"\n', 'FIX FIRST', 1)]:
            with self.subTest(verdict=verdict), tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / 'app.py').write_text(content, encoding='utf-8')
                output = io.StringIO()
                with patch('sys.argv', ['vibe-check', tmp]), contextlib.redirect_stdout(output):
                    self.assertEqual(main(), code)
                self.assertIn(verdict, output.getvalue())
