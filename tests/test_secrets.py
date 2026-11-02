import tempfile
import unittest
from pathlib import Path

from vibe_check.secrets import mask, scan


class SecretTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, filename, value):
        path = self.root / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding='utf-8')

    def test_tokens_and_private_keys(self):
        aws = 'AK' + 'IA' + 'Z' * 16
        github = 'gh' + 'p_' + 'Z' * 36
        self.write('secrets.txt', f'{aws}\n{github}\n-----BEGIN PRIVATE KEY-----\nNOTREAL\n-----END PRIVATE KEY-----\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nNOTREAL\n-----END PGP PRIVATE KEY BLOCK-----\n')
        findings = scan(self.root)
        self.assertEqual([f.rule for f in findings], ['aws-access-key', 'github-token', 'private-key-block', 'private-key-block'])
        self.assertEqual([f.line for f in findings], [1, 2, 3, 6])
        self.assertNotIn(aws, repr(findings))
        self.assertNotIn(github, repr(findings))

    def test_assignments_languages_and_env(self):
        data = {'a.py': 'api_key = "abcdef123456"', 'a.js': 'const apiKey = "abcdef123456";', 'a.ts': 'const apiKey: string = "abcdef123456";', 'a.go': 'apiKey := "abcdef123456"', 'a.php': '$api_key = "abcdef123456";', 'a.rb': 'api_key = "abcdef123456"', 'a.rs': 'let api_key = "abcdef123456";', '.env': 'API_KEY=abcdef123456'}
        for filename, value in data.items(): self.write(filename, value)
        findings = scan(self.root)
        self.assertEqual(len(findings), len(data))
        self.assertEqual({f.path for f in findings}, set(data))
        self.assertTrue(all(f.masked_value == 'abcd****' for f in findings))

    def test_placeholder_and_environment_reads(self):
        self.write('a.py', 'api_key = "your_api_key"\napi_key = os.environ.get("API_KEY")\napi_key = "<YOUR_API_KEY>"\n')
        self.write('.env.example', 'API_KEY=your_api_key\n')
        self.assertEqual(scan(self.root), [])

    def test_skipped_dirs_lockfiles_and_binary(self):
        for folder in ['.git', 'node_modules', '.venv', 'venv', 'build', 'dist', 'target']:
            self.write(folder + '/a.py', 'api_key = "abcdef123456"')
        self.write('package-lock.json', 'api_key = "abcdef123456"')
        (self.root / 'binary').write_bytes(b'\x00api_key = "abcdef123456"')
        self.assertEqual(scan(self.root), [])

    def test_mask(self):
        self.assertEqual(mask('abcd12345'), 'abcd****')
        self.assertEqual(mask('abcd'), '****')


if __name__ == '__main__': unittest.main()
