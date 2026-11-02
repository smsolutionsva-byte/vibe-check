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
        begin = '-----BEGIN ' + 'PRIVATE KEY-----'
        pgp = '-----BEGIN ' + 'PGP PRIVATE KEY BLOCK-----'
        self.write('secrets.txt', f'{aws}\n{github}\n{begin}\nNOTREAL\n-----END PRIVATE KEY-----\n{pgp}\nNOTREAL\n-----END PGP PRIVATE KEY BLOCK-----\n')
        findings = scan(self.root)
        self.assertEqual([f.rule for f in findings], ['aws-access-key', 'github-token', 'private-key-block', 'private-key-block'])
        self.assertEqual([f.line for f in findings], [1, 2, 3, 6])
        self.assertNotIn(aws, repr(findings))
        self.assertNotIn(github, repr(findings))

    def test_assignments_languages_and_env(self):
        fake = 'abcd' + 'ef123456'
        data = {'a.py': f'api_key = "{fake}"', 'a.js': f'const apiKey = "{fake}";', 'a.ts': f'const apiKey: string = "{fake}";', 'a.go': f'apiKey := "{fake}"', 'a.php': f'$api_key = "{fake}";', 'a.rb': f'api_key = "{fake}"', 'a.rs': f'let api_key = "{fake}";', '.env': f'API_KEY={fake}'}
        for filename, value in data.items(): self.write(filename, value)
        findings = scan(self.root)
        self.assertEqual(len(findings), len(data))
        self.assertEqual({f.path for f in findings}, set(data))
        self.assertTrue(all(f.masked_value == 'abcd****' for f in findings))

    def test_placeholder_and_environment_reads(self):
        self.write('a.py', 'api_key = "your_api_key"\napi_key = os.environ.get("API_KEY")\napi_key = "<YOUR_API_KEY>"\nsecret_key="secret-key"\nsecret_key="secret_key"\n')
        self.write('example.rst', 'export SECRET_KEY="base64 encoded random bytes"\n')
        self.write('.env.example', 'API_KEY=your_api_key\n')
        self.assertEqual(scan(self.root), [])

    def test_skipped_dirs_lockfiles_and_binary(self):
        fake_line = 'api_' + 'key = "' + 'abcd' + 'ef123456"'
        for folder in ['.git', 'node_modules', '.venv', 'venv', 'build', 'dist', 'target']:
            self.write(folder + '/a.py', fake_line)
        self.write('package-lock.json', fake_line)
        (self.root / 'binary').write_bytes(b'\x00' + fake_line.encode())
        self.assertEqual(scan(self.root), [])

    def test_mask(self):
        self.assertEqual(mask('abcd12345'), 'abcd****')
        self.assertEqual(mask('abcd'), '****')


if __name__ == '__main__': unittest.main()
