import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from vibe_check import web
from vibe_check.secrets import Finding


class UrlTests(unittest.TestCase):
    def test_accepts_public_repo_urls(self):
        self.assertEqual(web.parse_repo_url('https://github.com/owner/repo.git'), ('owner', 'repo'))
        self.assertEqual(web.parse_repo_url('https://github.com/o-1/a.b_c/'), ('o-1', 'a.b_c'))

    def test_rejects_malicious_urls(self):
        for url in ['http://github.com/o/r', 'https://github.com.evil.com/o/r', 'https://user@github.com/o/r', 'https://github.com/o/r/../x', 'https://github.com/o/..', 'https://github.com/o/r?x=1', 'https://github.com/o/r\n--upload-pack=x', 'ext::sh -c id', '--upload-pack=x', None]:
            with self.assertRaises(web.ScanError, msg=url):
                web.parse_repo_url(url)


class ScanTests(unittest.TestCase):
    def fake_clone(self, content, name='app.py'):
        def run(command, **kwargs):
            self.assertFalse(kwargs['shell'])
            self.assertEqual(command[command.index('--') + 1], 'https://github.com/o/r.git')
            target = Path(command[-1])
            target.mkdir()
            (target / name).write_text(content, encoding='utf-8')
            self.workspace = target.parent
            return CompletedProcess(command, 0)
        return run

    def test_scans_masks_and_cleans_up(self):
        result = web.scan_repo('https://github.com/o/r', self.fake_clone('eval(input())\n'))
        self.assertEqual(result['repo'], 'o/r')
        self.assertIn('dynamic-code-execution', [f['rule'] for f in result['findings']])
        self.assertFalse(self.workspace.exists())

    def test_read_only_git_folder_is_removed_before_scanning(self):
        def run(command, **kwargs):
            target = Path(command[-1])
            (target / '.git').mkdir(parents=True)
            locked = target / '.git' / 'pack'
            locked.write_text('x')
            locked.chmod(0o444)
            (target / 'app.py').write_text('x = 1\n')
            return CompletedProcess(command, 0)
        result = web.scan_repo('https://github.com/o/r', run)
        self.assertNotIn('.git', [f['name'] for f in result['folders']])

    def test_failed_clone_has_safe_message(self):
        with self.assertRaisesRegex(web.ScanError, 'Could not clone'):
            web.scan_repo('https://github.com/o/r', lambda c, **k: CompletedProcess(c, 128, b'', b'secret path'))

    def test_oversized_repo_is_rejected(self):
        with mock.patch.object(web, 'MAX_REPO_BYTES', 1), self.assertRaisesRegex(web.ScanError, 'demo limit'):
            web.scan_repo('https://github.com/o/r', self.fake_clone('hello'))
        self.assertFalse(self.workspace.exists())


class FolderTests(unittest.TestCase):
    def test_counts_files_and_merges_extra_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'readme.md').write_text('x')
            for i in range(13):
                (root / f'd{i:02}').mkdir()
                (root / f'd{i:02}' / 'a.txt').write_text('x')
            finding = Finding('js-eval', 'd12/a.txt', 1, 'eval', 'medium')
            folders, kept = web.summarize_folders(root, [finding])
        self.assertEqual(folders[0], {'name': 'd12', 'files': 1})
        self.assertEqual(len(folders), web.MAX_FOLDERS + 1)
        self.assertEqual(folders[-1]['name'], web.OTHER_FOLDER)
        self.assertEqual(sum(f['files'] for f in folders), 14)
        self.assertIn('d12', kept)

    def test_scan_groups_findings_by_folder(self):
        def run(command, **kwargs):
            target = Path(command[-1])
            (target / 'src').mkdir(parents=True)
            (target / 'src' / 'app.py').write_text('eval(input())\n')
            (target / 'top.py').write_text('eval(input())\n')
            return CompletedProcess(command, 0)
        result = web.scan_repo('https://github.com/o/r', run)
        self.assertEqual({f['folder'] for f in result['findings'] if f['rule'] == 'dynamic-code-execution'}, {'src', web.ROOT_FOLDER})


class PageTests(unittest.TestCase):
    def test_page_renders_repo_content_as_text_and_states_limits(self):
        page = web.PAGE.read_text(encoding='utf-8')
        self.assertNotIn('innerHTML', page)
        self.assertIn("Doesn't cover XSS, SSRF or full SQL injection", page)
        self.assertNotIn('BHARATCODE_API_KEY', page)


if __name__ == '__main__':
    unittest.main()
