"""Local demo UI: scan one public GitHub repository from a browser."""
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .ai import chat, fix_prompt
from .report import verdict
from .risks import scan as scan_risks
from .secrets import SECRET_RULES, masked_lines, scan

HOST = '127.0.0.1'
PORT = 8765
CLONE_TIMEOUT = 60
MAX_REPO_BYTES = 200 * 1024 * 1024
MAX_BODY_BYTES = 16384
MAX_QUESTION = 500
MAX_HISTORY = 6
MAX_TURN = 1200
SNIPPET_RADIUS = 3
MAX_LINE = 200
FILE_LEVEL_RULES = {'no-python-test-files-found'}
MAX_FOLDERS = 11
ROOT_FOLDER = '(root)'
OTHER_FOLDER = '(other)'
REPO_URL = re.compile(r'https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?')
PAGE = Path(__file__).with_name('web_ui.html')
EXAMPLE = Path(__file__).with_name('example_nodegoat.json')
scan_lock = threading.Lock()
latest_scan = {}


class ScanError(Exception):
    """A failure whose message is safe to show on the page."""


def parse_repo_url(url):
    match = REPO_URL.fullmatch(url.strip()) if isinstance(url, str) else None
    if not match or match.group(2) in {'.', '..'}:
        raise ScanError('Use a public repository link like https://github.com/owner/repo')
    return match.group(1), match.group(2)


def directory_size(root):
    return sum(path.stat().st_size for path in root.rglob('*') if path.is_file() and not path.is_symlink())


def remove_tree(path):
    def retry(function, target, _error):
        os.chmod(target, stat.S_IWRITE)
        function(target)
    shutil.rmtree(path, onerror=retry)


def clone(owner, name, target, runner=subprocess.run):
    url = f'https://github.com/{owner}/{name}.git'
    command = ['git', '-c', 'core.symlinks=false', '-c', 'protocol.ext.allow=never', 'clone', '--depth', '1', '--single-branch', '--no-tags', '--', url, str(target)]
    env = {**os.environ, 'GIT_TERMINAL_PROMPT': '0'}
    try:
        result = runner(command, shell=False, capture_output=True, timeout=CLONE_TIMEOUT, env=env)
    except subprocess.TimeoutExpired:
        raise ScanError('Cloning took too long. Try a smaller repository.') from None
    except OSError:
        raise ScanError('Git is not available on this computer.') from None
    if result.returncode != 0:
        raise ScanError('Could not clone that repository. Check that it exists and is public.')


def folder_of(path):
    parts = str(path).replace('\\', '/').split('/')
    return parts[0] if len(parts) > 1 else ROOT_FOLDER


def summarize_folders(root, findings):
    """Count files and findings per top-level folder, merging the quietest past MAX_FOLDERS."""
    files = {}
    for path in root.rglob('*'):
        if path.is_file() and not path.is_symlink():
            name = folder_of(path.relative_to(root).as_posix())
            files[name] = files.get(name, 0) + 1
    hits = {}
    for finding in findings:
        name = folder_of(finding.path)
        hits[name] = hits.get(name, 0) + 1
        files.setdefault(name, 0)
    ranked = sorted(files, key=lambda name: (-hits.get(name, 0), -files[name], name))
    kept = ranked[:MAX_FOLDERS]
    extra = ranked[MAX_FOLDERS:]
    folders = [{'name': name, 'files': files[name]} for name in kept]
    if extra:
        folders.append({'name': OTHER_FOLDER, 'files': sum(files[name] for name in extra)})
    return folders, set(kept)


def snippet_for(root, finding, findings):
    """Return masked lines around a finding; lines flagged as secrets are never included."""
    if finding.rule in FILE_LEVEL_RULES:
        return []
    hidden = {f.line for f in findings if f.path == finding.path and f.rule in SECRET_RULES}
    try:
        content = (root / finding.path).read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError):
        return []
    lines = masked_lines(content, hidden)
    first = max(finding.line - SNIPPET_RADIUS, 1)
    last = min(finding.line + SNIPPET_RADIUS, len(lines))
    return [{'line': number, 'text': lines[number - 1][:MAX_LINE], 'flagged': number == finding.line} for number in range(first, last + 1)]


def scan_repo(url, runner=subprocess.run):
    owner, name = parse_repo_url(url)
    workspace = Path(tempfile.mkdtemp(prefix='vibe-check-'))
    try:
        target = workspace / 'repo'
        clone(owner, name, target, runner)
        if directory_size(target) > MAX_REPO_BYTES:
            raise ScanError('That repository is over the 200 MB demo limit.')
        if (target / '.git').exists():
            remove_tree(target / '.git')
        findings = scan(target) + scan_risks(target)
        folders, kept = summarize_folders(target, findings)
        return {
            'scan': uuid.uuid4().hex,
            'repo': f'{owner}/{name}',
            'verdict': verdict(findings),
            'folders': folders,
            'findings': [{
                'id': index,
                'rule': f.rule,
                'path': f.path,
                'line': f.line,
                'evidence': f.masked_value,
                'severity': f.severity,
                'folder': folder_of(f.path) if folder_of(f.path) in kept else OTHER_FOLDER,
                'snippet': snippet_for(target, f, findings),
                'fix_prompt': fix_prompt(f.rule, f.path, f.line),
            } for index, f in enumerate(findings)],
        }
    finally:
        remove_tree(workspace)


def load_example():
    """A saved scan of OWASP NodeGoat, so the demo works without cloning."""
    result = json.loads(EXAMPLE.read_text(encoding='utf-8'))
    return {**result, 'scan': uuid.uuid4().hex, 'example': True}


def clean_history(history):
    if history is None:
        return []
    valid = isinstance(history, list) and all(isinstance(turn, dict) and turn.get('role') in {'user', 'assistant'} and isinstance(turn.get('content'), str) and len(turn['content']) <= MAX_TURN for turn in history)
    if not valid:
        raise ScanError('Invalid chat history.')
    return [{'role': turn['role'], 'content': turn['content']} for turn in history[-MAX_HISTORY:]]


class Handler(BaseHTTPRequestHandler):
    server_version = 'vibe-check'
    sys_version = ''

    def log_message(self, *_args):
        pass

    def trusted_host(self):
        allowed = {f'{HOST}:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        return self.headers.get('Host') in allowed

    def send_body(self, status, body, content_type):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, value):
        self.send_body(status, json.dumps(value).encode(), 'application/json')

    def do_GET(self):
        if not self.trusted_host():
            return self.send_json(403, {'error': 'Forbidden host.'})
        if self.path != '/':
            return self.send_json(404, {'error': 'Not found.'})
        self.send_body(200, PAGE.read_bytes(), 'text/html; charset=utf-8')

    def read_json(self):
        origin = self.headers.get('Origin')
        origins = {f'http://{HOST}:{self.server.server_port}', f'http://localhost:{self.server.server_port}'}
        if not self.trusted_host() or (origin and origin not in origins):
            raise PermissionError
        if self.headers.get('Content-Type') != 'application/json':
            raise ScanError('Send JSON.')
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            raise ScanError('Invalid request.') from None
        if not 0 < size <= MAX_BODY_BYTES:
            raise ScanError('Invalid request.')
        try:
            value = json.loads(self.rfile.read(size))
        except ValueError:
            raise ScanError('Invalid request.') from None
        if not isinstance(value, dict):
            raise ScanError('Invalid request.')
        return value

    def do_POST(self):
        try:
            value = self.read_json()
            if self.path == '/api/scan':
                if not scan_lock.acquire(blocking=False):
                    return self.send_json(429, {'error': 'A scan is already running.'})
                try:
                    result = scan_repo(value.get('url'))
                    latest_scan.clear()
                    latest_scan.update(result)
                    return self.send_json(200, result)
                finally:
                    scan_lock.release()
            if self.path == '/api/example':
                result = load_example()
                latest_scan.clear()
                latest_scan.update(result)
                return self.send_json(200, result)
            if self.path == '/api/chat':
                return self.send_json(200, self.answer(value))
            self.send_json(404, {'error': 'Not found.'})
        except PermissionError:
            self.send_json(403, {'error': 'Forbidden origin.'})
        except ScanError as exc:
            self.send_json(400, {'error': str(exc)})
        except OSError:
            self.send_json(500, {'error': 'The scan failed on this computer.'})

    def answer(self, value):
        findings = latest_scan.get('findings', [])
        index = value.get('finding')
        if not latest_scan or value.get('scan') != latest_scan.get('scan') or type(index) is not int or not 0 <= index < len(findings):
            raise ScanError('Scan the repository again to ask about this finding.')
        question = value.get('question')
        if not isinstance(question, str) or not question.strip() or len(question) > MAX_QUESTION:
            raise ScanError(f'Ask a question of up to {MAX_QUESTION} characters.')
        history = clean_history(value.get('history'))
        key = os.environ.get('BHARATCODE_API_KEY')
        if not key:
            raise ScanError('Set BHARATCODE_API_KEY to use chat. Scan results still work without it.')
        # Only this finding's masked snippet leaves the machine, never the repository.
        text = chat(findings[index], history, question.strip(), key)
        if not text:
            raise ScanError('BharatCode did not answer. Scan results still work without it.')
        return {'answer': text}


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f'http://{HOST}:{PORT}'
    print(f'vibe-check UI: {url}  (Ctrl+C to stop)')
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
