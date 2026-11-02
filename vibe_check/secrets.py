"""Conservative, evidence-based secret checks. Values never leave this module."""
from dataclasses import dataclass
from pathlib import Path
import os
import re

SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', 'env', '.tox', '.nox', 'build', 'dist', 'target', '__pycache__', '.next', 'vendor'}
LOCKFILES = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'Pipfile.lock', 'Cargo.lock', 'Gemfile.lock', 'composer.lock', 'uv.lock'}
ASSIGN = re.compile(r'''(?i)(?:\$|\b)(?:[\w]*?(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd|private[_-]?key))[\w-]*\s*(?::\s*[\w<>\[\]| ]+)?\s*(?::=|=|:)\s*["']([^"'\r\n]+)["']''')
ENV_ASSIGN = re.compile(r'(?i)^\s*(?:export\s+)?[\w]*(?:api_?key|access_?token|auth_?token|client_?secret|secret_?key|password|private_?key)[\w]*\s*=\s*([^\s#]+)')
AWS = re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')
GITHUB = re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b')
PRIVATE = re.compile(r'-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----')
PLACEHOLDER = re.compile(r'(?i)^(?:your[_-]?.*|<[^>]+>|\$\{?\w+\}?|\{\{.*\}\}|secret[_-]key|base64 encoded random bytes|(?:example|sample|dummy|fake|test|replace|placeholder|changeme|redacted)(?:[_-].*)?)$')


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    masked_value: str
    severity: str = 'high'


def mask(value: str) -> str:
    return value[:4] + '****' if len(value) > 4 else '****'


def files(root: Path):
    for base, dirs, names in os.walk(root, followlinks=False, onerror=lambda error: (_ for _ in ()).throw(error)):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(base) / d).is_symlink())
        for name in sorted(names):
            p = Path(base) / name
            if name in LOCKFILES or p.is_symlink():
                continue
            try:
                raw = p.read_bytes()
            except OSError as exc:
                raise OSError(f'Cannot read {p.relative_to(root)}') from exc
            if b'\x00' in raw:
                continue
            try:
                content = raw.decode('utf-8')
            except UnicodeDecodeError:
                continue
            yield p, content


def scan(root: Path):
    found = []
    for path, content in files(root):
        in_private = False
        for number, line in enumerate(content.splitlines(), 1):
            if PRIVATE.search(line):
                found.append(Finding('private-key-block', path.relative_to(root).as_posix(), number, '[private key block]'))
                in_private = True
                continue
            if in_private:
                if line.startswith('-----END '):
                    in_private = False
                continue
            values = [('aws-access-key', m.group()) for m in AWS.finditer(line)]
            values += [('github-token', m.group()) for m in GITHUB.finditer(line)]
            assignment = ASSIGN.search(line)
            if not assignment and (path.name == '.env' or path.name.startswith('.env.')):
                assignment = ENV_ASSIGN.search(line)
            if assignment:
                value = assignment.group(1).strip('"\'')
                if len(value) >= 8 and not PLACEHOLDER.fullmatch(value):
                    values.append(('hardcoded-credential', value))
            seen = set()
            for rule, value in values:
                if rule == 'hardcoded-credential' and any(value == other for _, other in values if _ != rule):
                    continue
                if (rule, value) not in seen:
                    found.append(Finding(rule, path.relative_to(root).as_posix(), number, mask(value)))
                    seen.add((rule, value))
    return found
