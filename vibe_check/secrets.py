"""Conservative, evidence-based secret checks. Values never leave this module."""
from dataclasses import dataclass
from pathlib import Path
import ast
import os
import re
from .js_patterns import views

SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', 'env', '.tox', '.nox', 'build', 'dist', 'target', '__pycache__', '.next', 'vendor'}
LOCKFILES = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'Pipfile.lock', 'Cargo.lock', 'Gemfile.lock', 'composer.lock', 'uv.lock'}
ASSIGN = re.compile(r'''(?i)(?P<name>\$?[a-z_]\w*(?:-\w+)*)\s*(?::\s*[\w<>\[\]|& ]+)?\s*(?::=|=|:)\s*["'](?P<value>[^"'\r\n]+)["']''')
NAME = re.compile(r'(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd|private[_-]?key)')
ENV_ASSIGN = re.compile(r'(?i)^\s*(?:export\s+)?(?P<name>[a-z_]\w*)\s*=\s*(?P<value>[^\s#]+)')
DOC_SUFFIXES = {'.md', '.markdown', '.rst', '.txt', '.html', '.htm', '.adoc'}
AWS = re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')
GITHUB = re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b')
PRIVATE = re.compile(r'-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----')
URL_PASSWORD = re.compile(r'(://[^/\s:@]+:)[^/\s@]+@')
LONG_TOKEN = re.compile(r'(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2}')
HIDDEN_LINE = '[line hidden: possible secret]'
SECRET_RULES = {'aws-access-key', 'github-token', 'private-key-block', 'hardcoded-credential'}
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


def mask_line(line):
    """Hide likely secret values in a line of source shown outside the scanner."""
    line = AWS.sub(lambda m: mask(m.group()), line)
    line = GITHUB.sub(lambda m: mask(m.group()), line)
    line = URL_PASSWORD.sub(lambda m: m.group(1) + '****@', line)
    for pattern in (ASSIGN, ENV_ASSIGN):
        for match in reversed(list(pattern.finditer(line))):
            if credential_name(match.group('name')):
                line = line[:match.start('value')] + mask(match.group('value')) + line[match.end('value'):]
    return LONG_TOKEN.sub(lambda m: mask(m.group()), line)


def masked_lines(content, hidden=()):
    """Mask a file line by line, dropping private key blocks and lines in hidden."""
    result = []
    in_private = False
    for number, line in enumerate(content.splitlines(), 1):
        if PRIVATE.search(line):
            in_private = True
        if in_private or number in hidden:
            result.append(HIDDEN_LINE)
        else:
            result.append(mask_line(line))
        if in_private and line.startswith('-----END '):
            in_private = False
    return result


def credential_name(name):
    normalized = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name).lower()
    ui_suffix = re.search(r'(?:password|passwd|api_key|access_token|auth_token|secret_key|client_secret|private_key)_(?:error|message|label|hint|description|prompt|regex|pattern)(?:_|$)', normalized)
    return bool(NAME.search(name)) and not ui_suffix


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


def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [target.attr]
    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
        return [target.slice.value]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for item in target.elts for name in target_names(item)]
    return []


def python_literals(content):
    """Literal values only; AST excludes comments, docstrings and env reads."""
    result = {}
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return result
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Assign):
            names = [name for target in node.targets for name in target_names(target)]
        elif isinstance(node, ast.AnnAssign):
            names = target_names(node.target)
        elif isinstance(node, ast.keyword) and node.arg:
            names = [node.arg]
        value = getattr(node, 'value', None)
        if names and any(credential_name(name) for name in names) and isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes)):
            literal = value.value.decode('utf-8', errors='replace') if isinstance(value.value, bytes) else value.value
            result.setdefault(node.lineno, []).append(literal)
    return result


def scan(root: Path):
    found = []
    for path, content in files(root):
        literals = python_literals(content) if path.suffix == '.py' else None
        generic_lines = content.splitlines()
        if path.suffix in {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.go', '.rs', '.php'}:
            generic_lines = views(content)[1].splitlines()
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
            generic_line = generic_lines[number - 1]
            generic_allowed = path.suffix.lower() not in DOC_SUFFIXES
            assignments = list(ASSIGN.finditer(generic_line)) if generic_allowed and literals is None and not generic_line.lstrip().startswith('#') else []
            if not assignments and (path.name == '.env' or path.name.startswith('.env.')):
                generic_allowed = True
                assignment = ENV_ASSIGN.search(line)
                assignments = [assignment] if assignment else []
            literal_values = list(literals.get(number, [])) if literals is not None else []
            for assignment in assignments:
                if generic_allowed and credential_name(assignment.group('name')):
                    literal_values.append(assignment.group('value').strip('"\''))
            for value in literal_values:
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
