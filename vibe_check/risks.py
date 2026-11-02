"""Narrow Python checks; this is not a security audit."""
import ast
import re
from pathlib import Path
from .secrets import Finding, files


def scan(root: Path):
    items = list(files(root))
    python = [(p, text) for p, text in items if p.suffix == '.py']
    tests = [p for p, _ in python if p.name.startswith('test_') or p.name.endswith('_test.py')]
    results = []
    for path, content in python:
        rel = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in {'eval', 'exec'}:
                results.append(Finding('dynamic-code-execution', rel, node.lineno, node.func.id + '(...)', 'medium'))
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
                if any(k.arg == 'shell' and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                    results.append(Finding('subprocess-shell-true', rel, node.lineno, 'subprocess.' + node.func.attr + '(shell=True)', 'medium'))
    for path, content in items:
        if path.suffix not in {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}:
            continue
        rel = path.relative_to(root).as_posix()
        # Pattern-based checks: no JS/TS parser or complete comment/string handling.
        child_process = bool(re.search(r'''(?:from\s*|require\s*\()\s*["'](?:node:)?child_process["']''', content))
        for number, line in enumerate(content.splitlines(), 1):
            if line.lstrip().startswith(('//', '*', '/*')):
                continue
            if re.search(r'(?<![\w.$])eval\s*\(', line):
                results.append(Finding('js-eval', rel, number, 'eval(...)', 'medium'))
            if re.search(r'\bnew\s+Function\s*\(', line):
                results.append(Finding('js-new-function', rel, number, 'new Function(...)', 'medium'))
            if child_process and re.search(r'\b(?:\w+\.)?exec\s*\([^\n;]*\+', line):
                results.append(Finding('js-child-process-concatenation', rel, number, 'exec(... + ...)', 'medium'))
    # A repository-level observation, not a claim that no tests exist in other languages.
    non_test = [(p, c) for p, c in python if p not in tests and p.name != '__init__.py' and c.strip()]
    if non_test and not tests:
        path, _ = non_test[0]
        results.append(Finding('no-python-test-files-found', path.relative_to(root).as_posix(), 1, 'No test files matched common naming patterns. Tests may exist elsewhere.', 'info'))
    return results
