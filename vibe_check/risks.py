"""Narrow Python checks; this is not a security audit."""
import ast
from pathlib import Path
from .secrets import Finding, files
from .js_patterns import risk_matches


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
        for rule, number, evidence in risk_matches(content):
            results.append(Finding(rule, rel, number, evidence, 'medium'))
    # A repository-level observation, not a claim that no tests exist in other languages.
    non_test = [(p, c) for p, c in python if p not in tests and p.name != '__init__.py' and c.strip()]
    if non_test and not tests:
        path, _ = non_test[0]
        results.append(Finding('no-python-test-files-found', path.relative_to(root).as_posix(), 1, 'No test files matched common naming patterns. Tests may exist elsewhere.', 'info'))
    return results
