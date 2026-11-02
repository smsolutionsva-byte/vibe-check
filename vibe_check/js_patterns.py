"""Lightweight JS/TS lexical filtering and call patterns, not a parser.

Preserve offsets for line evidence. Template interpolation, regex literal
disambiguation and binding scope are deliberately not fully understood.
"""
import re

TOKENS = re.compile(r'''/\*[\s\S]*?\*/|//[^\r\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`''')
MODULE = r'''["'](?:node:)?child_process["']'''


def blank(text):
    return ''.join('\n' if char == '\n' else ' ' for char in text)


def views(content):
    code, comments_removed = list(content), list(content)
    for match in TOKENS.finditer(content):
        replacement = blank(match.group())
        code[match.start():match.end()] = replacement
        if match.group().startswith(('//', '/*')):
            comments_removed[match.start():match.end()] = replacement
    return ''.join(code), ''.join(comments_removed)


def child_process_bindings(code, comments_removed):
    names = set()
    patterns = [
        (r'\b(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*' + MODULE + r'\s*\)', 'namespace'),
        (r'\bimport\s+\*\s+as\s+(\w+)\s+from\s*' + MODULE, 'namespace'),
        (r'\bimport\s+(\w+)\s+from\s*' + MODULE, 'namespace'),
        (r'\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*' + MODULE + r'\s*\)', 'cjs'),
        (r'\bimport\s*\{([^}]+)\}\s*from\s*' + MODULE, 'esm'),
    ]
    for pattern, kind in patterns:
        for match in re.finditer(pattern, comments_removed):
            if not code[match.start():match.start() + 1].strip():
                continue  # Import-like text inside a string.
            if kind == 'namespace':
                names.add(match.group(1) + '.exec')
            else:
                for member in match.group(1).split(','):
                    alias = re.fullmatch(r'\s*exec(?:\s*(?::|as\b)\s*(\w+))?\s*', member)
                    if alias:
                        names.add(alias.group(1) or 'exec')
    return names


def concatenated_first_argument(code, opening):
    depth = 1
    for char in code[opening + 1:]:
        if char in '([{': depth += 1
        elif char in ')]}': depth -= 1
        if depth == 0 or (char == ',' and depth == 1): return False
        if char == '+': return True
    return False


def risk_matches(content):
    code, comments_removed = views(content)
    matches = []
    for rule, pattern, evidence in [
        ('js-eval', r'(?<![\w.$])eval\s*\(', 'eval(...)'),
        ('js-new-function', r'\bnew\s+Function\s*\(', 'new Function(...)'),
    ]:
        for match in re.finditer(pattern, code):
            matches.append((match.start(), rule, evidence))
    for name in sorted(child_process_bindings(code, comments_removed)):
        pattern = r'(?<![\w.$])' + re.escape(name) + r'\s*\('
        for match in re.finditer(pattern, code):
            if concatenated_first_argument(code, match.end() - 1):
                matches.append((match.start(), 'js-child-process-concatenation', 'child_process exec(... + ...)'))
    return [(rule, content.count('\n', 0, start) + 1, evidence)
            for start, rule, evidence in sorted(matches)]
