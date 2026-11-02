"""Small AST review checks, not a complete Python name/dataflow analysis."""
import ast

SHELL_CALLS = {'run', 'Popen', 'call', 'check_call', 'check_output'}
CURSOR_NAMES = {'cursor', 'cur', 'db_cursor'}


class LocalNames(ast.NodeVisitor):
    """Find local bindings without treating nested bodies as the same scope."""
    def __init__(self):
        self.names = set()

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store): self.names.add(node.id)

    def visit_Import(self, node):
        self.names.update(a.asname or a.name.split('.')[0] for a in node.names)

    def visit_ImportFrom(self, node):
        self.names.update(a.asname or a.name for a in node.names)

    def visit_FunctionDef(self, node): self.names.add(node.name)
    visit_AsyncFunctionDef = visit_FunctionDef
    def visit_ClassDef(self, node): self.names.add(node.name)
    def visit_Lambda(self, node): pass


class Review(ast.NodeVisitor):
    def __init__(self):
        self.scopes = [{}]
        self.findings = []

    def lookup(self, name):
        for scope in reversed(self.scopes):
            if name in scope: return scope[name]
        return None

    def visit_Import(self, node):
        for item in node.names:
            self.scopes[-1][item.asname or item.name.split('.')[0]] = 'subprocess' if item.name == 'subprocess' else None

    def visit_ImportFrom(self, node):
        for item in node.names:
            kind = 'shell-call' if node.module == 'subprocess' and item.name in SHELL_CALLS else None
            self.scopes[-1][item.asname or item.name] = kind

    def visit_FunctionDef(self, node):
        # Defaults/decorators are evaluated outside the function body.
        for expr in [*node.decorator_list, *node.args.defaults, *[v for v in node.args.kw_defaults if v]]:
            self.visit(expr)
        self.scopes[-1][node.name] = None
        local = LocalNames()
        for item in node.body: local.visit(item)
        params = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        if node.args.vararg: params.append(node.args.vararg)
        if node.args.kwarg: params.append(node.args.kwarg)
        scope = dict.fromkeys(local.names | {a.arg for a in params})
        self.scopes.append(scope)
        for item in node.body: self.visit(item)
        self.scopes.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        self.visit(node.value)
        cursor = isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'cursor'
        for target in node.targets:
            for item in ast.walk(target):
                if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
                    self.scopes[-1][item.id] = 'cursor' if cursor else None

    def visit_AnnAssign(self, node):
        if node.value: self.visit(node.value)
        if isinstance(node.target, ast.Name):
            cursor = isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'cursor'
            self.scopes[-1][node.target.id] = 'cursor' if cursor else None

    def visit_Call(self, node):
        func = node.func
        if isinstance(func, ast.Name) and func.id in {'eval', 'exec'}:
            self.findings.append(('dynamic-code-execution', node.lineno, func.id + '(...)'))
        shell = isinstance(func, ast.Name) and self.lookup(func.id) == 'shell-call'
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            shell = func.attr in SHELL_CALLS and self.lookup(func.value.id) == 'subprocess'
        if shell and any(k.arg == 'shell' and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
            self.findings.append(('subprocess-shell-true', node.lineno, 'subprocess call with shell=True'))
        if isinstance(func, ast.Attribute) and func.attr == 'execute' and node.args:
            receiver = func.value
            cursor = isinstance(receiver, ast.Name) and (receiver.id in CURSOR_NAMES or self.lookup(receiver.id) == 'cursor')
            arg = node.args[0]
            interpolated = isinstance(arg, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in arg.values)
            concatenated = isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add) and any(isinstance(v, ast.Constant) and isinstance(v.value, str) for v in ast.walk(arg))
            if cursor and (interpolated or concatenated):
                self.findings.append(('possible-sql-string-building', node.lineno, 'possible SQL string building: cursor.execute(dynamic string)'))
        self.generic_visit(node)


def risk_matches(tree):
    visitor = Review()
    visitor.visit(tree)
    return visitor.findings
