import ast

SQL_METHODS = {"execute", "executemany"}
SUBPROCESS_METHODS = {"Popen", "run", "call"}
DESERIALIZE_METHODS = {"loads", "load"}
SAFE_PATH_FUNCS = {"basename", "secure_filename"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}


class SymbolicValue:
    def __init__(self, name, tainted=False, path=None):
        self.name = name
        self.tainted = tainted
        self.path = path or [name]

    def sanitize(self, label):
        clean = SymbolicValue(self.name, False, list(self.path))
        clean.path.append(f"sanitized:{label}")
        return clean

    def merge(self, other):
        merged = SymbolicValue(self.name, self.tainted or other.tainted, list(self.path))
        merged.path = list(dict.fromkeys(self.path + other.path))
        return merged


class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.issues = []
        self.counter = 0
        self.functions = {}

    def new_symbol(self, source="request"):
        self.counter += 1
        return SymbolicValue(f"{source}_{self.counter}", True, [source])

    def is_request(self, node):
        return (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "request"
            and node.attr in REQUEST_CONTAINERS
        )

    def eval_node(self, node):

        if node is None:
            return None

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # request.args.get(...)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and self.is_request(node.func.value):
                sym = self.new_symbol()
                sym.path.append("get")
                return sym

        # sanitizer
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in SAFE_PATH_FUNCS:
                val = self.eval_node(node.args[0])
                if isinstance(val, SymbolicValue):
                    return val.sanitize(node.func.attr)

        # string concatenation
        if isinstance(node, ast.BinOp):
            left = self.eval_node(node.left)
            right = self.eval_node(node.right)

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)
            if isinstance(left, SymbolicValue):
                return left
            if isinstance(right, SymbolicValue):
                return right

        # open()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            arg_val = self.eval_node(node.args[0])
            if isinstance(arg_val, SymbolicValue) and arg_val.tainted:
                self.issues.append("Path traversal vulnerability detected")
            return None

        # SQL
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in SQL_METHODS:
                query = self.eval_node(node.args[0])
                if len(node.args) == 1 and isinstance(query, SymbolicValue) and query.tainted:
                    self.issues.append("SQL injection vulnerability detected")

        # subprocess
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in SUBPROCESS_METHODS:
                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                cmd = self.eval_node(node.args[0])
                if isinstance(cmd, SymbolicValue) and cmd.tainted and shell_true:
                    self.issues.append("Command injection vulnerability detected")

        # deserialization
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in DESERIALIZE_METHODS:
                val = self.eval_node(node.args[0])
                if isinstance(val, SymbolicValue) and val.tainted:
                    self.issues.append("Unsafe deserialization vulnerability detected")

        return None

    def execute_block(self, body):
        for stmt in body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                self.symbols[stmt.targets[0].id] = self.eval_node(stmt.value)
            elif isinstance(stmt, ast.Expr):
                self.eval_node(stmt.value)

    def analyze(self, tree):

        # collect functions
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                self.functions[node.name] = node

        # simulate calling every function
        for func in self.functions.values():
            old_symbols = self.symbols.copy()

            # parameters become attacker-controlled
            for arg in func.args.args:
                self.symbols[arg.arg] = self.new_symbol("param")

            self.execute_block(func.body)

            self.symbols = old_symbols


class AnalysisReport:
    def __init__(self, issues):
        self.issues = issues


class MetaCodeEngine:
    def orchestrate(self, code):
        tree = ast.parse(code)
        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)
        return AnalysisReport(analyzer.issues)
