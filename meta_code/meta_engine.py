import ast

# ---- sinks ----
SQL_METHODS = {"execute", "executemany"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}
HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}
SANITIZERS = {"escape"}   # markupsafe.escape


# -------------------------------------------------
# Finding object
# -------------------------------------------------

class Finding:
    def __init__(self, vuln_type, severity, line, path, sink, reason, fix):
        self.vuln_type = vuln_type
        self.severity = severity
        self.line = line
        self.path = path
        self.sink = sink
        self.reason = reason
        self.fix = fix

    def format(self):
        return (
            f"{self.vuln_type}\n"
            f"Severity: {self.severity}\n"
            f"Location: line {self.line}\n"
            f"Attack Path: {' → '.join(self.path)}\n"
            f"Sink: {self.sink}\n"
            f"Why: {self.reason}\n"
            f"Fix: {self.fix}"
        )


# -------------------------------------------------
# Symbolic Value
# -------------------------------------------------

class SymbolicValue:
    def __init__(self, name, tainted=False, path=None, line=None):
        self.name = name
        self.tainted = tainted
        self.path = path or []
        self.line = line

    def step(self, label, node):
        ln = getattr(node, "lineno", self.line)
        return SymbolicValue(self.name, True, self.path + [f"{label}(line {ln})"], ln)


# -------------------------------------------------
# Analyzer
# -------------------------------------------------

class SymbolicAnalyzer(ast.NodeVisitor):

    def __init__(self):
        self.symbols = {}
        self.findings = []
        self._fingerprints = set()
        self.counter = 0
        self.http_handlers = set()
        self.functions = {}
        self.in_http_function = False
        self.web_context = False

    # ---------------- sources ----------------

    def new_request(self, node):
        self.counter += 1
        return SymbolicValue(
            f"request_{self.counter}",
            True,
            [f"request(line {node.lineno})"],
            node.lineno
        )

    # ---------------- findings ----------------

    def report(self, vuln, severity, sym, sink, reason, fix):

        fingerprint = (vuln, sym.line, sink)
        if fingerprint in self._fingerprints:
            return
        self._fingerprints.add(fingerprint)

        self.findings.append(
            Finding(vuln, severity, sym.line, sym.path, sink, reason, fix)
        )

    # ---------------- visit module ----------------

    def visit_Module(self, node):

        # detect "from flask import request"
        for n in ast.walk(node):
            if isinstance(n, ast.ImportFrom) and n.module == "flask":
                for name in n.names:
                    if name.name == "request":
                        self.web_context = True

        # detect @app.route
        for n in node.body:
            if isinstance(n, ast.FunctionDef):
                self.functions[n.name] = n
                for dec in n.decorator_list:
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                        if dec.func.attr == "route":
                            self.http_handlers.add(n.name)

        # snippet heuristic (IMPORTANT FIX)
        if self.web_context:
            for name in self.functions:
                self.http_handlers.add(name)

        for n in node.body:
            self.visit(n)

    # ---------------- function ----------------

    def visit_FunctionDef(self, node):

        prev = self.in_http_function
        if node.name in self.http_handlers:
            self.in_http_function = True

        for stmt in node.body:
            self.visit(stmt)

        self.in_http_function = prev

    # ---------------- assignment ----------------

    def visit_Assign(self, node):

        val = self.eval(node.value)

        if isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if isinstance(val, SymbolicValue):
                self.symbols[name] = val.step(name, node)
            else:
                self.symbols[name] = val

    # ---------------- return ----------------

    def visit_Return(self, node):

        val = self.eval(node.value)

        if isinstance(val, SymbolicValue) and val.tainted and self.in_http_function:

            self.report(
                "Cross-Site Scripting (XSS)",
                "HIGH",
                val,
                "HTTP response",
                "User input returned directly to browser",
                "Escape output or use templating auto-escaping"
            )

    # ---------------- evaluation ----------------

    def eval(self, node):

        if node is None:
            return None

        # constants
        if isinstance(node, ast.Constant):
            return node.value

        # variable usage
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # request.args.get
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Attribute)
                    and isinstance(node.func.value.value, ast.Name)
                    and node.func.value.value.id == "request"
                ):
                    return self.new_request(node)

        # sanitizer
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in SANITIZERS:
                return None

        # function call propagation (INTER-PROCEDURAL)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                fname = node.func.id
                if fname in self.functions and node.args:
                    arg = self.eval(node.args[0])
                    if isinstance(arg, SymbolicValue):
                        fn = self.functions[fname]
                        saved = dict(self.symbols)
                        param = fn.args.args[0].arg
                        self.symbols[param] = arg.step(fname, node)
                        for stmt in fn.body:
                            self.visit(stmt)
                        self.symbols = saved
                        return arg

        # string concat
        if isinstance(node, ast.BinOp):
            left = self.eval(node.left)
            right = self.eval(node.right)

            if isinstance(left, SymbolicValue):
                return left.step("propagation", node)
            if isinstance(right, SymbolicValue):
                return right.step("propagation", node)

        # SQL injection
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in SQL_METHODS and node.args:
                arg = self.eval(node.args[0])
                if isinstance(arg, SymbolicValue):
                    self.report(
                        "SQL Injection",
                        "HIGH",
                        arg,
                        "cursor.execute(query)",
                        "User input concatenated into SQL query",
                        "Use parameterized queries"
                    )

        # open(path)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "open" and node.args:
                arg = self.eval(node.args[0])
                if isinstance(arg, SymbolicValue):
                    self.report(
                        "Path Traversal",
                        "MEDIUM",
                        arg,
                        "open(path)",
                        "User input used as filesystem path",
                        "Validate filename"
                    )

        return None


# -------------------------------------------------
# Report
# -------------------------------------------------

class AnalysisReport:
    def __init__(self, findings):
        self.issues = [f.format() for f in findings]


# -------------------------------------------------
# Engine
# -------------------------------------------------

class MetaCodeEngine:
    def orchestrate(self, code):
        tree = ast.parse(code)
        analyzer = SymbolicAnalyzer()
        analyzer.visit(tree)
        return AnalysisReport(analyzer.findings)
