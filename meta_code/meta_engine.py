import ast

# ---------------- Known dangerous APIs ----------------
SQL_METHODS = {"execute", "executemany"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}
HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}


# ---------------- Finding Object ----------------
class Finding:
    def __init__(self, vuln_type, severity, path, sink, reason, fix, lineno):
        self.vuln_type = vuln_type
        self.severity = severity
        self.path = path
        self.sink = sink
        self.reason = reason
        self.fix = fix
        self.lineno = lineno


# ---------------- Symbolic Value (Taint) ----------------
class SymbolicValue:
    def __init__(self, name, tainted=False, path=None):
        self.name = name
        self.tainted = tainted
        self.path = path or []

    def add_step(self, label, node):
        line = getattr(node, "lineno", None)
        self.path.append((label, line))

    def merge(self, other):
        merged = SymbolicValue(self.name, self.tainted or other.tainted, list(self.path))
        merged.path = list(dict.fromkeys(self.path + other.path))
        return merged


# ================= SYMBOLIC ANALYZER =================
class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.findings = []
        self._fingerprints = set()
        self.counter = 0

    def new_symbol(self, node, source="request"):
        self.counter += 1
        sym = SymbolicValue(f"{source}_{self.counter}", True)
        sym.add_step(source, node)
        return sym

    # ---- prevents duplicate findings ----
    def add_finding(self, vuln_type, severity, sym, sink, reason, fix, node):
        lineno = getattr(node, "lineno", None)

        fingerprint = (vuln_type, lineno, sink)
        if fingerprint in self._fingerprints:
            return
        self._fingerprints.add(fingerprint)

        self.findings.append(
            Finding(vuln_type, severity, sym.path, sink, reason, fix, lineno)
        )

    # ---------------- Core evaluation ----------------
    def eval_node(self, node):

        if node is None:
            return None

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # -------- Flask request sources --------
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                if node.attr in REQUEST_CONTAINERS:
                    return self.new_symbol(node, "request")

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Attribute):
                    if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "request":
                        sym = self.new_symbol(node, "request")
                        sym.add_step("get", node)
                        return sym

        # -------- Sanitizer recognition --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "escape":
                return None

        # -------- XSS detection --------
        if isinstance(node, ast.BinOp):

            left = self.eval_node(node.left)
            right = self.eval_node(node.right)

            def html_literal(v):
                return isinstance(v, str) and any(tag in v.lower() for tag in HTML_KEYWORDS)

            if (html_literal(left) and isinstance(right, SymbolicValue)) or (
                html_literal(right) and isinstance(left, SymbolicValue)
            ):
                sym = right if isinstance(right, SymbolicValue) else left
                sym.add_step("propagation", node)

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)
            if isinstance(left, SymbolicValue):
                return left
            if isinstance(right, SymbolicValue):
                return right

        # -------- Return sink (real XSS trigger) --------
        if isinstance(node, ast.Return):
            val = self.eval_node(node.value)
            if isinstance(val, SymbolicValue):
                val.add_step("return", node)
                self.add_finding(
                    "Cross-Site Scripting (XSS)",
                    "HIGH",
                    val,
                    "HTTP response",
                    "User input returned directly to browser",
                    "Escape output or use templating auto-escaping",
                    node
                )

        # -------- SQL Injection --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in SQL_METHODS and node.args:
                query = self.eval_node(node.args[0])
                if isinstance(query, SymbolicValue):
                    self.add_finding(
                        "SQL Injection",
                        "HIGH",
                        query,
                        "cursor.execute(query)",
                        "User input concatenated into SQL query",
                        "Use parameterized queries",
                        node
                    )

        # -------- Path Traversal --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            if node.args:
                arg = self.eval_node(node.args[0])
                if isinstance(arg, SymbolicValue):
                    self.add_finding(
                        "Path Traversal",
                        "MEDIUM",
                        arg,
                        "open(path)",
                        "User input used as filesystem path",
                        "Validate filename",
                        node
                    )

        # -------- SSRF --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            obj = node.func.value
            if isinstance(obj, ast.Name) and obj.id == "requests":
                url_sym = None
                if node.args:
                    url_sym = self.eval_node(node.args[0])
                for kw in node.keywords:
                    if kw.arg in ("url", "uri"):
                        url_sym = self.eval_node(kw.value)

                if isinstance(url_sym, SymbolicValue):
                    self.add_finding(
                        "Server-Side Request Forgery (SSRF)",
                        "HIGH",
                        url_sym,
                        "HTTP request",
                        "User-controlled URL used in server request",
                        "Validate allowed hosts",
                        node
                    )

        # -------- Command Injection --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            obj = node.func.value
            if isinstance(obj, ast.Name) and obj.id == "subprocess":

                cmd_sym = None
                if node.args:
                    cmd_sym = self.eval_node(node.args[0])

                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )

                if isinstance(cmd_sym, SymbolicValue) and shell_true:
                    self.add_finding(
                        "Command Injection",
                        "CRITICAL",
                        cmd_sym,
                        "subprocess(shell=True)",
                        "User input executed by OS shell",
                        "Avoid shell=True and pass arguments as list",
                        node
                    )

        return None

    # -------- Traversal --------
    def execute_block(self, body):
        for stmt in body:

            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                val = self.eval_node(stmt.value)
                if isinstance(val, SymbolicValue):
                    val.add_step(stmt.targets[0].id, stmt)
                self.symbols[stmt.targets[0].id] = val

            elif isinstance(stmt, ast.Expr):
                self.eval_node(stmt.value)

            elif isinstance(stmt, ast.Return):
                self.eval_node(stmt)

            elif isinstance(stmt, ast.If):
                self.eval_node(stmt.test)
                self.execute_block(stmt.body)
                self.execute_block(stmt.orelse)

    def analyze(self, tree):
        self.execute_block(tree.body)

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                saved = self.symbols.copy()
                self.execute_block(node.body)
                self.symbols = saved


# ---------------- Report ----------------
class AnalysisReport:
    def __init__(self, findings):
        self.raw_findings = findings
        self.issues = [self._decorate(f) for f in findings]

    def _decorate(self, f):
        path_str = " → ".join(
            f"{label}(line {line})" if line else label
            for label, line in f.path
        )

        return (
            f"{f.vuln_type}\n"
            f"Severity: {f.severity}\n"
            f"Location: line {f.lineno}\n"
            f"Attack Path: {path_str}\n"
            f"Sink: {f.sink}\n"
            f"Why: {f.reason}\n"
            f"Fix: {f.fix}"
        )


# ---------------- Engine ----------------
class MetaCodeEngine:
    def orchestrate(self, code):
        tree = ast.parse(code)
        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)
        return AnalysisReport(analyzer.findings)
