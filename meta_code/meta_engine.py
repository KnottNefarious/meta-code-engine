import ast

SQL_METHODS = {"execute", "executemany"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}
HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}

SAFE_FUNCTIONS = {"escape"}  # markupsafe.escape


# ---------------- Finding ----------------
class Finding:
    def __init__(self, vuln_type, severity, path, sink, reason, fix, line):
        self.vuln_type = vuln_type
        self.severity = severity
        self.path = path
        self.sink = sink
        self.reason = reason
        self.fix = fix
        self.line = line

    def format(self):
        path_str = " → ".join(
            f"{label}(line {ln})" if ln else label
            for label, ln in self.path
        )

        return (
            f"{self.vuln_type}\n"
            f"Severity: {self.severity}\n"
            f"Location: line {self.line}\n"
            f"Attack Path: {path_str}\n"
            f"Sink: {self.sink}\n"
            f"Why: {self.reason}\n"
            f"Fix: {self.fix}"
        )


# ---------------- Symbolic Value ----------------
class SymbolicValue:
    def __init__(self, name, tainted=False, path=None):
        self.name = name
        self.tainted = tainted
        self.path = path or [(name, None)]

    def add(self, label, node):
        self.path.append((label, getattr(node, "lineno", None)))

    def merge(self, other):
        merged = SymbolicValue(self.name, self.tainted or other.tainted, list(self.path))
        for step in other.path:
            if step not in merged.path:
                merged.path.append(step)
        return merged


# ---------------- Analyzer ----------------
class SymbolicAnalyzer:

    def __init__(self):
        self.symbols = {}
        self.findings = []
        self._fingerprints = set()
        self.counter = 0

    def new_symbol(self, node):
        self.counter += 1
        return SymbolicValue(f"request_{self.counter}", True, [("request", node.lineno)])

    def add_finding(self, vuln_type, severity, sym, sink, reason, fix, node):

        line = getattr(node, "lineno", None)

        # Correct deduplication: vuln type + sink + line
        fingerprint = (vuln_type, sink, line)
        if fingerprint in self._fingerprints:
            return
        self._fingerprints.add(fingerprint)

        self.findings.append(
            Finding(vuln_type, severity, sym.path, sink, reason, fix, line)
        )

    # ---------------- Node evaluation ----------------
    def eval_node(self, node):

        if node is None:
            return None

        # constants
        if isinstance(node, ast.Constant):
            return node.value

        # variable lookup
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # -------- request sources --------
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                if node.attr in REQUEST_CONTAINERS:
                    return self.new_symbol(node)

        # request.args.get(...)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Attribute):
                    if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "request":
                        sym = self.new_symbol(node)
                        sym.add("get", node)
                        return sym

        # -------- sanitizer recognition --------
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in SAFE_FUNCTIONS:
                return None

        # -------- string concatenation XSS --------
        if isinstance(node, ast.BinOp):

            left = self.eval_node(node.left)
            right = self.eval_node(node.right)

            def is_html(val):
                return isinstance(val, str) and any(tag in val.lower() for tag in HTML_KEYWORDS)

            if (is_html(left) and isinstance(right, SymbolicValue)) or (
                is_html(right) and isinstance(left, SymbolicValue)
            ):
                sym = right if isinstance(right, SymbolicValue) else left
                sym.add("propagation", node)
                return sym

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)
            if isinstance(left, SymbolicValue):
                return left
            if isinstance(right, SymbolicValue):
                return right

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
                path = self.eval_node(node.args[0])
                if isinstance(path, SymbolicValue):
                    self.add_finding(
                        "Path Traversal",
                        "MEDIUM",
                        path,
                        "open(path)",
                        "User input used as filesystem path",
                        "Validate filename",
                        node
                    )

        # -------- Flask template sink --------
        if isinstance(node, ast.Call):

            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in ("render_template", "render_template_string"):
                for kw in node.keywords:
                    val = self.eval_node(kw.value)
                    if isinstance(val, SymbolicValue):
                        val.add("template", node)
                        self.add_finding(
                            "Cross-Site Scripting (XSS)",
                            "HIGH",
                            val,
                            "Jinja template render",
                            "User input injected into HTML template",
                            "Escape variables or enable autoescape",
                            node
                        )

        return None

    # ---------------- execution ----------------
    def execute_block(self, body):
        for stmt in body:

            # assignment tracking
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                val = self.eval_node(stmt.value)
                if isinstance(val, SymbolicValue):
                    val.add(stmt.targets[0].id, stmt)
                self.symbols[stmt.targets[0].id] = val

            # return sink
            elif isinstance(stmt, ast.Return):
                val = self.eval_node(stmt.value)
                if isinstance(val, SymbolicValue):
                    val.add("return", stmt)
                    self.add_finding(
                        "Cross-Site Scripting (XSS)",
                        "HIGH",
                        val,
                        "HTTP response",
                        "User input returned directly to browser",
                        "Escape output or use templating auto-escaping",
                        stmt
                    )

            elif isinstance(stmt, ast.Expr):
                self.eval_node(stmt.value)

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
        self.issues = [f.format() for f in findings]


class MetaCodeEngine:
    def orchestrate(self, code):
        tree = ast.parse(code)
        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)
        return AnalysisReport(analyzer.findings)
