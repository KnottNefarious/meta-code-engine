import ast

# ---------------- configuration ----------------

SQL_METHODS = {"execute", "executemany"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}
HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}

SANITIZERS = {"escape"}  # markupsafe.escape


# ---------------- finding ----------------

class Finding:
    def __init__(self, vuln_type, severity, location, path, sink, reason, fix):
        self.vuln_type = vuln_type
        self.severity = severity
        self.location = location
        self.path = path
        self.sink = sink
        self.reason = reason
        self.fix = fix

    def format(self):
        return (
            f"{self.vuln_type}\n"
            f"Severity: {self.severity}\n"
            f"Location: line {self.location}\n"
            f"Attack Path: {' → '.join(self.path)}\n"
            f"Sink: {self.sink}\n"
            f"Why: {self.reason}\n"
            f"Fix: {self.fix}"
        )


# ---------------- symbolic value ----------------

class SymbolicValue:
    def __init__(self, name, tainted=False, path=None):
        self.name = name
        self.tainted = tainted
        self.path = path or []
        self.line = None

    def propagate(self, label, node):
        line = getattr(node, "lineno", None)
        self.path.append(f"{label}(line {line})")
        self.line = line
        return self


# ---------------- analyzer ----------------

class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.findings = []
        self.counter = 0
        self._fingerprints = set()

    # ---------- utilities ----------

    def new_taint(self, node):
        self.counter += 1
        sym = SymbolicValue(f"request_{self.counter}", True, [])
        sym.propagate("request", node)
        return sym

    def add_finding(self, vuln_type, severity, sym, sink, reason, fix):
        if not sym.tainted:
            return

        fingerprint = (vuln_type, tuple(sym.path), sink)
        if fingerprint in self._fingerprints:
            return
        self._fingerprints.add(fingerprint)

        location = sym.line if sym.line else 0

        self.findings.append(
            Finding(vuln_type, severity, location, sym.path, sink, reason, fix)
        )

    # ---------- evaluation ----------

    def eval(self, node):

        if node is None:
            return None

        # constants
        if isinstance(node, ast.Constant):
            return node.value

        # variable reference
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # request.args / form / json
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                if node.attr in REQUEST_CONTAINERS:
                    return self.new_taint(node)

        # request.args.get("q")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):

                # sanitizer
                if node.func.attr in SANITIZERS:
                    val = self.eval(node.args[0]) if node.args else None
                    if isinstance(val, SymbolicValue):
                        val.tainted = False
                    return val

                # request.args.get
                if isinstance(node.func.value, ast.Attribute):
                    if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "request":
                        sym = self.new_taint(node)
                        sym.propagate("get", node)
                        return sym

        # string concatenation (XSS)
        if isinstance(node, ast.BinOp):
            left = self.eval(node.left)
            right = self.eval(node.right)

            def html(x):
                return isinstance(x, str) and any(t in x.lower() for t in HTML_KEYWORDS)

            if isinstance(left, SymbolicValue):
                left.propagate("propagation", node)
            if isinstance(right, SymbolicValue):
                right.propagate("propagation", node)

            if (html(left) and isinstance(right, SymbolicValue)) or (html(right) and isinstance(left, SymbolicValue)):
                sym = right if isinstance(right, SymbolicValue) else left
                self.add_finding(
                    "Cross-Site Scripting (XSS)",
                    "HIGH",
                    sym,
                    "HTTP response",
                    "User input returned directly to browser",
                    "Escape output or use templating auto-escaping",
                )

            return left if isinstance(left, SymbolicValue) else right

        # return sink
        if isinstance(node, ast.Return):
            val = self.eval(node.value)
            if isinstance(val, SymbolicValue):
                val.propagate("return", node)
                self.add_finding(
                    "Cross-Site Scripting (XSS)",
                    "HIGH",
                    val,
                    "HTTP response",
                    "User input returned directly to browser",
                    "Escape output or use templating auto-escaping",
                )

        return None

    # ---------- traversal ----------

    def walk(self, body):
        for stmt in body:

            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                val = self.eval(stmt.value)
                if isinstance(val, SymbolicValue):
                    val.propagate(stmt.targets[0].id, stmt)
                self.symbols[stmt.targets[0].id] = val

            elif isinstance(stmt, ast.Expr):
                self.eval(stmt.value)

            elif isinstance(stmt, ast.Return):
                self.eval(stmt)

            elif isinstance(stmt, ast.FunctionDef):
                saved = self.symbols.copy()
                self.walk(stmt.body)
                self.symbols = saved

            elif isinstance(stmt, ast.If):
                self.walk(stmt.body)
                self.walk(stmt.orelse)

    def analyze(self, tree):
        self.walk(tree.body)


# ---------------- report ----------------

class AnalysisReport:
    def __init__(self, findings):
        self.issues = [f.format() for f in findings]


# ---------------- engine ----------------

class MetaCodeEngine:
    def orchestrate(self, code):
        try:
            tree = ast.parse(code)
        except Exception:
            return AnalysisReport([])

        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)
        return AnalysisReport(analyzer.findings)
