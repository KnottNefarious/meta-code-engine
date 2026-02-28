import ast

SQL_METHODS = {"execute", "executemany"}
SUBPROCESS_METHODS = {"Popen", "run", "call"}
DESERIALIZE_METHODS = {"loads", "load"}
DB_FETCH_NAMES = {"find", "load", "fetch", "get_user", "get_by_id", "query_user"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}
HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}


# ---------------- Finding ----------------
class Finding:
    def __init__(self, vuln_type, severity, path, sink, reason, fix):
        self.vuln_type = vuln_type
        self.severity = severity
        self.path = path
        self.sink = sink
        self.reason = reason
        self.fix = fix

    def format(self):
        return (
            f"{self.vuln_type}\n"
            f"Severity: {self.severity}\n"
            f"Attack Path: {' → '.join(self.path)}\n"
            f"Sink: {self.sink}\n"
            f"Why: {self.reason}\n"
            f"Fix: {self.fix}"
        )


# ---------------- Symbolic Value ----------------
class SymbolicValue:
    def __init__(self, tainted=False, path=None):
        self.tainted = tainted
        self.path = path or []

    def merge(self, other):
        return SymbolicValue(
            self.tainted or other.tainted,
            list(dict.fromkeys(self.path + other.path))
        )


# ================= ANALYZER =================
class SymbolicAnalyzer(ast.NodeVisitor):

    def __init__(self):
        self.symbols = {}
        self.findings = []
        self._fingerprints = set()

    # ---------- helper ----------
    def new_taint(self, source):
        return SymbolicValue(True, [source])

    def add(self, vuln, severity, sym, sink, why, fix):
        fp = (vuln, tuple(sym.path), sink)
        if fp in self._fingerprints:
            return
        self._fingerprints.add(fp)
        self.findings.append(Finding(vuln, severity, sym.path, sink, why, fix))

    # ---------- expression resolver ----------
    def resolve(self, node):

        if node is None:
            return SymbolicValue(False, [])

        # constants
        if isinstance(node, ast.Constant):
            return SymbolicValue(False, [])

        # variable
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id, SymbolicValue(False, []))

        # request sources
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                if node.attr in REQUEST_CONTAINERS:
                    return self.new_taint("request")

        # request.get(...)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Attribute):
                    if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "request":
                        return self.new_taint("request → get")

        # f-strings
        if isinstance(node, ast.JoinedStr):
            result = SymbolicValue(False, [])
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    result = result.merge(self.resolve(v.value))
            return result

        # concatenation
        if isinstance(node, ast.BinOp):
            left = self.resolve(node.left)
            right = self.resolve(node.right)
            return left.merge(right)

        return SymbolicValue(False, [])

    # ---------- assignments ----------
    def visit_Assign(self, node):
        val = self.resolve(node.value)
        for t in node.targets:
            if isinstance(t, ast.Name):
                self.symbols[t.id] = val

    # ---------- return (XSS sink) ----------
    def visit_Return(self, node):
        val = self.resolve(node.value)
        if val.tainted:
            self.add(
                "Cross-Site Scripting (XSS)",
                "HIGH",
                val,
                "HTTP response",
                "User input returned directly to browser",
                "Escape output or use templating auto-escaping"
            )

    # ---------- SQL ----------
    def visit_Call(self, node):

        # SQL injection
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in SQL_METHODS and node.args:
                q = self.resolve(node.args[0])
                if q.tainted:
                    self.add(
                        "SQL Injection",
                        "HIGH",
                        q,
                        "cursor.execute(query)",
                        "User input concatenated into SQL query",
                        "Use parameterized queries"
                    )

        # command injection
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in SUBPROCESS_METHODS:
                if node.args:
                    cmd = self.resolve(node.args[0])
                    shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value for k in node.keywords)
                    if cmd.tainted and shell:
                        self.add(
                            "Command Injection",
                            "CRITICAL",
                            cmd,
                            "subprocess(shell=True)",
                            "User input executed by OS shell",
                            "Avoid shell=True"
                        )

        # deserialization
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in DESERIALIZE_METHODS and node.args:
                val = self.resolve(node.args[0])
                if val.tainted:
                    self.add(
                        "Unsafe Deserialization",
                        "CRITICAL",
                        val,
                        "pickle/yaml loads()",
                        "Untrusted data deserialized into objects",
                        "Never deserialize untrusted input"
                    )

        # path traversal
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if node.args:
                p = self.resolve(node.args[0])
                if p.tainted:
                    self.add(
                        "Path Traversal",
                        "MEDIUM",
                        p,
                        "open(path)",
                        "User input used as filesystem path",
                        "Validate filename"
                    )

        # SSRF
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "requests":
                if node.args:
                    u = self.resolve(node.args[0])
                    if u.tainted:
                        self.add(
                            "Server-Side Request Forgery (SSRF)",
                            "HIGH",
                            u,
                            "HTTP request",
                            "User-controlled URL used in server request",
                            "Validate allowed hosts"
                        )

        self.generic_visit(node)


# ---------------- Report ----------------
class AnalysisReport:
    def __init__(self, findings):
        self.issues = [f.format() for f in findings]


class MetaCodeEngine:
    def orchestrate(self, code):
        tree = ast.parse(code)
        analyzer = SymbolicAnalyzer()
        analyzer.visit(tree)
        return AnalysisReport(analyzer.findings)
