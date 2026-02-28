import ast

# ---------------- Sink definitions ----------------
SQL_METHODS = {"execute", "executemany"}
SUBPROCESS_METHODS = {"Popen", "run", "call"}
DESERIALIZE_METHODS = {"loads", "load"}
NETWORK_METHODS = {"get", "post", "put", "delete", "head", "options", "request"}
DB_FETCH_NAMES = {"find", "load", "fetch", "get_user", "get_by_id", "query_user"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}

HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}


# =========================================================
# Finding Object
# =========================================================
class Finding:
    def __init__(self, vuln_type, severity, path, sink, reason, fix):
        self.vuln_type = vuln_type
        self.severity = severity
        self.path = path
        self.sink = sink
        self.reason = reason
        self.fix = fix


# =========================================================
# Symbolic Value (TAINT OBJECT)
# =========================================================
class SymbolicValue:
    def __init__(self, name, tainted=False, path=None):
        self.name = name
        self.tainted = tainted
        self.path = path or [(name, None)]

    def add_step(self, label, node):
        line = getattr(node, "lineno", None)
        self.path.append((label, line))

    def merge(self, other):
        merged = SymbolicValue(self.name, self.tainted or other.tainted, list(self.path))
        merged.path = list(dict.fromkeys(self.path + other.path))
        return merged


# =========================================================
# Symbolic Analyzer
# =========================================================
class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.findings = []
        self._fingerprints = set()
        self.counter = 0
        self.authorized_ids = set()

    # ---------- taint source ----------
    def new_symbol(self, source="request", node=None):
        self.counter += 1
        return SymbolicValue(
            f"{source}_{self.counter}",
            True,
            [(source, getattr(node, "lineno", None))]
        )

    # ---------- deduplicated finding ----------
    def add_finding(self, vuln_type, severity, sym, sink, reason, fix):
        fingerprint = (vuln_type, tuple(sym.path), sink)
        if fingerprint in self._fingerprints:
            return

        self._fingerprints.add(fingerprint)
        self.findings.append(Finding(vuln_type, severity, sym.path, sink, reason, fix))

    # =========================================================
    # AST Evaluation
    # =========================================================
    def eval_node(self, node):

        if node is None:
            return None

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # ---------- request sources ----------
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                if node.attr in REQUEST_CONTAINERS:
                    return self.new_symbol("request", node)

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Attribute):
                    if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "request":
                        sym = self.new_symbol("request", node)
                        sym.add_step("get", node)
                        return sym

        # ---------- XSS ----------
        if isinstance(node, ast.BinOp):

            left = self.eval_node(node.left)
            right = self.eval_node(node.right)

            def contains_html(v):
                return isinstance(v, str) and any(tag in v.lower() for tag in HTML_KEYWORDS)

            if (contains_html(left) and isinstance(right, SymbolicValue)) or (
                contains_html(right) and isinstance(left, SymbolicValue)
            ):
                sym = right if isinstance(right, SymbolicValue) else left
                self.add_finding(
                    "Cross-Site Scripting (XSS)",
                    "HIGH",
                    sym,
                    "HTTP response",
                    "User input returned directly to browser",
                    "Escape output or use templating auto-escaping"
                )

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)
            if isinstance(left, SymbolicValue):
                return left
            if isinstance(right, SymbolicValue):
                return right

        # ---------- Path Traversal ----------
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
                        "Validate filename or use secure_filename()"
                    )

        # ---------- SQL Injection ----------
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
                        "Use parameterized queries"
                    )

        # ---------- SSRF ----------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            obj = node.func.value
            if isinstance(obj, ast.Name) and obj.id == "requests":
                url = None
                if node.args:
                    url = self.eval_node(node.args[0])
                for kw in node.keywords:
                    if kw.arg in ("url", "uri"):
                        url = self.eval_node(kw.value)
                if isinstance(url, SymbolicValue):
                    self.add_finding(
                        "Server-Side Request Forgery (SSRF)",
                        "HIGH",
                        url,
                        "HTTP request",
                        "User-controlled URL used in server request",
                        "Validate allowed hosts"
                    )

        return None

    # =========================================================
    # Traversal
    # =========================================================
    def execute_block(self, body):
        for stmt in body:

            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                val = self.eval_node(stmt.value)
                if isinstance(val, SymbolicValue):
                    val.add_step(stmt.targets[0].id, stmt)
                self.symbols[stmt.targets[0].id] = val

            elif isinstance(stmt, ast.Expr):
                self.eval_node(stmt.value)

            # ---------- RETURN SINK ----------
            elif isinstance(stmt, ast.Return):
                val = self.eval_node(stmt.value)
                if isinstance(val, SymbolicValue):
                    val.add_step("return", stmt)
                    self.add_finding(
                        "Cross-Site Scripting (XSS)",
                        "HIGH",
                        val,
                        "HTTP response",
                        "User input returned directly to browser",
                        "Escape output or use templating auto-escaping"
                    )

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


# =========================================================
# REPORT (Risk Intelligence Layer)
# =========================================================
class AnalysisReport:
    def __init__(self, findings):
        self.raw_findings = findings
        self.issues = [self._decorate(f) for f in findings]

    def _decorate(self, finding):

        path_str = " → ".join(
            f"{name}(line {line})" if line else name
            for name, line in finding.path
        )

        exploitability, reason = self._score_exploitability(finding)

        return (
            f"{finding.vuln_type}\n"
            f"Severity: {finding.severity}\n"
            f"Exploitability: {exploitability}\n"
            f"Reason: {reason}\n"
            f"Attack Path: {path_str}\n"
            f"Sink: {finding.sink}\n"
            f"Why: {finding.reason}\n"
            f"Fix: {finding.fix}"
        )

    def _score_exploitability(self, finding):

        if finding.vuln_type in ("Command Injection", "Unsafe Deserialization"):
            return "VERY LIKELY", "attacker can execute arbitrary code on server"

        if finding.vuln_type == "SQL Injection":
            return "VERY LIKELY", "attacker can read or modify database contents"

        if finding.vuln_type == "Cross-Site Scripting (XSS)":
            return "LIKELY", "attacker can execute JavaScript in victim browser"

        if finding.vuln_type == "Path Traversal":
            return "LIKELY", "attacker may read sensitive server files"

        if finding.vuln_type == "Server-Side Request Forgery (SSRF)":
            return "LIKELY", "attacker can make server perform internal network requests"

        return "UNKNOWN", "insufficient context"


# =========================================================
# ENGINE
# =========================================================
class MetaCodeEngine:
    def orchestrate(self, code):
        tree = ast.parse(code)
        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)
        return AnalysisReport(analyzer.findings)
