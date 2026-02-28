import ast

# =========================
# Known sinks & sources
# =========================

SQL_METHODS = {"execute", "executemany"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}
HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}

IDOR_FUNCTIONS = {"get_user", "load_user", "find_user", "query_user", "get_by_id"}


# =========================
# Finding Object
# =========================

class Finding:
    def __init__(self, vuln_type, severity, path, sink, reason, fix, location=None):
        self.vuln_type = vuln_type
        self.severity = severity
        self.path = path
        self.sink = sink
        self.reason = reason
        self.fix = fix
        self.location = location


# =========================
# Symbolic Value (Taint Object)
# =========================

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
        for step in other.path:
            if step not in merged.path:
                merged.path.append(step)
        return merged


# =========================
# Symbolic Analyzer
# =========================

class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.findings = []
        self._fingerprints = set()
        self.counter = 0

    # -------- Create tainted symbol --------
    def new_symbol(self, node, source="request"):
        self.counter += 1
        sym = SymbolicValue(f"{source}_{self.counter}", True)
        sym.add_step(source, node)
        return sym

    # -------- Add finding (deduplicated) --------
    def add_finding(self, vuln_type, severity, sym, sink, reason, fix, node):
        location = getattr(node, "lineno", None)

        fingerprint = (vuln_type, location, sink)
        if fingerprint in self._fingerprints:
            return

        self._fingerprints.add(fingerprint)

        self.findings.append(
            Finding(vuln_type, severity, list(sym.path), sink, reason, fix, location)
        )

    # =========================
    # Node Evaluation
    # =========================

    def eval_node(self, node):

        if node is None:
            return None

        # constants
        if isinstance(node, ast.Constant):
            return node.value

        # variable usage
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # request.args / request.form etc
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                if node.attr in REQUEST_CONTAINERS:
                    return self.new_symbol(node)

        # request.args.get("q")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                attr = node.func

                if isinstance(attr.value, ast.Attribute):
                    if isinstance(attr.value.value, ast.Name) and attr.value.value.id == "request":
                        sym = self.new_symbol(node)
                        sym.add_step("get", node)
                        return sym

        # string concatenation (XSS propagation)
        if isinstance(node, ast.BinOp):
            left = self.eval_node(node.left)
            right = self.eval_node(node.right)

            def html_literal(v):
                return isinstance(v, str) and any(tag in v.lower() for tag in HTML_KEYWORDS)

            if isinstance(left, SymbolicValue) and html_literal(right):
                left.add_step("propagation", node)
                return left

            if isinstance(right, SymbolicValue) and html_literal(left):
                right.add_step("propagation", node)
                return right

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)

            if isinstance(left, SymbolicValue):
                return left
            if isinstance(right, SymbolicValue):
                return right

        # return sink (XSS)
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
                    node,
                )

        # SQL Injection
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
                        node,
                    )

        # IDOR
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in IDOR_FUNCTIONS and node.args:
                ident = self.eval_node(node.args[0])
                if isinstance(ident, SymbolicValue):
                    self.add_finding(
                        "Insecure Direct Object Reference (IDOR)",
                        "HIGH",
                        ident,
                        f"{node.func.id}(id)",
                        "User-controlled identifier used to access protected object",
                        "Verify the object belongs to the current authenticated user",
                        node,
                    )

        return None

    # =========================
    # Traverse code
    # =========================

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

        # analyze functions
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                saved = self.symbols.copy()
                self.execute_block(node.body)
                self.symbols = saved


# =========================
# Report Formatter
# =========================

class AnalysisReport:
    def __init__(self, findings):
        self.issues = [self.format_issue(f) for f in findings]

    def format_issue(self, finding):
        path_str = " → ".join(
            f"{label}(line {line})" if line else label
            for label, line in finding.path
        )

        return (
            f"{finding.vuln_type}\n"
            f"Severity: {finding.severity}\n"
            f"Location: line {finding.location}\n"
            f"Attack Path: {path_str}\n"
            f"Sink: {finding.sink}\n"
            f"Why: {finding.reason}\n"
            f"Fix: {finding.fix}"
        )


# =========================
# Engine Entry Point
# =========================

class MetaCodeEngine:
    def orchestrate(self, code: str):
        tree = ast.parse(code)
        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)
        return AnalysisReport(analyzer.findings)
