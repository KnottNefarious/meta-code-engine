import ast

SQL_METHODS = {"execute", "executemany"}
SUBPROCESS_METHODS = {"Popen", "run", "call"}
DESERIALIZE_METHODS = {"loads", "load"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}
DB_FETCH_NAMES = {"find", "load", "fetch", "get_user", "get_by_id", "query_user"}

SANITIZERS = {"escape"}   # markupsafe.escape

HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}


# ---------------------------------------------------------
# Finding
# ---------------------------------------------------------

class Finding:
    def __init__(self, vuln_type, severity, sym, sink, reason, fix, lineno):
        self.vuln_type = vuln_type
        self.severity = severity
        self.path = sym.path
        self.sink = sink
        self.reason = reason
        self.fix = fix
        self.lineno = lineno


# ---------------------------------------------------------
# Symbolic Value (taint object)
# ---------------------------------------------------------

class SymbolicValue:
    def __init__(self, name, tainted=False, path=None):
        self.name = name
        self.tainted = tainted
        self.path = path or []

    def step(self, label, node):
        line = getattr(node, "lineno", None)
        self.path.append(f"{label}(line {line})")

    def merge(self, other):
        merged = SymbolicValue(self.name, self.tainted or other.tainted, list(self.path))
        merged.path = list(dict.fromkeys(self.path + other.path))
        return merged


# ---------------------------------------------------------
# Analyzer
# ---------------------------------------------------------

class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.findings = []
        self._fingerprints = set()
        self.counter = 0
        self.authorized_ids = set()
        self.functions = {}

    # ------------------ taint source ------------------

    def new_symbol(self, node):
        self.counter += 1
        sym = SymbolicValue(f"request_{self.counter}", True, [])
        sym.step("request", node)
        return sym

    # ------------------ add finding ------------------

    def add_finding(self, vuln_type, severity, sym, sink, reason, fix, node):

        lineno = getattr(node, "lineno", None)

        fingerprint = (
            vuln_type,
            lineno,
            tuple(sym.path),
            sink
        )

        if fingerprint in self._fingerprints:
            return

        self._fingerprints.add(fingerprint)

        self.findings.append(
            Finding(vuln_type, severity, sym, sink, reason, fix, lineno)
        )

    # -------------------------------------------------
    # Expression evaluation
    # -------------------------------------------------

    def eval_node(self, node):

        if node is None:
            return None

        # constants
        if isinstance(node, ast.Constant):
            return node.value

        # variables
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # request.args.get(...)
        if isinstance(node, ast.Call):

            # sanitizer
            if isinstance(node.func, ast.Name) and node.func.id in SANITIZERS:
                val = self.eval_node(node.args[0])
                return None  # sanitized

            # flask request
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Attribute):
                    if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "request":
                        sym = self.new_symbol(node)
                        sym.step("get", node)
                        return sym

        # string concatenation → XSS propagation
        if isinstance(node, ast.BinOp):

            left = self.eval_node(node.left)
            right = self.eval_node(node.right)

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)

            if isinstance(left, SymbolicValue):
                left.step("propagation", node)
                return left

            if isinstance(right, SymbolicValue):
                right.step("propagation", node)
                return right

        return None

    # -------------------------------------------------
    # control flow
    # -------------------------------------------------

    def execute_block(self, body):

        for stmt in body:

            # assignment
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                val = self.eval_node(stmt.value)
                self.symbols[stmt.targets[0].id] = val
                if isinstance(val, SymbolicValue):
                    val.step(stmt.targets[0].id, stmt)

            # return (XSS sink)
            elif isinstance(stmt, ast.Return):

                val = self.eval_node(stmt.value)

                if isinstance(val, SymbolicValue):
                    val.step("return", stmt)
                    self.add_finding(
                        "Cross-Site Scripting (XSS)",
                        "HIGH",
                        val,
                        "HTTP response",
                        "User input returned directly to browser",
                        "Escape output or use templating auto-escaping",
                        stmt
                    )

            # SQL injection
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value

                if isinstance(call.func, ast.Attribute):
                    if call.func.attr in SQL_METHODS:
                        arg = self.eval_node(call.args[0])
                        if isinstance(arg, SymbolicValue):
                            self.add_finding(
                                "SQL Injection",
                                "HIGH",
                                arg,
                                "cursor.execute(query)",
                                "User input concatenated into SQL query",
                                "Use parameterized queries",
                                stmt
                            )

            # path traversal
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                if isinstance(call.func, ast.Name) and call.func.id == "open":
                    arg = self.eval_node(call.args[0])
                    if isinstance(arg, SymbolicValue):
                        self.add_finding(
                            "Path Traversal",
                            "MEDIUM",
                            arg,
                            "open(path)",
                            "User input used as filesystem path",
                            "Validate filename",
                            stmt
                        )

            # IDOR detection
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                if isinstance(call.func, ast.Name) and call.func.id in DB_FETCH_NAMES:
                    arg = self.eval_node(call.args[0])
                    if isinstance(arg, SymbolicValue) and call.args[0].id not in self.authorized_ids:
                        self.add_finding(
                            "Insecure Direct Object Reference (IDOR)",
                            "HIGH",
                            arg,
                            "get_user(id)",
                            "User-controlled identifier used to access protected object",
                            "Verify the object belongs to the current authenticated user",
                            stmt
                        )

            # ---------------- AUTHORIZATION GATE (FIX) ----------------
            elif isinstance(stmt, ast.If):

                def extract_name(node):
                    if isinstance(node, ast.Name):
                        return node.id
                    if isinstance(node, ast.Call) and node.args:
                        return extract_name(node.args[0])
                    return None

                def is_current_user(node):
                    if isinstance(node, ast.Attribute):
                        return isinstance(node.value, ast.Name) and node.value.id == "current_user"
                    if isinstance(node, ast.Call) and node.args:
                        return is_current_user(node.args[0])
                    return False

                if isinstance(stmt.test, ast.Compare):

                    left = stmt.test.left
                    right = stmt.test.comparators[0]

                    left_name = extract_name(left)
                    right_name = extract_name(right)

                    if left_name and is_current_user(right):
                        self.authorized_ids.add(left_name)

                    if right_name and is_current_user(left):
                        self.authorized_ids.add(right_name)

                # still walk inside branches
                self.execute_block(stmt.body)
                self.execute_block(stmt.orelse)

    # -------------------------------------------------
    # analyze
    # -------------------------------------------------

    def analyze(self, tree):
        self.execute_block(tree.body)


# ---------------------------------------------------------
# Report
# ---------------------------------------------------------

class AnalysisReport:
    def __init__(self, findings):
        self.issues = []

        for f in findings:
            self.issues.append(
                f"{f.vuln_type}\n"
                f"Severity: {f.severity}\n"
                f"Location: line {f.lineno}\n"
                f"Attack Path: {' → '.join(f.path)}\n"
                f"Sink: {f.sink}\n"
                f"Why: {f.reason}\n"
                f"Fix: {f.fix}"
            )


# ---------------------------------------------------------
# Engine
# ---------------------------------------------------------

class MetaCodeEngine:
    def orchestrate(self, code):
        tree = ast.parse(code)
        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)
        return AnalysisReport(analyzer.findings)
